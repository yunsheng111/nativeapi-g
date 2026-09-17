"""内置工具注册表（P3）：注册 + 白名单物理隔离 + 统一执行契约。

物理隔离原则（融合方案 2.4，对照 glm-web-code）：不启用的工具**不注册进
registry**，而不是"注册了靠提示词劝阻模型别用" —— 模型幻觉调用一个物理上
不存在的工具时，循环会得到明确的"工具不存在"结果，不会静默失败。

工具形态：OpenAI function calling 的 schema（name/description/parameters），
直接放进 payload["tools"] 走底座既有协议桥（tool_protocol 注入 → DSML →
tool_parser 解析 → tool_result 回灌），P3 不新增任何协议。

执行契约（原则 3：失败不可伪装成成功）：handler 抛出的任何异常都被 run_tool
捕获并转成 error 结果回灌给模型 —— 工具失败是给模型看的运行事实，不是给
客户端看的 HTTP 错误；registry 级错误（工具未注册）同样以 error 结果回灌，
保证循环可以继续。
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Callable

_logger = logging.getLogger("glmrelay.tools")


@dataclass
class ToolSpec:
    """一个内置工具：OpenAI function schema + 只读标记 + 执行体。"""

    name: str
    description: str
    parameters: dict  # JSON Schema（OpenAI function parameters 形态）
    handler: Callable[[dict, object], str]  # (args, session) -> 工具结果文本
    readonly: bool = False

    def to_openai_schema(self) -> dict:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


@dataclass
class ToolExecutionResult:
    """单次工具执行的完整观测（进度流与回灌共用）。"""

    name: str
    ok: bool
    output: str
    duration_ms: float = 0.0

    def to_tool_content(self) -> str:
        """回灌给模型的文本。失败时显式 error 前缀 —— 模型据此决定重试/换路。"""
        if self.ok:
            return self.output
        return "[error] " + self.output


@dataclass
class ToolRegistry:
    tools: dict[str, ToolSpec] = field(default_factory=dict)

    def register(self, spec: ToolSpec) -> None:
        if spec.name in self.tools:
            raise ValueError("工具重复注册: " + spec.name)
        self.tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self.tools.get(name)

    def schemas(self) -> list[dict]:
        """给 payload["tools"] 的 OpenAI schema 列表（按名字排序保证稳定注入序）。"""
        return [self.tools[name].to_openai_schema() for name in sorted(self.tools)]

    def names(self) -> list[str]:
        return sorted(self.tools)

    def run_tool(self, tool_name: str, arguments: dict, session: object) -> ToolExecutionResult:
        """统一执行入口。未注册/异常都转成 error 结果 —— 循环不因工具故障中断。"""
        spec = self.tools.get(tool_name)
        if spec is None:
            registered = ", ".join(self.names()) or "(无)"
            _logger.warning("模型调用了未注册的内置工具 name=%s registered=%s", tool_name, registered)
            message = "工具不存在: {0}；可用工具: {1}".format(tool_name, registered)
            return ToolExecutionResult(name=tool_name, ok=False, output=message)
        started = time.monotonic()
        try:
            output = spec.handler(arguments or {}, session)
            return ToolExecutionResult(name=tool_name, ok=True, output=str(output),
                                       duration_ms=(time.monotonic() - started) * 1000)
        except Exception as exc:  # noqa: BLE001  工具失败如实回灌，不上抛
            _logger.warning("内置工具执行失败 name=%s error=%s", tool_name, exc)
            return ToolExecutionResult(
                name=tool_name, ok=False, output="{0}: {1}".format(type(exc).__name__, exc),
                duration_ms=(time.monotonic() - started) * 1000,
            )


def build_registry(enabled_names: list[str], builder: dict[str, Callable[[], ToolSpec]]) -> ToolRegistry:
    """按启用名单构建 registry（物理隔离：名单外的一行代码都不执行）。

    builder 是 name -> ToolSpec 工厂表（tools/fs.py 等模块各自提供），
    延迟构造 —— 未启用工具的模块甚至可以不导入。
    """
    registry = ToolRegistry()
    for name in enabled_names:
        name = name.strip()
        if not name:
            continue
        factory = builder.get(name)
        if factory is None:
            _logger.warning("GLM_BUILTIN_TOOLS 含未知工具 name=%s（已跳过）", name)
            continue
        registry.register(factory())
    return registry
