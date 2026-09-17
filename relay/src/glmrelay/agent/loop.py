"""模式 B 的 agent loop（P3）：多轮工具循环 + 进度流 + keepalive 兼容。

闭环形态（架构设计 3.3）：客户端请求（builtin 模式）→ 注入内置工具 schema
→ 上游 GLM（底座协议桥自动完成 tools 注入 / DSML 解析）→ tool_calls 出现
则中转自己执行 → 进度 delta 实时下发 → tool 结果回灌 → 再问上游 → 直到
无 tool_calls 或轮数上限。

流式体验（3.3 的「必须做」项）：loop 内部用底座非流式 chat_completion 聚合
（比流式再拼装简单可靠一个量级），对外包装成 OpenAI SSE chunk 序列 ——
工具执行进度作为 content delta 实时下发（可观测性，不是剧透），server 层
的空闲心跳继续兜底 keepalive。

工具结果全文只回灌给模型；对客户端只下发执行摘要 —— 对话界面不被 1MB
的工具输出刷屏。
"""

from __future__ import annotations

import json
import logging
from typing import Iterator

from glm2api.services.glm_client import GLMWebClient
from glmrelay.bridge.mode import resolve_tool_mode, strip_builtin_suffix
from glmrelay.tools.registry import ToolExecutionResult, ToolRegistry, build_registry

_logger = logging.getLogger("glmrelay.agent")

# 进度图标：让「中转在干什么」在聊天界面一眼可辨（🔧）
_TOOL_ICON = "\U0001F527"


class AgentSession:
    """单次 builtin 请求的会话状态（todo 状态、轮数、进度回调挂钩）。"""

    def __init__(self) -> None:
        self.todo_list: list[dict] = []
        self.rounds_used = 0


def _chunk(delta: dict, finish_reason: str | None = None) -> bytes:
    payload = {
        "id": "chatcmpl-builtin",
        "object": "chat.completion.chunk",
        "created": 0,
        "model": "builtin",
        "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}],
    }
    # SSE 线上格式必须是 "data: {json}\n\n"：server 层原样下发这些字节给
    # OpenAI 兼容客户端，aggregate_builtin_response 也按 "data:" 前缀解析 ——
    # 与 _sse_done 的 "data: [DONE]" 保持同一帧格式。
    return ("data: " + json.dumps(payload, ensure_ascii=False) + "\n\n").encode("utf-8")


def _sse_done() -> bytes:
    return b"data: [DONE]\n\n"


def _summarize_output(output: str, limit: int = 200) -> str:
    text = output.strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "…(已截断，全文已回灌给模型)"


def build_builtin_registry(config) -> ToolRegistry:
    """按 GLM_BUILTIN_TOOLS 构建内置工具注册表（物理隔离）。

    工厂表延迟导入 —— 名单外的工具模块不加载（shell 不在默认名单时，
    subprocess 相关代码完全不上进程）。

    例外是 MCP（P4）：工具名是运行时从各服务器拉取的动态集合，无法预先写进
    静态名单 —— 「配置了服务器即视为显式启用」（与把名字写进 GLM_BUILTIN_TOOLS
    是同等级的用户动作），GLM_MCP_TOOLS glob 提供二次收窄。
    """
    from glmrelay.tools.fs import TOOL_FACTORIES as FS_FACTORIES
    from glmrelay.tools.shell import TOOL_FACTORIES as SHELL_FACTORIES
    from glmrelay.tools.todo import TOOL_FACTORIES as TODO_FACTORIES

    builders: dict = {}
    # 工厂形态是 (config) -> ToolSpec（沙箱根/超时在构建期绑定到 handler 闭包），
    # 而 registry.build_registry 的 builder 契约是零参工厂 —— 这里做一次闭包适配。
    # 用默认参数绑定 factory/config，避免循环变量晚绑定陷阱。
    for factories in (FS_FACTORIES, SHELL_FACTORIES, TODO_FACTORIES):
        for name, factory in factories.items():
            builders[name] = (lambda f=factory, c=config: f(c))

    # P4 扩展工具：browser / skills 同样走静态名单（默认不在名单内，需显式启用）
    from glmrelay.tools.browser import TOOL_FACTORIES as BROWSER_FACTORIES
    from glmrelay.tools.skills import TOOL_FACTORIES as SKILLS_FACTORIES

    for factories in (BROWSER_FACTORIES, SKILLS_FACTORIES):
        for name, factory in factories.items():
            builders[name] = (lambda f=factory, c=config: f(c))

    # P4 MCP：动态工具名（mcp__<server>__<tool>），配置了服务器才注册
    enabled_names = list(config.glm_builtin_tools)
    servers = list(getattr(config, "glm_mcp_servers", None) or [])
    if servers:
        from glmrelay.tools.mcp import build_mcp_factories

        mcp_factories = build_mcp_factories(config)
        for name, factory in mcp_factories.items():
            builders[name] = (lambda f=factory, c=config: f(c))
        enabled_names.extend(mcp_factories)

    return build_registry(enabled_names, builders)


def run_builtin_agent(
    payload: dict,
    client: GLMWebClient,
    config,
    logger,
) -> Iterator[bytes]:
    """builtin 模式主循环。产出 OpenAI SSE chunk 字节流（含 [DONE] 收尾）。"""
    upstream_model = strip_builtin_suffix(str(payload.get("model", "glm-4")))
    registry = build_builtin_registry(config)
    if not registry.names():
        # 物理隔离后一个工具都没有：显式失败而非静默当透传跑
        yield _chunk({"role": "assistant", "content": ""})
        yield _chunk({
            "content": "[builtin 模式] 未启用任何内置工具，请检查 GLM_BUILTIN_TOOLS 配置。"
        }, "stop")
        yield _sse_done()
        return

    session = AgentSession()
    messages = [dict(m) for m in payload.get("messages", [])]  # type: ignore[arg-type]
    max_rounds = int(config.glm_builtin_max_rounds)

    for round_index in range(max_rounds):
        session.rounds_used = round_index + 1
        request: dict = {k: v for k, v in payload.items() if k not in ("stream", "tools", "tool_choice", "model")}
        request["model"] = upstream_model
        request["messages"] = messages
        request["tools"] = registry.schemas()
        # 内置闭环里工具必须可用：模型忽略工具直接编答案时靠轮数上限兜底
        request["tool_choice"] = "auto"

        logger.info(
            "builtin 循环 round=%s/%s model=%s tools=%s",
            round_index + 1, max_rounds, upstream_model, ",".join(registry.names()),
        )
        response, _conversation_id = client.chat_completion(request)
        choices = response.get("choices") or []
        if not choices:
            raise RuntimeError("builtin 循环收到空响应")
        message = choices[0].get("message") or {}
        tool_calls = message.get("tool_calls") or []

        if round_index == 0 and message.get("content"):
            # 首轮模型可能在调工具前先说话 —— 原样透出，保持对话自然
            yield _chunk({"role": "assistant", "content": str(message["content"])})

        if not tool_calls:
            final_text = str(message.get("content") or "")
            if final_text and round_index > 0:
                # 后续轮次的纯文本（如工具结果的总结）作为最终答复下发
                yield _chunk({"content": final_text})
            yield _chunk({}, "stop")
            yield _sse_done()
            return

        # assistant 的 tool_calls 消息必须原样进历史（tool_call_id 对齐回灌的前提）
        messages.append(message)
        for tool_call in tool_calls:
            function = tool_call.get("function") or {}
            tool_name = str(function.get("name", ""))
            raw_arguments = function.get("arguments") or "{}"
            try:
                arguments = json.loads(raw_arguments) if isinstance(raw_arguments, str) else dict(raw_arguments)
            except json.JSONDecodeError as exc:
                arguments = None
                logger.warning("builtin 工具参数不是合法 JSON name=%s error=%s", tool_name, exc)
                result_output = "工具参数解析失败（不是合法 JSON）: " + str(exc)
                from glmrelay.tools.registry import ToolExecutionResult

                result = ToolExecutionResult(name=tool_name, ok=False, output=result_output)
            else:
                result = registry.run_tool(tool_name, arguments or {}, session)

            # 进度 delta（可观测性）：工具名 + 成败 + 输出摘要
            status_line = "{0} {1} {2} ({3:.0f}ms)".format(
                _TOOL_ICON, tool_name, "成功" if result.ok else "失败", result.duration_ms
            )
            yield _chunk({"content": status_line + "\n" + _summarize_output(result.output) + "\n\n"})

            # 结果回灌：role=tool + 原始 tool_call_id（底座 convert_messages
            # 的 id 对齐校验依赖它与 assistant 消息严格对应）
            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.get("id") or "",
                "content": result.to_tool_content(),
            })

    yield _chunk({"content": ""})
    yield _chunk({
        "content": "[builtin 模式] 已达最大工具轮数 {0}，循环终止。以上为已获得的工具结果摘要；".format(max_rounds)
                   + "如需继续，请把任务拆小后重试。"
    }, "stop")
    yield _sse_done()


def aggregate_builtin_response(stream: Iterator[bytes]) -> dict:
    """把 loop 的 SSE 流聚合成非流式 OpenAI response（builtin + stream=false 用）。"""
    content_parts: list[str] = []
    for chunk_bytes in stream:
        for line in chunk_bytes.decode("utf-8").splitlines():
            line = line.strip()
            if not line.startswith("data:") or line == "data: [DONE]":
                continue
            try:
                event = json.loads(line[5:].strip())
            except json.JSONDecodeError:
                continue
            for choice in event.get("choices") or []:
                delta = choice.get("delta") or {}
                if delta.get("content"):
                    content_parts.append(str(delta["content"]))
    return {
        "id": "chatcmpl-builtin",
        "object": "chat.completion",
        "created": 0,
        "model": "builtin",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "".join(content_parts)},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


def handle_builtin_request(
    payload: dict,
    headers: dict,
    client: GLMWebClient,
    config,
    key_mode: str = "",
):
    """底座 server.py 的 chat/completions 扩展点（P3；P5 起支持 key 绑定档）。

    按四层覆盖判定工具模式：非 builtin 返回 None（底座走透传）；
    builtin 返回 dict（非流式完整 response）或 Iterator[bytes]（SSE 进度流）。
    key_mode 是请求所用 API Key 上绑定的档位（"" = 未绑定，跳过该层）。
    客户端声明的 tools 在 builtin 模式下被忽略 —— loop 是同步闭环，无法
    等待客户端回传结果；忽略时记日志说明（失败不伪装）。
    """
    requested_model = str(payload.get("model", ""))
    mode = resolve_tool_mode(headers, requested_model, config.glm_tool_mode, key_mode=key_mode)
    if mode != "builtin":
        return None
    if payload.get("tools"):
        _logger.info(
            "builtin 模式忽略客户端声明的 tools（中转闭环无法等待客户端回传） count=%s",
            len(payload.get("tools") or []),
        )
    builtin_payload = dict(payload)
    builtin_payload["model"] = strip_builtin_suffix(requested_model)
    stream = run_builtin_agent(builtin_payload, client, config, _logger)
    if payload.get("stream"):
        return stream
    return aggregate_builtin_response(stream)
