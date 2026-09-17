"""工具模式判定（P3，架构设计 3.2 的三层覆盖）。

优先级从高到低：
    1. 请求头 X-GLM2API-Tool-Mode: passthrough | builtin（临时覆盖，调试用）
    2. 模型名 @builtin 后缀（glm-4-flash@builtin，单次请求覆盖，客户端免改配置）
    3. 全局 GLM_TOOL_MODE（默认 passthrough）

API Key 绑定档位属 P5（管理面板工具策略页）范围，此处挂账不实现。

模式语义（架构设计 3.1）：
    passthrough —— 工具由客户端执行；中转只做协议桥（现状行为）
    builtin     —— 中转端 agent loop 闭环执行内置工具（P3）；客户端声明的
                   tools 被忽略（loop 是同步闭环，无法等待客户端回传）
"""

from __future__ import annotations

BUILTIN_SUFFIX = "@builtin"
_VALID_MODES = ("passthrough", "builtin")


def normalize_mode(value: str | None) -> str:
    """非法值一律回落 passthrough（默认模式不许被脏输入打开）。"""
    lowered = str(value or "").strip().lower()
    return lowered if lowered in _VALID_MODES else "passthrough"


def resolve_tool_mode(headers: dict[str, str] | None, model: str, global_default: str) -> str:
    """三层覆盖判定。headers 是大小写不敏感视图或普通 dict（键按原样匹配）。"""
    header_value = ""
    if headers:
        for key, value in headers.items():
            if str(key).lower() == "x-glm2api-tool-mode":
                header_value = str(value)
                break
    if header_value:
        return normalize_mode(header_value)

    if model and str(model).lower().endswith(BUILTIN_SUFFIX):
        return "builtin"

    return normalize_mode(global_default)


def strip_builtin_suffix(model: str) -> str:
    """剥掉 @builtin 后缀得到真实上游模型名（无后缀原样返回）。"""
    lowered = str(model or "")
    if lowered.lower().endswith(BUILTIN_SUFFIX):
        return lowered[: -len(BUILTIN_SUFFIX)]
    return lowered
