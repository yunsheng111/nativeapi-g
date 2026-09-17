"""工具模式判定（P3 三层覆盖 + P5 API Key 绑定档，架构设计 3.2）。

优先级从高到低：
    1. 请求头 X-GLM2API-Tool-Mode: passthrough | builtin（临时覆盖，调试用）
    2. 模型名 @builtin 后缀（glm-4-flash@builtin，单次请求覆盖，客户端免改配置）
    3. API Key 绑定档（管理面板按 key 设置；"" = 未绑定）
    4. 全局 GLM_TOOL_MODE（默认 passthrough）

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


def resolve_tool_mode(
    headers: dict[str, str] | None,
    model: str,
    global_default: str,
    key_mode: str = "",
) -> str:
    """四层覆盖判定。headers 是大小写不敏感视图或普通 dict（键按原样匹配）。

    key_mode 是请求所用 API Key 上绑定的档位（"" = 未绑定，跳过该层）。
    """
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

    bound = str(key_mode or "").strip().lower()
    if bound in _VALID_MODES:
        return bound

    return normalize_mode(global_default)


def strip_builtin_suffix(model: str) -> str:
    """剥掉 @builtin 后缀得到真实上游模型名（无后缀原样返回）。"""
    lowered = str(model or "")
    if lowered.lower().endswith(BUILTIN_SUFFIX):
        return lowered[: -len(BUILTIN_SUFFIX)]
    return lowered
