"""纯标准库浏览器自动化（CDP）。

对外只暴露两个门面：
    cdp.ManagedBrowser  —— 启动 / 连接 / 清理一条龙
    cdp.CDPClient       —— 单个调试目标的 CDP 会话

底层 ws.WebSocket 是手写的最小 WebSocket 实现，避免引入第三方依赖。
"""

from .cdp import (
    DEFAULT_DEBUG_PORT,
    BrowserInfo,
    CDPClient,
    CDPError,
    ManagedBrowser,
    find_browser,
    find_page_target,
    launch_browser,
    list_targets,
    normalize_ws_url,
    wait_for_devtools,
)
from .ws import WebSocket, WebSocketError

__all__ = [
    "BrowserInfo",
    "CDPClient",
    "CDPError",
    "DEFAULT_DEBUG_PORT",
    "ManagedBrowser",
    "WebSocket",
    "WebSocketError",
    "find_browser",
    "find_page_target",
    "launch_browser",
    "list_targets",
    "normalize_ws_url",
    "wait_for_devtools",
]
