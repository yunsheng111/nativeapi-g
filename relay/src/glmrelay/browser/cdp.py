"""最小 Chrome DevTools Protocol 客户端 + 浏览器启动器。

只覆盖本项目需要的部分：拉起一个独立 profile 的浏览器实例、连上它的
调试端口、在页面里求值 / 读 DOM Storage。零第三方依赖。

用途：
1. 账号登录导入 —— 用户在受控浏览器里登录 chatglm.cn，程序读 localStorage 拿 refresh_token
2. P4 浏览器操作工具 —— 同一个客户端可直接复用

注意：Chrome / Edge 136+ 起，**不允许在默认 user-data-dir 上开
--remote-debugging-port**（安全策略）。所以这里强制使用独立 profile 目录，
顺带也避免污染用户日常浏览器的登录态。
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import dataclass
from typing import Any

from .ws import WebSocket, WebSocketError

DEFAULT_DEBUG_PORT = 9333

_CANDIDATES: tuple[tuple[str, str], ...] = (
    ("Edge", r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
    ("Edge", r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
    ("Edge", r"%LOCALAPPDATA%\Microsoft\Edge\Application\msedge.exe"),
    ("Chrome", r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
    ("Chrome", r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
    ("Chrome", r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
)


class CDPError(RuntimeError):
    """CDP 层错误。"""


@dataclass(frozen=True)
class BrowserInfo:
    name: str
    path: str
    version: str

    def __str__(self) -> str:
        return f"{self.name} {self.version}"


# --------------------------------------------------------------------- 浏览器发现


def find_browser(preferred: str | None = None) -> BrowserInfo:
    """定位本机可用的 Edge / Chrome。preferred 可指定 'edge' 或 'chrome'。"""
    want = preferred.strip().lower() if preferred else None
    for name, pattern in _CANDIDATES:
        if want and name.lower() != want:
            continue
        path = os.path.expandvars(pattern)
        if os.path.isfile(path):
            version = ""
            try:
                # 版本号从文件名附近的清单拿不到，直接问可执行文件
                out = subprocess.run(
                    [path, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                text = (out.stdout or out.stderr or "").strip()
                if text:
                    version = text.split()[-1]
            except Exception:  # noqa: BLE001
                version = "unknown"
            return BrowserInfo(name=name, path=path, version=version)
    raise CDPError("未找到 Edge 或 Chrome，请确认已安装其中之一")


# --------------------------------------------------------------------- HTTP 端点


def _local_opener() -> urllib.request.OpenerDirector:
    """绕开系统代理：本地调试端口绝不能被代理接管。"""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _get_json(url: str, timeout: float = 5.0) -> Any:
    # 不要覆盖 Host 头！Chrome/Edge 会用请求的 Host 来拼 webSocketDebuggerUrl，
    # 手写 "Host: 127.0.0.1"（不带端口）会让返回的调试地址丢掉端口号。
    req = urllib.request.Request(url)
    with _local_opener().open(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def normalize_ws_url(ws_url: str, port: int) -> str:
    """补全 webSocketDebuggerUrl 缺失的端口。

    防御性措施：即便 Host 头正确，个别浏览器版本仍可能返回不带端口的
    ws 地址（`ws://127.0.0.1/devtools/page/...`）。不做补全会静默连到 80 端口。
    """
    parsed = urllib.parse.urlparse(ws_url)
    if parsed.port is not None or not parsed.hostname:
        return ws_url
    netloc = f"{parsed.hostname}:{port}"
    if parsed.username:
        # 理论上不会走到，保留以免误伤带凭证的 URL
        return ws_url
    return urllib.parse.urlunparse(parsed._replace(netloc=netloc))


def wait_for_devtools(port: int = DEFAULT_DEBUG_PORT, timeout: float = 45.0) -> dict:
    """等待调试端口就绪，返回 /json/version 的内容。"""
    deadline = time.time() + timeout
    last_error = ""
    while time.time() < deadline:
        try:
            return _get_json(f"http://127.0.0.1:{port}/json/version", timeout=2.0)
        except Exception as exc:  # noqa: BLE001
            last_error = f"{type(exc).__name__}: {exc}"
            time.sleep(0.3)
    raise CDPError(f"调试端口 {port} 在 {timeout:.0f}s 内未就绪（{last_error}）")


def list_targets(port: int = DEFAULT_DEBUG_PORT) -> list[dict]:
    """列出所有调试目标（页面 / worker / iframe …）。"""
    try:
        data = _get_json(f"http://127.0.0.1:{port}/json/list", timeout=5.0)
    except Exception as exc:  # noqa: BLE001
        raise CDPError(f"读取调试目标失败: {exc}") from exc
    if not isinstance(data, list):
        raise CDPError("调试目标返回格式异常")
    return data


def find_page_target(
    port: int = DEFAULT_DEBUG_PORT,
    url_contains: str | None = None,
    timeout: float = 20.0,
) -> dict:
    """找到一个 type=page 且 URL 含指定片段的调试目标。"""
    deadline = time.time() + timeout
    seen: list[str] = []
    while time.time() < deadline:
        for target in list_targets(port):
            if target.get("type") != "page":
                continue
            url = target.get("url", "")
            ws_url = target.get("webSocketDebuggerUrl")
            if not ws_url:
                continue
            if url_contains and url_contains not in url:
                seen.append(url)
                continue
            target = dict(target)
            target["webSocketDebuggerUrl"] = normalize_ws_url(str(ws_url), port)
            return target
        time.sleep(0.4)
    detail = f"，当前页面: {seen}" if seen else ""
    raise CDPError(f"未找到匹配 {url_contains!r} 的页面{detail}")


def find_browser_target(port: int = DEFAULT_DEBUG_PORT) -> dict:
    """browser 级调试目标（/json/version 的 ws）。

    Target.createBrowserContext / disposeBrowserContext / closeTarget 等
    Target 域操作只能在 browser 级会话上调用 —— 连 page target 的会话会报
    "Target domain is not supported on this target"。
    """
    data = wait_for_devtools(port)
    ws_url = data.get("webSocketDebuggerUrl")
    if not ws_url:
        raise CDPError("浏览器调试端点未返回 webSocketDebuggerUrl")
    return {
        "type": "browser",
        "id": data.get("Browser", "browser"),
        "webSocketDebuggerUrl": normalize_ws_url(str(ws_url), port),
    }


def find_target_by_id(port: int, target_id: str, timeout: float = 20.0) -> dict:
    """按 targetId 查找调试目标。

    Target.createTarget 刚创建的 page target 不会立刻出现在 /json/list
    （目标在创建中），必须轮询等待；这是 BrowserContext 池把新 tab 接入
    双连接的唯一入口。
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        for target in list_targets(port):
            if target.get("id") == target_id and target.get("webSocketDebuggerUrl"):
                target = dict(target)
                target["webSocketDebuggerUrl"] = normalize_ws_url(
                    str(target["webSocketDebuggerUrl"]), port
                )
                return target
        time.sleep(0.2)
    raise CDPError(f"调试目标 {target_id} 在 {timeout:.0f}s 内未出现")


# --------------------------------------------------------------------- 启动浏览器


def build_launch_args(
    browser: BrowserInfo,
    port: int,
    user_data_dir: str,
    url: str | None = None,
    headless: bool = False,
    extra: list[str] | None = None,
) -> list[str]:
    args = [
        browser.path,
        f"--remote-debugging-port={port}",
        f"--user-data-dir={user_data_dir}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-popup-blocking",
        # 关掉「恢复上次会话」弹窗，避免遮挡登录页
        "--hide-crash-restore-bubble",
    ]
    if headless:
        args.append("--headless=new")
    if extra:
        args.extend(extra)
    if url:
        args.append(url)
    return args


def launch_browser(
    browser: BrowserInfo,
    port: int = DEFAULT_DEBUG_PORT,
    user_data_dir: str | None = None,
    url: str | None = None,
    headless: bool = False,
    extra: list[str] | None = None,
) -> subprocess.Popen:
    """拉起一个独立 profile 的浏览器实例。调用方负责 terminate()。"""
    if not user_data_dir:
        raise CDPError("必须显式指定 user_data_dir；不允许多个实例共用 profile")
    os.makedirs(user_data_dir, exist_ok=True)
    args = build_launch_args(browser, port, user_data_dir, url, headless, extra)
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if headless else 0
    return subprocess.Popen(
        args,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        creationflags=creationflags,
    )


# --------------------------------------------------------------------- CDP 会话


class CDPClient:
    """绑定到单个调试目标（页面）的 CDP 会话。"""

    def __init__(self, ws_url: str, timeout: float = 30.0) -> None:
        self._ws_url = ws_url
        self._timeout = timeout
        self._ws: WebSocket | None = None
        self._next_id = 1
        self._events: deque[dict] = deque(maxlen=200)

    # -- 生命周期

    def connect(self) -> "CDPClient":
        ws = WebSocket(self._ws_url, timeout=self._timeout)
        ws.connect()
        self._ws = ws
        return self

    def close(self) -> None:
        if self._ws is not None:
            self._ws.close()
            self._ws = None

    def __enter__(self) -> "CDPClient":
        return self.connect()

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- 调用

    @property
    def events(self) -> list[dict]:
        """最近收到的 CDP 事件（不含调用响应）。"""
        return list(self._events)

    def call(self, method: str, params: dict | None = None, timeout: float | None = None) -> dict:
        """发送一条 CDP 命令并等待同 id 的响应。"""
        if self._ws is None:
            raise CDPError("CDP 会话未连接")
        call_id = self._next_id
        self._next_id += 1
        payload = {"id": call_id, "method": method}
        if params:
            payload["params"] = params
        # 传输层异常统一降级成 CDPError：调用方只需处理一种异常，
        # 否则 WebSocketError 会漏过 `except CDPError`，把可恢复的抖动升级成致命错误。
        try:
            self._ws.send_text(json.dumps(payload, ensure_ascii=False))
        except WebSocketError as exc:
            raise CDPError(f"CDP 连接已断开（发送 {method} 时）: {exc}") from exc

        deadline = time.time() + (timeout if timeout is not None else self._timeout)
        while True:
            if time.time() > deadline:
                raise CDPError(f"CDP 调用超时: {method}")
            try:
                message = self._ws.recv_text()
            except WebSocketError as exc:
                raise CDPError(f"CDP 连接已断开（等待 {method} 响应时）: {exc}") from exc
            if message is None:
                raise CDPError(f"CDP 连接被关闭（等待 {method} 响应时）")
            try:
                obj = json.loads(message)
            except json.JSONDecodeError:
                continue
            if obj.get("id") != call_id:
                if "id" not in obj and obj.get("method"):
                    self._events.append(obj)
                continue
            if "error" in obj:
                raise CDPError(f"CDP {method} 失败: {obj['error']}")
            result = obj.get("result")
            return result if isinstance(result, dict) else {}

    # -- 便捷方法

    def pump_events(self, callback, on_close=None) -> None:
        """阻塞循环分发 CDP 事件，供独立线程做流式泵。

        本连接约定只收不调（call 由主连接负责），因此循环里忽略一切
        call 响应，仅向 callback 投递 method 事件；连接断开时回调
        on_close 后返回（WebSocketError 视为正常断连，其他异常同样终止）。
        """
        ws = self._ws
        if ws is None:
            raise CDPError("CDP 会话未连接")
        try:
            while True:
                message = ws.recv_text()
                if message is None:
                    break
                try:
                    obj = json.loads(message)
                except json.JSONDecodeError:
                    continue
                if "id" not in obj and obj.get("method"):
                    callback(obj)
        except (WebSocketError, OSError, TimeoutError):
            # WebSocketError = 协议层断连；OSError（含 WinError 10038 socket 已关）
            # 与 TimeoutError = stop() 关闭连接时泵线程正在 recv，均视作正常断连。
            pass
        finally:
            if on_close is not None:
                try:
                    on_close()
                except Exception:  # noqa: BLE001
                    pass

    def evaluate(
        self,
        expression: str,
        return_by_value: bool = True,
        await_promise: bool = False,
        timeout: float | None = None,
    ) -> Any:
        """在页面上下文求值，返回 JS 值。"""
        result = self.call(
            "Runtime.evaluate",
            {
                "expression": expression,
                "returnByValue": return_by_value,
                "awaitPromise": await_promise,
                "userGesture": True,
            },
            timeout=timeout,
        )
        if result.get("exceptionDetails"):
            detail = result["exceptionDetails"]
            text = (detail.get("exception") or {}).get("description") or detail.get("text")
            raise CDPError(f"页面求值异常: {text}")
        return (result.get("result") or {}).get("value")

    # -- 页面就绪

    def page_state(self) -> dict | None:
        """读取页面当前状态；页面尚未建立执行上下文时返回 None。"""
        try:
            state = self.evaluate(
                "({href: location.href, ready: document.readyState,"
                " origin: location.origin, title: document.title})"
            )
        except CDPError:
            return None
        return state if isinstance(state, dict) else None

    def wait_loaded(self, timeout: float = 45.0, poll: float = 0.3) -> dict:
        """等待页面真正可用。

        刚连上时目标往往还停在 about:blank —— 导航只是在 /json/list 里**已可见**
        但尚未提交，此时 document.title 为空、localStorage 会因不透明源抛
        SecurityError。必须等到 origin 有效且文档加载完成。
        """
        deadline = time.time() + timeout
        last: dict = {}
        while time.time() < deadline:
            state = self.page_state()
            if state:
                last = state
                origin = state.get("origin")
                if state.get("ready") == "complete" and origin not in (None, "", "null"):
                    return state
            time.sleep(poll)
        return last

    def navigate(self, url: str, timeout: float = 60.0) -> dict:
        """导航到指定 URL 并等待页面就绪。"""
        self.call("Page.navigate", {"url": url}, timeout=timeout)
        return self.wait_loaded(timeout=timeout)

    def dom_storage_items(self, origin: str) -> dict[str, str]:
        """用 DOMStorage 域直读某个 origin 的 localStorage，不依赖页面脚本。"""
        result = self.call(
            "DOMStorage.getDOMStorageItems",
            {"storageId": {"securityOrigin": origin, "isLocalStorage": True}},
        )
        items: dict[str, str] = {}
        for entry in result.get("entries", []) or []:
            if isinstance(entry, list) and len(entry) == 2:
                items[str(entry[0])] = str(entry[1])
        return items

    def attach(self) -> None:
        """开启页面必要的域。个别域在当前浏览器版本不存在时静默跳过。"""
        for domain in ("Runtime", "DOMStorage", "Page", "DOM"):
            try:
                self.call(f"{domain}.enable", timeout=8.0)
            except CDPError:
                pass


# --------------------------------------------------------------------- 组合入口


class ManagedBrowser:
    """启动 + 连接 + 清理的一条龙封装，供账号导入使用。"""

    def __init__(
        self,
        user_data_dir: str,
        port: int = DEFAULT_DEBUG_PORT,
        preferred: str | None = None,
        headless: bool = False,
        start_url: str | None = None,
    ) -> None:
        self.browser = find_browser(preferred)
        self.port = port
        self.user_data_dir = user_data_dir
        self.headless = headless
        self.start_url = start_url
        self._proc: subprocess.Popen | None = None

    def start(self, page_url_contains: str | None = None, wait_ready: bool = True) -> tuple[subprocess.Popen, CDPClient]:
        self._proc = launch_browser(
            self.browser,
            port=self.port,
            user_data_dir=self.user_data_dir,
            url=self.start_url,
            headless=self.headless,
        )
        wait_for_devtools(self.port)
        target = find_page_target(self.port, page_url_contains)
        client = CDPClient(target["webSocketDebuggerUrl"]).connect()
        client.attach()
        if wait_ready:
            client.wait_loaded()
        return self._proc, client

    def stop(self) -> None:
        if self._proc is None:
            return
        try:
            self._proc.terminate()
            self._proc.wait(timeout=10)
        except Exception:  # noqa: BLE001
            try:
                self._proc.kill()
            except Exception:  # noqa: BLE001
                pass
        finally:
            self._proc = None

    def __enter__(self) -> "ManagedBrowser":
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()


__all__ = [
    "CDPClient",
    "CDPError",
    "BrowserInfo",
    "ManagedBrowser",
    "DEFAULT_DEBUG_PORT",
    "find_browser",
    "find_browser_target",
    "find_page_target",
    "find_target_by_id",
    "launch_browser",
    "list_targets",
    "normalize_ws_url",
    "wait_for_devtools",
    "WebSocketError",
]
