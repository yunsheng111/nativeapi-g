"""内置浏览器工具（P4 模式 B）：navigate / read / click / type，走既有 CDP 基建。

安全设计（架构设计六章「安全阀不可绕」与 10.7 的教训）：
  - **独立 profile**：工具浏览器用 .glmrelay/browser-tool（或 GLM_TOOL_BROWSER_PROFILE），
    绝不复用 chatglm 登录导入的 profile —— 模型可以让浏览器去任意网页，
    同 profile 下任意页面都有机会读到登录态（localStorage/cookie 同源隔离挡不住
    XSS/恶意页面对同 profile 其他 site 的社会工程路径），身份隔离必须做到实例级。
  - **导航 URL 校验**：只允许 http/https；环回/链路本地无条件拒绝、私网默认拒绝
    （GLM_TOOL_BROWSER_ALLOW_PRIVATE 放行）—— 防止提示注入后模型拿浏览器探测
    内网服务（含本机 admin 面板）。这层校验在 Python 侧做，浏览器只是执行者。
  - **物理隔离**：browser_* 四个工具默认不在 GLM_BUILTIN_TOOLS 名单内，
    不显式加入就不注册 —— registry 不认识它们，模型幻觉调用只会得到明确报错。
  - **端口随机化**：每次启动取随机空闲调试端口（只绑 127.0.0.1），不写死
    9222/9333 —— 调试端口上任何本机进程都能接管浏览器，暴露面必须最小化。

实例生命周期：模块级单例，第一次工具调用才懒启动，进程退出时 atext 清理；
单实例 + 操作互斥锁 —— 浏览器操作是低频 I/O，串行足够，不做并发 tab 池。
"""

from __future__ import annotations

import atexit
import ipaddress
import json
import os
import socket
import threading
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from .registry import ToolSpec

# page text 截断时尾部保留比例（对齐 tool_protocol 截断的 75/25 形态）
_TAIL_RATIO = 0.25
# JS 求值/点击/输入的默认超时（导航超时独立走 config）
_EVAL_TIMEOUT_SECONDS = 15.0
# RFC 2544 benchmark 段（198.18.0.0/15）：TUN 代理 fake-IP 模式用它承载公网域名，
# Python 的 ipaddress 视其为 private。与 core/transport.py 的同一例外保持一致 ——
# 代理环境下不放行它，等于把全部正常上网导航打死。
_FAKEIP_NETWORKS = tuple(ipaddress.ip_network(n) for n in ("198.18.0.0/15",))


# --------------------------------------------------------------- URL 校验


def _is_blocked_ip(ip, allow_private: bool) -> str | None:
    """返回拒绝原因；放行返回 None。环回/链路本地无条件拒，私网按配置。"""
    if ip.is_loopback or ip.is_link_local or ip.is_unspecified:
        return "环回/链路本地地址无条件拒绝"
    if ip.is_private and not allow_private and not any(ip in net for net in _FAKEIP_NETWORKS):
        return "私网地址默认拒绝（GLM_TOOL_BROWSER_ALLOW_PRIVATE=true 可放行）"
    return None


def validate_url(url: str, allow_private: bool = False) -> str:
    """校验导航目标：scheme 白名单 + 解析后逐 IP 判定。返回规整后的 URL。"""
    text = str(url or "").strip()
    if not text:
        raise ValueError("缺少 URL 参数")
    parts = urlsplit(text)
    if parts.scheme.lower() not in ("http", "https"):
        raise ValueError("只允许 http/https URL: {0}".format(text))
    if not parts.hostname:
        raise ValueError("URL 缺少主机名: {0}".format(text))
    try:
        infos = socket.getaddrinfo(parts.hostname, None)
    except OSError as exc:
        raise ValueError("主机名解析失败: {0}（{1}）".format(parts.hostname, exc)) from exc
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        reason = _is_blocked_ip(ip, allow_private)
        if reason:
            raise ValueError("导航目标被拒绝（{0} → {1}）: {2}".format(parts.hostname, addr, reason))
    return text


# --------------------------------------------------------------- 会话单例


def _profile_dir() -> str:
    custom = os.environ.get("GLM_TOOL_BROWSER_PROFILE", "").strip()
    if custom:
        return custom
    return str(Path.cwd() / ".glmrelay" / "browser-tool")


def _pick_free_port() -> int:
    """向内核要一个空闲 TCP 端口（bind 127.0.0.1）。关闭与浏览器真正监听之间
    存在被抢占的理论窗口，但本机单人场景概率可忽略，换来的是端口不可预测。"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _BrowserSession:
    """专用浏览器的懒启动单例。所有公开操作须持有 `_lock`（工具层已串行化）。"""

    def __init__(self) -> None:
        self._proc = None
        self._client = None
        self._headless = True

    def ensure(self, headless: bool, timeout: float):
        """返回可用的 CDPClient；实例不存在或进程已死则重新启动。"""
        if self._proc is not None and self._proc.poll() is not None:
            self._shutdown()
        if self._client is None:
            self._headless = headless
            from ..browser.cdp import ManagedBrowser

            browser = ManagedBrowser(
                user_data_dir=_profile_dir(),
                port=_pick_free_port(),
                headless=headless,
                start_url="about:blank",
            )
            self._proc, self._client = browser.start(page_url_contains=None, wait_ready=False)
        return self._client

    def _shutdown(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:  # noqa: BLE001  清理路径上的异常没有听众
                pass
            self._client = None
        if self._proc is not None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except Exception:  # noqa: BLE001
                pass
            self._proc = None

    def mark_dead(self) -> None:
        """操作中途 CDP 断连时丢弃实例，下次调用自动重启（自愈）。"""
        self._shutdown()


_session = _BrowserSession()
_session_lock = threading.RLock()
atexit.register(_session._shutdown)


def _run_js(client, expression: str, timeout: float = _EVAL_TIMEOUT_SECONDS):
    try:
        return client.evaluate(expression, timeout=timeout)
    except Exception:
        # CDP 断连/页面崩溃：标记实例死亡，本次失败如实上报，下次自动重建
        _session.mark_dead()
        raise


def _with_page(config, js_expression: str, timeout: float = _EVAL_TIMEOUT_SECONDS):
    """懒启动 + 持锁求值的公共路径。返回 JS 求值结果。"""
    headless = bool(getattr(config, "glm_tool_browser_headless", True))
    op_timeout = float(getattr(config, "glm_tool_browser_timeout_seconds", 45.0))
    with _session_lock:
        client = _session.ensure(headless, op_timeout)
        return _run_js(client, js_expression)


def _overview_js() -> str:
    return "JSON.stringify({title: document.title || '', url: location.href})"


def _overview(client) -> str:
    try:
        raw = _run_js(client, _overview_js())
        info = json.loads(raw) if isinstance(raw, str) else {}
    except Exception:  # noqa: BLE001  概览拿不到不挡主流程
        info = {}
    return "[页面] {0} {1}".format(info.get("title") or "(无标题)", info.get("url") or "")


def _truncate_chars(text: str, limit: int) -> str:
    """页面文本超限时头尾保留（75/25），注明原始长度 —— 模型可请求分页方案。"""
    text = text or ""
    if limit <= 0 or len(text) <= limit:
        return text
    head_len = max(1, int(limit * (1 - _TAIL_RATIO)))
    tail_len = max(1, limit - head_len)
    return (
        text[:head_len]
        + "\n…[已截断：原始 {0} 字符，仅保留首尾；如需完整内容请用 browser_click 定位或分页导航]…\n".format(len(text))
        + text[-tail_len:]
    )


# --------------------------------------------------------------- 工具实现


def _handle_navigate(config):
    def handler(args: dict, session: object) -> str:
        url = validate_url(str(args.get("url", "")), bool(getattr(config, "glm_tool_browser_allow_private", False)))
        headless = bool(getattr(config, "glm_tool_browser_headless", True))
        timeout = float(getattr(config, "glm_tool_browser_timeout_seconds", 45.0))
        with _session_lock:
            client = _session.ensure(headless, timeout)
            try:
                client.navigate(url, timeout=timeout)
            except Exception:
                _session.mark_dead()
                raise
            overview = _overview(client)
            body_text = _run_js(client, "(document.body ? document.body.innerText : '')") or ""
        preview = _truncate_chars(str(body_text).strip(), int(getattr(config, "glm_tool_browser_max_chars", 18000)))
        return overview + "\n\n" + (preview or "(页面无可见文本)")

    return handler


def _handle_read(config):
    def handler(args: dict, session: object) -> str:
        headless = bool(getattr(config, "glm_tool_browser_headless", True))
        timeout = float(getattr(config, "glm_tool_browser_timeout_seconds", 45.0))
        with _session_lock:
            client = _session.ensure(headless, timeout)
            overview = _overview(client)
            body_text = _run_js(client, "(document.body ? document.body.innerText : '')") or ""
        preview = _truncate_chars(str(body_text).strip(), int(getattr(config, "glm_tool_browser_max_chars", 18000)))
        return overview + "\n\n" + (preview or "(页面无可见文本)")

    return handler


def _handle_click(config):
    def handler(args: dict, session: object) -> str:
        selector = str(args.get("selector", "") or "").strip()
        if not selector:
            raise ValueError("缺少 selector 参数（CSS 选择器）")
        # 选择器经 json.dumps 转成合法 JS 字符串字面量，杜绝引号注入
        selector_js = json.dumps(selector, ensure_ascii=False)
        headless = bool(getattr(config, "glm_tool_browser_headless", True))
        timeout = float(getattr(config, "glm_tool_browser_timeout_seconds", 45.0))
        with _session_lock:
            client = _session.ensure(headless, timeout)
            clicked = _run_js(client, (
                "(function(){{var el=document.querySelector({0});"
                "if(!el) return 'not-found'; el.click(); return 'clicked';}})()"
            ).format(selector_js))
            if clicked == "not-found":
                raise ValueError("元素不存在: {0}".format(selector))
            # 点击可能触发导航：短等待让页面回到可用状态再报状态
            try:
                client.wait_loaded(timeout=10.0)
            except Exception:  # noqa: BLE001  未导航的点击 wait_loaded 也不该报错
                pass
            overview = _overview(client)
        return overview + "\n(已点击 " + selector + ")"

    return handler


def _handle_type(config):
    def handler(args: dict, session: object) -> str:
        selector = str(args.get("selector", "") or "").strip()
        text = str(args.get("text", "") or "")
        if not selector:
            raise ValueError("缺少 selector 参数（CSS 选择器）")
        selector_js = json.dumps(selector, ensure_ascii=False)
        text_js = json.dumps(text, ensure_ascii=False)
        headless = bool(getattr(config, "glm_tool_browser_headless", True))
        timeout = float(getattr(config, "glm_tool_browser_timeout_seconds", 45.0))
        # 原生 value setter + input/change 事件：让 React/Vue 类框架感知输入
        type_js = (
            "(function(){{var el=document.querySelector({0});"
            "if(!el) return 'not-found';"
            "var proto=(el instanceof HTMLTextAreaElement)?HTMLTextAreaElement.prototype:HTMLInputElement.prototype;"
            "var desc=Object.getOwnPropertyDescriptor(proto,'value');"
            "if(!desc||!desc.set) return 'not-input';"
            "desc.set.call(el,{1});"
            "el.dispatchEvent(new Event('input',{{bubbles:true}}));"
            "el.dispatchEvent(new Event('change',{{bubbles:true}}));"
            "return 'typed';}})()"
        ).format(selector_js, text_js)
        with _session_lock:
            client = _session.ensure(headless, timeout)
            result = _run_js(client, type_js)
        if result == "not-found":
            raise ValueError("元素不存在: {0}".format(selector))
        if result == "not-input":
            raise ValueError("目标不是可输入元素（input/textarea）: {0}".format(selector))
        return "(已在 {0} 输入 {1} 个字符)".format(selector, len(text))

    return handler


# --------------------------------------------------------------- 工厂表


def _factory_navigate(config) -> ToolSpec:
    return ToolSpec(
        name="browser_navigate",
        description=(
            "让中转的专用浏览器打开一个 http/https 网页并返回标题、URL 与页面文本。"
            "安全约束：环回/私网地址默认拒绝；每次导航使用独立浏览器实例。"
            "参数：url（必填，完整 http/https 地址）。"
        ),
        parameters={
            "type": "object",
            "properties": {"url": {"type": "string", "description": "要打开的完整 URL"}},
            "required": ["url"],
        },
        handler=_handle_navigate(config),
        readonly=True,
    )


def _factory_read(config) -> ToolSpec:
    return ToolSpec(
        name="browser_read",
        description=(
            "读取当前浏览器页面的标题、URL 与可见文本（超长时保留首尾）。"
            "先 browser_navigate 打开页面后再用。无参数。"
        ),
        parameters={"type": "object", "properties": {}, "required": []},
        handler=_handle_read(config),
        readonly=True,
    )


def _factory_click(config) -> ToolSpec:
    return ToolSpec(
        name="browser_click",
        description=(
            "在当前页面上按 CSS 选择器点击一个元素（可能触发导航，返回点击后的页面状态）。"
            "参数：selector（必填，CSS 选择器，如 #submit、a.login）。"
        ),
        parameters={
            "type": "object",
            "properties": {"selector": {"type": "string", "description": "CSS 选择器"}},
            "required": ["selector"],
        },
        handler=_handle_click(config),
        readonly=False,
    )


def _factory_type(config) -> ToolSpec:
    return ToolSpec(
        name="browser_type",
        description=(
            "向当前页面上的 input/textarea 输入文本（触发 input/change 事件，框架可感知）。"
            "参数：selector（必填，CSS 选择器）、text（必填，要输入的文本）。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "selector": {"type": "string", "description": "CSS 选择器"},
                "text": {"type": "string", "description": "要输入的文本"},
            },
            "required": ["selector", "text"],
        },
        handler=_handle_type(config),
        readonly=False,
    )


TOOL_FACTORIES: dict[str, Callable[[object], ToolSpec]] = {
    "browser_navigate": _factory_navigate,
    "browser_read": _factory_read,
    "browser_click": _factory_click,
    "browser_type": _factory_type,
}
