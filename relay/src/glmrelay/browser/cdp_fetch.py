"""CDP 同源 fetch 传输（P2.5 + P2.5 第二批 BrowserContext 账号隔离池）。

把上游 HTTP 请求交给已登录浏览器执行：attach 页面 → 页面内 bridge 发同源
fetch → Runtime.addBinding 逐 chunk 回传。真实浏览器自带 cookie、真实
TLS/JA4/HTTP2 指纹与头序；上游协议（端点 + SSE 格式）不变，translator /
事件累积器 / 工具解析全部原样复用 —— 换传输不换协议。

设计定案见 docs/技术选型融合方案.md 10.7/10.8/11.3 与 D2（11.2-A）：
- 流式泵用第二条 WebSocket 连接同一 target，专职收 bindingCalled，
  主连接的串行 call 不受影响；
- bridge 用 Page.addScriptToEvaluateOnNewDocument 预装 + 首次 evaluate
  注入当前页，binding 名随机会话化，注入面最小化；
- chunk 微批（4KB / 20ms）+ base64（文本与二进制通用）；
- __meta 打头、__end / __err 收尾；HTTP 4xx/5xx 映射为 urllib.error.HTTPError，
  账号轮换与风控分类语义不变；
- fetch 禁止头剔除（浏览器自动发真实值），少伪装 = 少被识别；
- 传输级熔断：CDP 通道连续失败自动回落 urllib（显式记日志），到期半开。

P2.5 第二批（D2 定案）：非游客账号各自绑定专属 BrowserContext
（Target.createBrowserContext，cookie/存储互相隔离），同源 fetch 自动带
该账号自己的 cookie —— 消除「账号 A 的 cookie + 账号 B 的 Authorization」
身份混叠。cookie 来源：登录导入时 importer 抓取（accounts.json 旁挂），
context 创建时灌入；游客与无 cookie 账号使用干净 context（身份隔离仍然
成立：context 内身份自洽且跨请求稳定）。
"""

from __future__ import annotations

import base64
import json
import logging
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections import deque
from http.client import IncompleteRead
from typing import Callable

from .cdp import CDPClient, CDPError, find_browser, find_browser_target, find_page_target, find_target_by_id, launch_browser, wait_for_devtools

_logger = logging.getLogger("glmrelay.cdp_fetch")

# fetch 禁止头：浏览器自动发真实值（或本就不该发），seam 里必须剔除。
# 见融合方案 11.3 —— 少发 10 个假头，让浏览器发 10 个真头。
_FORBIDDEN_HEADER_KEYS = frozenset(
    {
        "accept-encoding",
        "connection",
        "content-length",
        "cookie",
        "host",
        "origin",
        "referer",
        "user-agent",
        "x-forwarded-for",
    }
)

_DEFAULT_KEEPALIVE_INTERVAL = 30.0
_CHUNK_FLUSH_BYTES = 4096
_CHUNK_FLUSH_MS = 20


class CdpTransportRetry(RuntimeError):
    """请求尚未发出即失败的传输故障，调用方可安全回落 urllib 重放。"""


class CdpHeaders:
    """大小写不敏感的响应头视图，对齐 urllib HTTPMessage 的 .get 契约。"""

    def __init__(self, items: dict[str, str]) -> None:
        self._items = {str(k).lower(): str(v) for k, v in (items or {}).items()}

    def get(self, name: str, default: str | None = None) -> str | None:
        return self._items.get(str(name).lower(), default)

    def get_content_type(self) -> str:
        return (self.get("Content-Type") or "application/octet-stream").split(";")[0].strip().lower()

    def as_dict(self) -> dict[str, str]:
        return dict(self._items)


class CdpStreamResponse:
    """伪 response：对齐 urllib 契约（.read 超时抛 socket.timeout、.close、.headers）。

    数据由流式泵线程 feed；HTTP 语义在 read / wait_meta 内还原 ——
    4xx/5xx 收完错误体后抛 HTTPError，流中途死亡抛 IncompleteRead
    （_iter_sse_events 对两者都有既有处理路径）。
    """

    def __init__(self, fetch_id: str, url: str, keepalive_interval: float) -> None:
        self.fetch_id = fetch_id
        self.url = url
        self.status: int | None = None
        self.headers = CdpHeaders({})
        self._cond = threading.Condition()
        self._queue: deque[tuple[str, object]] = deque()
        self._meta_seen = False
        self._ended = False
        self._error: str | None = None
        self._closed = False
        self._bytes_read = 0
        self._error_body: list[bytes] = []
        self._keepalive = keepalive_interval
        self._on_close = None

    # -- 泵线程投递

    def feed(self, message: dict) -> None:
        kind = message.get("t")
        with self._cond:
            if kind == "meta":
                self.status = int(message.get("status") or 0)
                self.headers = CdpHeaders(message.get("headers") or {})
                self._meta_seen = True
            elif kind == "chunk":
                if self.status is not None and self.status >= 400:
                    data = base64.b64decode(message.get("data") or "")
                    self._error_body.append(data)
                else:
                    self._queue.append(("chunk", base64.b64decode(message.get("data") or "")))
            elif kind == "end":
                self._ended = True
            elif kind == "err":
                self._error = str(message.get("message") or "page fetch failed")
                self._ended = True
            else:
                return
            self._cond.notify_all()

    # -- 消费侧

    def _wait_next(self, timeout: float):
        deadline = time.monotonic() + timeout
        with self._cond:
            while not self._queue:
                if self._ended:
                    return ("end", None) if self._error is None else ("err", self._error)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return ("timeout", None)
                self._cond.wait(remaining)
            return self._queue.popleft()

    def wait_meta(self, timeout: float) -> "CdpStreamResponse":
        deadline = time.monotonic() + timeout
        with self._cond:
            while not self._meta_seen:
                if self._ended:
                    raise CDPError(f"页面 fetch 在返回响应前失败: {self._error}")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise socket.timeout(f"CDP fetch 等待响应头超时 {timeout:.0f}s")
                self._cond.wait(remaining)
        if self.status is None:
            raise CDPError("页面 fetch 未返回状态码")
        if self.status >= 400:
            body = self._drain_error_body()
            raise urllib.error.HTTPError(
                self.url,
                self.status,
                "",
                self.headers,  # type: ignore[arg-type]  HTTPError 只要求 .get 兼容
                _BytesIOShim(body),
            )
        return self

    def _drain_error_body(self) -> bytes:
        # 错误体一般很小，等终态（end/err）或封顶 10s，交给 HTTPError.fp
        deadline = time.monotonic() + 10.0
        with self._cond:
            while not self._ended and time.monotonic() < deadline:
                self._cond.wait(0.5)
        return b"".join(self._error_body)

    def read(self, size: int = -1) -> bytes:
        if self._closed:
            return b""
        if self.status is not None and self.status >= 400:
            # HTTPError 已抛出，read 不应再被调用；防御性透出错误体
            body = self._drain_error_body()
            return body

        chunks: list[bytes] = []
        want = size if isinstance(size, int) and size > 0 else None
        while want is None or sum(len(c) for c in chunks) < want:
            kind, payload = self._wait_next(self._keepalive)
            if kind == "timeout":
                raise socket.timeout("CDP fetch 读取空闲超时（keepalive）")
            if kind == "err":
                # 已收的本次数据作为 partial 抛出，_iter_sse_events 按已接收内容收尾
                raise IncompleteRead(b"".join(chunks), self._bytes_read)
            if kind == "end":
                break
            chunks.append(payload)  # type: ignore[arg-type]
            self._bytes_read += len(payload)  # type: ignore[arg-type]
        data = b"".join(chunks)
        if want is not None and len(data) > want:
            # 微批块可能大于请求量：超出部分放回队列头，不丢数据
            self._queue.appendleft(("chunk", data[want:]))
            data = data[:want]
        return data

    def close(self) -> None:
        self._closed = True
        if self._on_close is not None:
            try:
                self._on_close(self.fetch_id)
            except Exception:  # noqa: BLE001
                pass

    def __enter__(self) -> "CdpStreamResponse":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def attach_close_hook(self, hook) -> None:
        self._on_close = hook


class _BytesIOShim:
    def __init__(self, body: bytes) -> None:
        self._buf = body
        self._pos = 0

    def read(self, size: int = -1) -> bytes:
        if self._pos >= len(self._buf):
            return b""
        if size is None or size < 0:
            data = self._buf[self._pos :]
            self._pos = len(self._buf)
            return data
        data = self._buf[self._pos : self._pos + size]
        self._pos += len(data)
        return data


def build_bridge_source(binding_name: str, allowed_origin: str) -> str:
    """页面端 bridge：_send 入口发同源 fetch，结果经 CDP binding 回传。

    注意 window[binding_name] 本身是 Runtime.addBinding 注入的绑定函数
    （页面调用它 → bindingCalled 事件），bridge 绝不能定义/覆盖它。
    """
    return (
        "(() => {\n"
        f"  const NAME = {json.dumps(binding_name)};\n"
        f"  const ORIGIN = {json.dumps(allowed_origin)};\n"
        "  if (window[NAME + '_send']) return;\n"
        "  const send = (obj) => { try { window[NAME](JSON.stringify(obj)); } catch (e) {} };\n"
        "  const aborts = {};\n"
        "  const b64 = (bytes) => { let bin = ''; const CH = 0x8000;"
        " for (let i = 0; i < bytes.length; i += CH)"
        " bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CH)); return btoa(bin); };\n"
        "  const b2u8 = (b) => { const bin = atob(b); const u8 = new Uint8Array(bin.length);"
        " for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i); return u8; };\n"
        "  window[NAME + '_abort'] = (id) => { const c = aborts[id]; if (c) c.abort('closed'); };\n"
        "  window[NAME + '_send'] = (payloadJson) => {\n"
        "    let p; try { p = JSON.parse(payloadJson); } catch (e) { return; }\n"
        "    if (p.t !== 'go') return;\n"
        "    (async () => {\n"
        "      const id = p.id;\n"
        "      const ctrl = new AbortController();\n"
        "      aborts[id] = ctrl;\n"
        "      const timer = p.timeoutMs ? setTimeout(() => ctrl.abort('timeout'), p.timeoutMs) : null;\n"
        "      try {\n"
        "        if (location.origin !== ORIGIN) throw new Error('origin:' + location.origin);\n"
        "        const res = await fetch(p.url, {\n"
        "          method: p.method,\n"
        "          headers: p.headers || {},\n"
        "          body: p.bodyB64 == null ? undefined : b2u8(p.bodyB64),\n"
        "          credentials: 'include',\n"
        "          referrer: p.referrer || undefined,\n"
        "          signal: ctrl.signal,\n"
        "        });\n"
        "        const headers = {}; res.headers.forEach((v, k) => { headers[k] = v; });\n"
        "        send({ t: 'meta', id, status: res.status, headers });\n"
        "        const reader = res.body.getReader();\n"
        "        let buf = new Uint8Array(0), last = Date.now(), seq = 0;\n"
        "        const flush = () => { if (buf.length) {\n"
        "          send({ t: 'chunk', id, seq: seq++, data: b64(buf) });\n"
        "          buf = new Uint8Array(0); last = Date.now(); } };\n"
        "        for (;;) {\n"
        "          const step = await reader.read();\n"
        "          if (step.done) break;\n"
        "          const merged = new Uint8Array(buf.length + step.value.length);\n"
        "          merged.set(buf); merged.set(step.value, buf.length);\n"
        "          buf = merged;\n"
        "          if (buf.length >= 4096 || Date.now() - last >= 20) flush();\n"
        "        }\n"
        "        flush();\n"
        "        send({ t: 'end', id });\n"
        "      } catch (e) {\n"
        "        send({ t: 'err', id, message: String((e && e.message) || e) });\n"
        "      } finally {\n"
        "        if (timer) clearTimeout(timer);\n"
        "        delete aborts[id];\n"
        "      }\n"
        "    })();\n"
        "  };\n"
        "})();"
    )


def extract_fetch_headers(request: urllib.request.Request) -> dict[str, str]:
    """从 urllib Request 提取 fetch 可设头；禁止头剔除，其余（协议头）保留。"""
    out: dict[str, str] = {}
    for key, value in request.header_items():
        lowered = key.lower()
        if lowered in _FORBIDDEN_HEADER_KEYS or lowered.startswith("sec-"):
            continue
        out[key] = value
    return out


def map_cookie_for_context(cookie: dict) -> dict | None:
    """把 importer 抓到的 cookie dict 映射为 CDP Storage.setCookies 形态。

    缺 name/value 的条目直接丢弃（灌入一个坏 cookie 可能连累整批 setCookies）。
    """
    name = str(cookie.get("name") or "")
    value = str(cookie.get("value") or "")
    if not name:
        return None
    out: dict = {"name": name, "value": value}
    for key in ("domain", "path"):
        if cookie.get(key):
            out[key] = str(cookie[key])
    if cookie.get("expires") is not None:
        try:
            out["expires"] = float(cookie["expires"])
        except (TypeError, ValueError):
            pass
    for key in ("httpOnly", "secure"):
        if key in cookie:
            out[key] = bool(cookie[key])
    same_site = str(cookie.get("sameSite") or "").strip().lower()
    mapped = {"strict": "Strict", "lax": "Lax", "none": "None"}.get(same_site)
    if mapped:
        out["sameSite"] = mapped
    return out


class _AccountSlot:
    """一个隔离身份单元：browserContext（可选）+ page target + 双连接 + in-flight 路由。

    - 默认槽（browser_context=False）：attach 浏览器启动页，用浏览器默认身份，
      游客账号与未开启隔离池时的全部请求都走这里 —— 与 P2.5 第一批行为一致；
    - 账号槽（browser_context=True）：Target.createBrowserContext 建专属
      context，createTarget 在 context 内开页，importer 抓到的 cookie 灌入
      context —— 该账号的 cookie 与 Authorization 同源一致（D2）。

    每个 slot 独立 binding 名与 in-flight 路由表：泵按连接区分，同名 binding
    在不同 session 上互不可见，仍随机会话化以最小化注入面。
    """

    def __init__(self, transport: "CdpFetchTransport", key: str, *, browser_context: bool) -> None:
        self.transport = transport
        self.key = key
        self.browser_context = browser_context
        self.binding_name = f"__glmFetch{uuid.uuid4().hex[:10]}"
        self.bridge_source = build_bridge_source(self.binding_name, transport.allowed_origin)
        self.browser_context_id: str = ""
        self.target_id: str = ""
        self.main_client: CDPClient | None = None
        self.pump_client: CDPClient | None = None
        self.pump_thread: threading.Thread | None = None
        self._main_call_lock = threading.Lock()
        self._inflight: dict[str, CdpStreamResponse] = {}
        self._lock = threading.Lock()
        self._started = False

    # -- 生命周期

    def ensure(self) -> None:
        with self._lock:
            if self._started and self.main_client is not None:
                return
            transport = self.transport
            if transport._browser_client is None:
                raise CDPError("浏览器级 CDP 会话不存在")
            try:
                if self.browser_context:
                    result = transport._browser_client.call(
                        "Target.createBrowserContext", {}, timeout=transport.launch_timeout
                    )
                    self.browser_context_id = str(result.get("browserContextId") or "")
                    if not self.browser_context_id:
                        raise CDPError("Target.createBrowserContext 未返回 browserContextId")
                    # cookie 先于页面创建灌入：首次导航即携带账号身份
                    self._inject_cookies_locked()
                    created = transport._browser_client.call(
                        "Target.createTarget",
                        {"url": transport.allowed_origin, "browserContextId": self.browser_context_id},
                        timeout=transport.launch_timeout,
                    )
                    self.target_id = str(created.get("targetId") or "")
                    if not self.target_id:
                        raise CDPError("Target.createTarget 未返回 targetId")
                    target = find_target_by_id(transport.port, self.target_id, timeout=transport.launch_timeout)
                else:
                    target = find_page_target(transport.port, timeout=transport.launch_timeout)
                ws_url = target["webSocketDebuggerUrl"]
                self.main_client = CDPClient(ws_url, timeout=transport.launch_timeout).connect()
                self.main_client.attach()
                self.main_client.wait_loaded(timeout=transport.launch_timeout)
                # 当前页先手动注入一次；addScript 保证后续导航后 bridge 仍在
                self.main_client.evaluate(self.bridge_source, timeout=transport.launch_timeout)
                self.main_client.call(
                    "Page.addScriptToEvaluateOnNewDocument",
                    {"source": self.bridge_source},
                    timeout=transport.launch_timeout,
                )
                # 泵连接：同一 target 的第二条 WS，只收 bindingCalled
                self.pump_client = CDPClient(ws_url, timeout=transport.launch_timeout).connect()
                self.pump_client.call("Runtime.enable", timeout=transport.launch_timeout)
                self.pump_client.call(
                    "Runtime.addBinding", {"name": self.binding_name}, timeout=transport.launch_timeout
                )
                self.pump_client.call(
                    "Page.addScriptToEvaluateOnNewDocument",
                    {"source": self.bridge_source},
                    timeout=transport.launch_timeout,
                )
                self.pump_client.evaluate(self.bridge_source, timeout=transport.launch_timeout)
            except Exception:
                self._teardown_clients_locked()
                raise
            self.pump_thread = threading.Thread(
                target=self._pump_loop,
                name=f"glm2api-cdp-pump-{self.key}",
                daemon=True,
            )
            self.pump_thread.start()
            self._started = True
            _logger.info(
                "CDP 槽位就绪 key=%s context=%s target=%s",
                self.key,
                self.browser_context_id[:12] or "(默认)",
                self.target_id[:12] or target.get("id", "")[:12],
            )

    def _inject_cookies_locked(self) -> None:
        """把账号 cookie 灌入专属 context（D2）。失败降级为干净 context，
        不阻断槽位创建 —— cookie 是身份一致性的加分项，不是硬前提。"""
        resolver = self.transport.cookie_resolver
        if resolver is None:
            return
        account_key = int(self.key.rsplit("-", 1)[-1])
        try:
            raw_cookies = resolver(account_key) or []
        except Exception as exc:  # noqa: BLE001
            _logger.warning("CDP 账号 cookie 读取失败 key=%s error=%s（降级干净 context）", self.key, exc)
            return
        mapped = [c for c in (map_cookie_for_context(raw) for raw in raw_cookies if isinstance(raw, dict)) if c]
        if not mapped:
            return
        try:
            self.transport._browser_client.call(
                "Storage.setCookies",
                {"cookies": mapped, "browserContextId": self.browser_context_id},
                timeout=15.0,
            )
            _logger.info("CDP 账号 context 已灌入 cookie key=%s count=%d", self.key, len(mapped))
        except CDPError as exc:
            _logger.warning("CDP cookie 灌入失败 key=%s error=%s（降级干净 context）", self.key, exc)

    def _pump_loop(self) -> None:
        def on_event(message: dict) -> None:
            if message.get("method") != "Runtime.bindingCalled":
                return
            payload = (message.get("params") or {}).get("payload")
            if not isinstance(payload, str):
                return
            try:
                data = json.loads(payload)
            except json.JSONDecodeError:
                return
            fetch_id = str(data.get("id") or "")
            response = self._inflight.get(fetch_id)
            if response is not None:
                response.feed(data)

        def on_close() -> None:
            _logger.warning("CDP 流式泵断连 slot=%s，终止该槽全部 in-flight 请求", self.key)
            self.fail_all_inflight("pump disconnected")

        assert self.pump_client is not None
        self.pump_client.pump_events(on_event, on_close)

    def fail_all_inflight(self, reason: str) -> None:
        with self._lock:
            pending = list(self._inflight.values())
        for response in pending:
            response.feed({"t": "err", "id": response.fetch_id, "message": reason})

    def _teardown_clients_locked(self) -> None:
        self._started = False
        for client in (self.main_client, self.pump_client):
            if client is not None:
                try:
                    client.close()
                except Exception:  # noqa: BLE001
                    pass
        self.main_client = None
        self.pump_client = None
        self.pump_thread = None

    def teardown(self, *, dispose: bool = True) -> None:
        """关闭槽位。dispose=True 时顺带销毁专属 context（浏览器级操作）。"""
        with self._lock:
            target_id = self.target_id
            context_id = self.browser_context_id
            self._teardown_clients_locked()
            self.target_id = ""
            self.browser_context_id = ""
        if not dispose:
            return
        browser_client = self.transport._browser_client
        if browser_client is None:
            return
        if target_id:
            try:
                browser_client.call("Target.closeTarget", {"targetId": target_id}, timeout=10.0)
            except CDPError:
                pass
        if context_id:
            try:
                browser_client.call("Target.disposeBrowserContext", {"browserContextId": context_id}, timeout=10.0)
            except CDPError:
                pass

    # -- seam 入口

    def open_(self, request: urllib.request.Request, timeout: float | None = None):
        """对齐 transport seam 契约；仅「请求未发出」阶段失败可回落重放。"""
        effective_timeout = float(timeout) if timeout else 120.0
        self.ensure()
        fetch_id = uuid.uuid4().hex
        response = CdpStreamResponse(fetch_id, request.full_url, self.transport.keepalive_interval)
        # inflight 必须活到响应消费期结束（close 才弹出）：泵线程按 fetch_id
        # 路由 meta/chunk/end，若 open_ 返回时就弹出，chunk 会因查不到路由被丢弃。
        response.attach_close_hook(self._finish_fetch)
        with self._lock:
            self._inflight[fetch_id] = response
        try:
            payload = {
                "t": "go",
                "id": fetch_id,
                "url": request.full_url,
                "method": request.get_method(),
                "headers": extract_fetch_headers(request),
                "bodyB64": base64.b64encode(request.data).decode("ascii") if request.data else None,
                "timeoutMs": int(effective_timeout * 1000),
            }
            assert self.main_client is not None
            try:
                # CDPClient.call 的响应按 id 路由、非线程安全：并发请求在本槽
                # 主连接上必须串行触发（不同槽的连接彼此独立，可并行）
                with self._main_call_lock:
                    result = self.main_client.call(
                        "Runtime.evaluate",
                        {"expression": "window", "returnByValue": False},
                        timeout=effective_timeout,
                    )
                    object_id = (result.get("result") or {}).get("objectId") if isinstance(result, dict) else None
                    if not object_id:
                        raise CDPError("未取得 window objectId")
                    self.main_client.call(
                        "Runtime.callFunctionOn",
                        {
                            "objectId": object_id,
                            "functionDeclaration": (
                                f"function(payloadJson) {{ return window[{json.dumps(self.binding_name + '_send')}](payloadJson); }}"
                            ),
                            "arguments": [{"value": json.dumps(payload, ensure_ascii=False)}],
                            "returnByValue": True,
                        },
                        timeout=effective_timeout,
                    )
            except CDPError as exc:
                raise CdpTransportRetry(f"CDP fetch 触发失败: {exc}") from exc
            try:
                prepared = response.wait_meta(effective_timeout)
            except socket.timeout:
                raise
            except CDPError:
                raise
            return prepared
        except Exception:
            # 失败路径立即注销；成功路径交给 close hook
            with self._lock:
                self._inflight.pop(fetch_id, None)
            raise

    def _finish_fetch(self, fetch_id: str) -> None:
        with self._lock:
            self._inflight.pop(fetch_id, None)
        self._abort_fetch(fetch_id)

    def _abort_fetch(self, fetch_id: str) -> None:
        """响应被提前 close 时反向 abort 页面内 fetch，避免泄漏野跑。"""
        try:
            if self.main_client is not None:
                self.main_client.evaluate(
                    f'window[{json.dumps(self.binding_name + "_abort")}]({json.dumps(fetch_id)})'
                )
        except CDPError:
            pass


class TransportCanary:
    """传输通道 A/B 分流与观测（11.4「默认翻转由数据决定」）。

    对照 gptGrok B 的代理 canary 调度迁移到传输通道维度：
    - 主力走稳定通道（= 全局默认 GLM_TRANSPORT）；
    - 每 N 次放 1 次 canary 到探针通道（另一条）；
    - 探针连败 M 次淘汰冷却（期间全走稳定通道）；
    - 探针连续成功达升级阈值 → 打日志给出翻转建议（**不自动改配置**，
      翻转判据用人看数据拍板）。

    默认关闭（GLM_CANARY_ENABLED=false）：pick 不改变选路，仅 record 记录
    统计 —— 「每请求 transport 记录」这个 canary 前置由此天然达成。
    显式请求覆盖（X-GLM2API-Transport 头 / -cdp 后缀）不参与分流。
    """

    def __init__(
        self,
        *,
        enabled: bool,
        default_channel: str,
        every_n: int = 20,
        failure_threshold: int = 3,
        cooldown_seconds: float = 600.0,
        promote_after: int = 10,
    ) -> None:
        self.enabled = enabled
        self.default_channel = default_channel
        self.every_n = max(1, every_n)
        self.failure_threshold = max(1, failure_threshold)
        self.cooldown_seconds = cooldown_seconds
        self.promote_after = max(1, promote_after)
        self._lock = threading.Lock()
        self._counters: dict[str, dict[str, float]] = {
            "urllib": self._fresh(),
            "cdp": self._fresh(),
        }
        self._since_canary = 0
        self._promote_announced = False

    @staticmethod
    def _fresh() -> dict[str, float]:
        return {
            "requests": 0.0,
            "successes": 0.0,
            "failures": 0.0,
            "consecutive_failures": 0.0,
            "consecutive_successes": 0.0,
            "eliminated_until": 0.0,
        }

    def probe_channel(self) -> str:
        return "cdp" if self.default_channel != "cdp" else "urllib"

    def pick(self, wanted: str, *, explicit: bool = False) -> str:
        """决定本次请求实际走的通道。"""
        if explicit or not self.enabled or wanted not in ("urllib", "cdp"):
            return wanted
        stable = self.default_channel
        probe = self.probe_channel()
        now = time.monotonic()
        with self._lock:
            counters = self._counters[probe]
            eliminated = now < counters["eliminated_until"]
            if not eliminated:
                self._since_canary += 1
                if self._since_canary >= self.every_n:
                    self._since_canary = 0
                    return probe  # 放一次 canary（每 N 次请求 1 次）
            return stable

    def record(self, channel: str, ok: bool, account_tag: str = "") -> None:
        if channel not in self._counters:
            return
        with self._lock:
            counters = self._counters[channel]
            counters["requests"] += 1
            if ok:
                counters["successes"] += 1
                counters["consecutive_failures"] = 0
                counters["consecutive_successes"] += 1
            else:
                counters["failures"] += 1
                counters["consecutive_successes"] = 0
                counters["consecutive_failures"] += 1
            if channel == self.probe_channel():
                if ok and counters["consecutive_successes"] >= self.promote_after and not self._promote_announced:
                    self._promote_announced = True
                    _logger.warning(
                        "canary 探针通道 %s 连续成功 %d 次（稳定通道 %s：%d/%d 成功）——"
                        "具备翻转默认通道的数据条件，是否翻转请人工拍板",
                        channel,
                        int(counters["consecutive_successes"]),
                        self.default_channel,
                        int(self._counters[self.default_channel]["successes"]),
                        int(self._counters[self.default_channel]["requests"]),
                    )
                if not ok and counters["consecutive_failures"] >= self.failure_threshold:
                    counters["eliminated_until"] = time.monotonic() + self.cooldown_seconds
                    counters["consecutive_failures"] = 0
                    _logger.warning(
                        "canary 探针通道 %s 连败 %d 次，淘汰冷却 %.0fs 期间全走 %s",
                        channel,
                        self.failure_threshold,
                        self.cooldown_seconds,
                        self.default_channel,
                    )

    def stats(self) -> dict:
        with self._lock:
            return {
                "enabled": self.enabled,
                "default_channel": self.default_channel,
                "probe_channel": self.probe_channel(),
                "every_n": self.every_n,
                "channels": {
                    name: {k: (int(v) if k not in ("eliminated_until",) else v) for k, v in counters.items()}
                    for name, counters in self._counters.items()
                },
            }


class CdpFetchTransport:
    """浏览器生命周期 + BrowserContext 账号槽池 + 通道级熔断。"""

    def __init__(
        self,
        user_data_dir: str,
        *,
        allowed_origin: str = "https://chatglm.cn",
        headless: bool = False,
        port: int = 0,
        preferred_browser: str | None = None,
        breaker_threshold: int = 3,
        breaker_seconds: float = 600.0,
        keepalive_interval: float = _DEFAULT_KEEPALIVE_INTERVAL,
        launch_timeout: float = 60.0,
        account_contexts: bool = True,
        guest_resolver: Callable[[int], bool] | None = None,
        cookie_resolver: Callable[[int], list[dict]] | None = None,
    ) -> None:
        self.allowed_origin = allowed_origin
        self.headless = headless
        self.port = port
        self.preferred_browser = preferred_browser
        self.user_data_dir = user_data_dir
        self.breaker_threshold = breaker_threshold
        self.breaker_seconds = breaker_seconds
        self.keepalive_interval = keepalive_interval
        self.launch_timeout = launch_timeout
        # D2：非游客账号各自专属 BrowserContext；false 退回单 context 旧形态
        self.account_contexts = account_contexts
        # (account_index) -> bool：该账号是否游客（游客走默认槽）。延迟解析
        # —— 装配时底座 manager 可能尚未创建。
        self.guest_resolver = guest_resolver
        # (account_index) -> list[dict]：该账号的登录 cookie（importer 抓取）。
        self.cookie_resolver = cookie_resolver

        self._lock = threading.Lock()
        self._proc = None
        self._browser_client: CDPClient | None = None
        self._slots: dict[str, _AccountSlot] = {}
        self._started = False
        self._closed = False

        self._failures = 0
        self._breaker_until = 0.0

    # -- 熔断（通道级；HTTP 4xx/5xx 是上游响应，不计入）

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self.breaker_threshold:
                self._breaker_until = time.monotonic() + self.breaker_seconds
                _logger.warning(
                    "CDP 传输连续失败 %d 次，熔断 %.0fs 期间回落 urllib（到期后半开）",
                    self._failures,
                    self.breaker_seconds,
                )

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0

    def breaked(self) -> bool:
        with self._lock:
            return time.monotonic() < self._breaker_until

    # -- 槽位选择

    def _slot_for_request(self) -> _AccountSlot:
        """按账号提示选槽（D2）。游客/无提示 → 默认槽；非游客 → 专属槽（懒建）。"""
        account_index = None
        try:
            from glm2api.core.transport import current_request_account

            account_index = current_request_account()
        except Exception:  # noqa: BLE001
            account_index = None
        if not self.account_contexts or account_index is None:
            return self._slots.setdefault("default", _AccountSlot(self, "default", browser_context=False))
        if self.guest_resolver is not None:
            try:
                if self.guest_resolver(account_index):
                    return self._slots.setdefault("default", _AccountSlot(self, "default", browser_context=False))
            except Exception:  # noqa: BLE001
                pass
        return self._slots.setdefault(
            f"account-{account_index}", _AccountSlot(self, f"account-{account_index}", browser_context=True)
        )

    # -- 浏览器生命周期

    def ensure_started(self) -> None:
        """公开入口：确保浏览器与默认槽就绪（P2.5 第一批 API，live 自检脚本使用）。"""
        self._ensure_browser()

    def _ensure_browser(self) -> None:
        with self._lock:
            if self._started and self._proc is not None and self._proc.poll() is None and self._browser_client is not None:
                return
            if self._closed:
                raise CDPError("CDP 传输已关闭")
            self._teardown_locked()
            browser = find_browser(self.preferred_browser)
            port = self.port or self._free_port()
            self.port = port
            _logger.info("CDP 传输启动浏览器 %s 端口=%d profile=%s", browser, port, self.user_data_dir)
            self._proc = launch_browser(
                browser,
                port=port,
                user_data_dir=self.user_data_dir,
                url=self.allowed_origin,
                headless=self.headless,
            )
            try:
                wait_for_devtools(port, timeout=self.launch_timeout)
                # browser 级连接：Target 域操作（createBrowserContext 等）只能在这里调
                browser_target = find_browser_target(port)
                self._browser_client = CDPClient(
                    browser_target["webSocketDebuggerUrl"], timeout=self.launch_timeout
                ).connect()
                # 默认槽：attach 浏览器启动页（P2.5 第一批形态）
                self._slots.setdefault("default", _AccountSlot(self, "default", browser_context=False)).ensure()
            except Exception:
                self._teardown_locked()
                raise
            self._started = True
            _logger.info("CDP 传输就绪 默认槽就绪 account_contexts=%s", self.account_contexts)

    def _teardown_locked(self) -> None:
        self._started = False
        for slot in list(self._slots.values()):
            try:
                slot.teardown(dispose=False)  # 浏览器都要没了，无需逐个 dispose
            except Exception:  # noqa: BLE001
                pass
        self._slots.clear()
        if self._browser_client is not None:
            try:
                self._browser_client.close()
            except Exception:  # noqa: BLE001
                pass
            self._browser_client = None
        if self._proc is not None:
            try:
                self._proc.terminate()
            except Exception:  # noqa: BLE001
                pass
            self._proc = None

    def stop(self) -> None:
        with self._lock:
            self._closed = True
            # 浏览器仍在时逐槽 dispose context（account context 的 cookie 只在内存，
            # 销毁即失效 —— 这是 D2 的固有特性：context 身份不落盘）
            if self._browser_client is not None:
                for slot in list(self._slots.values()):
                    try:
                        slot.teardown(dispose=True)
                    except Exception:  # noqa: BLE001
                        pass
                self._slots.clear()
            self._teardown_locked()

    def slot_snapshot(self) -> list[dict]:
        """面板/诊断用：当前槽位视图。"""
        with self._lock:
            return [
                {
                    "key": slot.key,
                    "browser_context": slot.browser_context,
                    "started": slot._started,
                    "context_id_head": slot.browser_context_id[:12],
                    "inflight": len(slot._inflight),
                }
                for slot in self._slots.values()
            ]

    @staticmethod
    def _free_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    # -- seam 入口

    def open_(self, request: urllib.request.Request, timeout: float | None = None):
        """对齐 transport seam 契约；仅「请求未发出」阶段失败可回落重放。"""
        try:
            self._ensure_browser()
        except CDPError as exc:
            self.record_failure()
            raise CdpTransportRetry(f"CDP 传输启动失败: {exc}") from exc

        slot = self._slot_for_request()
        try:
            try:
                response = slot.open_(request, timeout=timeout)
            except CdpTransportRetry:
                # 槽内触发失败：该槽连接状态可疑，销毁待下次懒重建
                slot.teardown(dispose=slot.browser_context)
                raise
            except socket.timeout:
                slot.teardown(dispose=slot.browser_context)
                self.record_failure()
                raise
            except CDPError:
                slot.teardown(dispose=slot.browser_context)
                self.record_failure()
                raise
            self.record_success()
            return response
        except CdpTransportRetry:
            self.record_failure()
            raise


def _warn_identity_once(transport_name: str, request: urllib.request.Request, tag: str, logger: logging.Logger) -> None:
    """传输选择点的身份矛盾自检（P1-2/B1，报告二 7.2 边界：只自检不伪造）。

    每次传输选择时构造该路的身份画像并校验；warn_identity_conflicts 内部
    按 (transport, 矛盾文本) 去重，重复矛盾不会刷屏。自检失败静默跳过
    （可观测性辅助路径，不得影响请求主链路）。
    """
    try:
        from glm2api.core import transport as transport_mod
        from glm2api.services.glm_auth import GLMAccessTokenManager

        from ..identity import build_profile_from_headers, warn_identity_conflicts

        headers = dict(request.header_items()) if isinstance(request, urllib.request.Request) else {}
        if transport_name == "cdp":
            # 按实际将发给 fetch 的头自检（禁止头剔除已生效）——用原始头会把
            # "稍后会被剔除的伪装 UA" 误报成矛盾
            headers = extract_fetch_headers(request)
        device_id = ""
        hint = transport_mod.current_request_account()
        manager = GLMAccessTokenManager.last_instance
        if manager is not None and hint is not None:
            device_id = manager.get_device_id_for_account(hint)
        profile = build_profile_from_headers(transport_name, device_id, headers)
        warn_identity_conflicts(profile, logger, tag)
    except Exception:  # noqa: BLE001
        pass


def install_transport_route(config, logger: logging.Logger) -> bool:
    """装配路由 opener 并注入 seam；返回是否实际接管（GLM_TRANSPORT=cdp 时）。"""
    from glm2api.core import transport

    urllib_open = transport._DEFAULT_OPEN

    cdp = CdpFetchTransport(
        user_data_dir=config.glm_cdp_user_data_dir,
        allowed_origin=config.glm_cdp_origin,
        headless=config.glm_cdp_headless,
        port=config.glm_cdp_port,
        breaker_threshold=config.glm_cdp_breaker_threshold,
        breaker_seconds=config.glm_cdp_breaker_seconds,
        keepalive_interval=30.0,
        account_contexts=config.glm_cdp_account_contexts,
        guest_resolver=_make_guest_resolver(),
        cookie_resolver=_make_cookie_resolver(),
    )

    canary = TransportCanary(
        enabled=config.glm_canary_enabled,
        default_channel=config.glm_transport,
        every_n=config.glm_canary_every_n,
        failure_threshold=config.glm_canary_failure_threshold,
        cooldown_seconds=config.glm_canary_cooldown_seconds,
    )

    def _account_tag() -> str:
        hint = transport.current_request_account()
        return f"a{hint}" if hint is not None else "anon"

    def routed_open(request, timeout=None):
        explicit = transport.current_request_transport()
        wanted = explicit or config.glm_transport
        channel = canary.pick(wanted, explicit=explicit is not None)
        tag = _account_tag()
        if channel != "cdp":
            _warn_identity_once("urllib", request, tag, logger)
            ok = True
            try:
                return urllib_open(request, timeout=timeout)
            except Exception:
                ok = False
                raise
            finally:
                canary.record("urllib", ok, tag)
        if cdp.breaked():
            # 熔断打开期不计 canary 统计（cdp 内部熔断已在管），只静默走 urllib
            return urllib_open(request, timeout=timeout)
        _warn_identity_once("cdp", request, tag, logger)
        try:
            response = cdp.open_(request, timeout=timeout)
        except CdpTransportRetry as exc:
            canary.record("cdp", False, tag)
            logger.warning("CDP 传输不可用，本次请求回落 urllib（显式回落） detail=%s", exc)
            return urllib_open(request, timeout=timeout)
        except Exception:
            canary.record("cdp", False, tag)
            raise
        canary.record("cdp", True, tag)
        return response

    transport.set_upstream_transport(routed_open)
    import atexit

    atexit.register(cdp.stop)
    logger.info(
        "CDP 传输路由已装配 默认传输=%s 熔断阈值=%d/%.0fs 账号隔离池=%s canary=%s",
        config.glm_transport,
        config.glm_cdp_breaker_threshold,
        config.glm_cdp_breaker_seconds,
        config.glm_cdp_account_contexts,
        "on" if config.glm_canary_enabled else "off(仅记录)",
    )
    return config.glm_transport == "cdp"


def _make_guest_resolver():
    """延迟解析底座 manager 的游客判定（装配时 manager 可能尚未创建）。"""

    def resolve(account_index: int) -> bool:
        from glm2api.services.glm_auth import GLMAccessTokenManager

        manager = GLMAccessTokenManager.last_instance
        if manager is None:
            return False
        return manager.is_guest_account(account_index)

    return resolve


def _make_cookie_resolver():
    """从 accounts.json 读账号登录 cookie（importer 抓取，P2.5 第二批 D2）。

    账号提示是 index —— token.txt 的行序与底座账号槽一致（轮换原位替换、
    面板导入追加，均不改变既有行序），按行序取 token 后按指纹查旁挂元数据。
    """

    def resolve(account_index: int) -> list[dict]:
        from .accounts.registry import _token_file
        from .accounts.store import TokenStore

        store = TokenStore(_token_file())
        tokens = store.load_tokens()
        if not (0 <= account_index < len(tokens)):
            return []
        meta = store.load_meta()
        entry = meta.get(store.fingerprint(tokens[account_index]))
        if entry is None:
            return []
        cookies = entry.extra.get("cookies")
        return cookies if isinstance(cookies, list) else []

    return resolve


__all__ = [
    "CdpFetchTransport",
    "CdpHeaders",
    "CdpStreamResponse",
    "CdpTransportRetry",
    "TransportCanary",
    "build_bridge_source",
    "extract_fetch_headers",
    "install_transport_route",
    "map_cookie_for_context",
]
