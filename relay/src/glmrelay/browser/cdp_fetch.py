"""CDP 同源 fetch 传输（P2.5）。

把上游 HTTP 请求交给已登录浏览器执行：attach 页面 → 页面内 bridge 发同源
fetch → Runtime.addBinding 逐 chunk 回传。真实浏览器自带 cookie、真实
TLS/JA4/HTTP2 指纹与头序；上游协议（端点 + SSE 格式）不变，translator /
事件累积器 / 工具解析全部原样复用 —— 换传输不换协议。

设计定案见 docs/技术选型融合方案.md 10.7/10.8/11.3：
- 流式泵用第二条 WebSocket 连接同一 target，专职收 bindingCalled，
  主连接的串行 call 不受影响；
- bridge 用 Page.addScriptToEvaluateOnNewDocument 预装 + 首次 evaluate
  注入当前页，binding 名随机会话化，注入面最小化；
- chunk 微批（4KB / 20ms）+ base64（文本与二进制通用）；
- __meta 打头、__end / __err 收尾；HTTP 4xx/5xx 映射为 urllib.error.HTTPError，
  账号轮换与风控分类语义不变；
- fetch 禁止头剔除（浏览器自动发真实值），少伪装 = 少被识别；
- 传输级熔断：CDP 通道连续失败自动回落 urllib（显式记日志），到期半开。
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

from .cdp import CDPClient, CDPError, ManagedBrowser, find_page_target, launch_browser, wait_for_devtools
from .cdp import find_browser

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


class CdpFetchTransport:
    """懒启动浏览器 + 双连接（主 call / 泵事件）+ in-flight 路由 + 熔断。"""

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

        self._lock = threading.Lock()
        self._main_call_lock = threading.Lock()
        self._proc = None
        self._main_client: CDPClient | None = None
        self._pump_client: CDPClient | None = None
        self._pump_thread: threading.Thread | None = None
        self._binding_name = f"__glmFetch{uuid.uuid4().hex[:10]}"
        self._bridge_source = build_bridge_source(self._binding_name, allowed_origin)
        self._inflight: dict[str, CdpStreamResponse] = {}
        self._started = False
        self._closed = False

        self._failures = 0
        self._breaker_until = 0.0

    # -- 熔断（传输级；HTTP 4xx/5xx 是上游响应，不计入）

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

    # -- 生命周期

    def ensure_started(self) -> None:
        with self._lock:
            if self._started and self._proc is not None and self._proc.poll() is None:
                return
            if self._closed:
                raise CDPError("CDP 传输已关闭")
            self._teardown_locked()
            browser = find_browser(self.preferred_browser)
            port = self.port or self._free_port()
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
                target = find_page_target(port, timeout=self.launch_timeout)
                ws_url = target["webSocketDebuggerUrl"]
                self._main_client = CDPClient(ws_url, timeout=self.launch_timeout).connect()
                self._main_client.attach()
                self._main_client.navigate(self.allowed_origin, timeout=self.launch_timeout)
                # 当前页先手动注入一次；addScript 保证后续导航后 bridge 仍在
                self._main_client.evaluate(self._bridge_source, timeout=self.launch_timeout)
                self._main_client.call(
                    "Page.addScriptToEvaluateOnNewDocument",
                    {"source": self._bridge_source},
                    timeout=self.launch_timeout,
                )
                # 泵连接：同一 target 的第二条 WS，只收 bindingCalled
                pump_target = find_page_target(port, timeout=self.launch_timeout)
                self._pump_client = CDPClient(pump_target["webSocketDebuggerUrl"], timeout=self.launch_timeout).connect()
                self._pump_client.call("Runtime.enable", timeout=self.launch_timeout)
                self._pump_client.call(
                    "Runtime.addBinding", {"name": self._binding_name}, timeout=self.launch_timeout
                )
                self._pump_client.call(
                    "Page.addScriptToEvaluateOnNewDocument",
                    {"source": self._bridge_source},
                    timeout=self.launch_timeout,
                )
                self._pump_client.evaluate(self._bridge_source, timeout=self.launch_timeout)
            except Exception:
                self._teardown_locked()
                raise
            self._pump_thread = threading.Thread(
                target=self._pump_loop,
                name="glm2api-cdp-pump",
                daemon=True,
            )
            self._pump_thread.start()
            self._started = True
            _logger.info("CDP 传输就绪 binding=%s", self._binding_name)

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
            _logger.warning("CDP 流式泵连接断开，终止全部 in-flight 请求")
            self._fail_all_inflight("pump disconnected")

        assert self._pump_client is not None
        self._pump_client.pump_events(on_event, on_close)

    def _fail_all_inflight(self, reason: str) -> None:
        with self._lock:
            pending = list(self._inflight.values())
        for response in pending:
            response.feed({"t": "err", "id": response.fetch_id, "message": reason})

    def _teardown_locked(self) -> None:
        self._started = False
        for client in (self._main_client, self._pump_client):
            if client is not None:
                try:
                    client.close()
                except Exception:  # noqa: BLE001
                    pass
        self._main_client = None
        self._pump_client = None
        if self._proc is not None:
            try:
                self._proc.terminate()
            except Exception:  # noqa: BLE001
                pass
            self._proc = None

    def stop(self) -> None:
        with self._lock:
            self._closed = True
            self._teardown_locked()

    @staticmethod
    def _free_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    # -- seam 入口

    def open_(self, request: urllib.request.Request, timeout: float | None = None):
        """对齐 transport seam 契约；仅「请求未发出」阶段失败可回落重放。"""
        effective_timeout = float(timeout) if timeout else 120.0
        try:
            self.ensure_started()
        except CDPError as exc:
            self.record_failure()
            raise CdpTransportRetry(f"CDP 传输启动失败: {exc}") from exc

        fetch_id = uuid.uuid4().hex
        response = CdpStreamResponse(fetch_id, request.full_url, self.keepalive_interval)
        # inflight 必须活到响应消费期结束（close 才弹出）：泵线程按 fetch_id
        # 路由 meta/chunk/end，若 open_ 返回时就弹出，chunk 会因查不到路由被丢弃。
        response.attach_close_hook(self._finish_fetch)
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
            assert self._main_client is not None
            try:
                # CDPClient.call 的响应按 id 路由、非线程安全：并发请求在主连接上必须串行触发
                with self._main_call_lock:
                    result = self._main_client.call(
                        "Runtime.evaluate",
                        {"expression": "window", "returnByValue": False},
                        timeout=effective_timeout,
                    )
                    object_id = (result.get("result") or {}).get("objectId") if isinstance(result, dict) else None
                    if not object_id:
                        raise CDPError("未取得 window objectId")
                    self._main_client.call(
                        "Runtime.callFunctionOn",
                        {
                            "objectId": object_id,
                            "functionDeclaration": (
                                f"function(payloadJson) {{ return window[{json.dumps(self._binding_name + '_send')}](payloadJson); }}"
                            ),
                            "arguments": [{"value": json.dumps(payload, ensure_ascii=False)}],
                            "returnByValue": True,
                        },
                        timeout=effective_timeout,
                    )
            except CDPError as exc:
                self.record_failure()
                raise CdpTransportRetry(f"CDP fetch 触发失败: {exc}") from exc
            try:
                prepared = response.wait_meta(effective_timeout)
            except socket.timeout:
                self.record_failure()
                raise
            except CDPError:
                self.record_failure()
                raise
            self.record_success()
            return prepared
        except Exception:
            # 失败路径立即注销；成功路径交给 close hook
            self._inflight.pop(fetch_id, None)
            raise

    def _finish_fetch(self, fetch_id: str) -> None:
        self._inflight.pop(fetch_id, None)
        self._abort_fetch(fetch_id)

    def _abort_fetch(self, fetch_id: str) -> None:
        """响应被提前 close 时反向 abort 页面内 fetch，避免泄漏野跑。"""
        try:
            if self._main_client is not None:
                self._main_client.evaluate(
                    f'window[{json.dumps(self._binding_name + "_abort")}]({json.dumps(fetch_id)})'
                )
        except CDPError:
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
    )

    def routed_open(request, timeout=None):
        wanted = transport.current_request_transport() or config.glm_transport
        if wanted != "cdp" or cdp.breaked():
            return urllib_open(request, timeout=timeout)
        try:
            response = cdp.open_(request, timeout=timeout)
        except CdpTransportRetry as exc:
            logger.warning("CDP 传输不可用，本次请求回落 urllib（显式回落） detail=%s", exc)
            return urllib_open(request, timeout=timeout)
        cdp.record_success()
        return response

    transport.set_upstream_transport(routed_open)
    import atexit

    atexit.register(cdp.stop)
    logger.info(
        "CDP 传输路由已装配 默认传输=%s 熔断阈值=%d/%.0fs",
        config.glm_transport,
        config.glm_cdp_breaker_threshold,
        config.glm_cdp_breaker_seconds,
    )
    return config.glm_transport == "cdp"


__all__ = [
    "CdpFetchTransport",
    "CdpHeaders",
    "CdpStreamResponse",
    "CdpTransportRetry",
    "build_bridge_source",
    "extract_fetch_headers",
    "install_transport_route",
]
