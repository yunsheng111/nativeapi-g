"""P2.5 cdp_fetch 验收：CdpStreamResponse 纯单测 + 传输路由离线断言。

双层测试策略（10.7 ④）：页面 origin 是 chatglm.cn，fetch 本地 mock 会被
CORS 拦截 —— 因此流式协议全部用直接喂 binding 消息序列的方式离线验证，
不依赖网络；真实端到端往返由 tools/check_cdp_fetch_live.py 单独覆盖。

用法：
    python tools/check_cdp_fetch.py
退出码：0 = 全部通过；1 = 存在 FAIL。
"""

from __future__ import annotations

import base64
import http.client
import socket
import sys
import threading
import time
import urllib.error
from pathlib import Path

RELAY_SRC = Path(__file__).resolve().parent.parent / "relay" / "src"
sys.path.insert(0, str(RELAY_SRC))

PASS: list[str] = []
FAIL: list[str] = []


def check(cond: bool, name: str, detail: str = "") -> None:
    (PASS if cond else FAIL).append(name)
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" :: {detail}" if detail and not cond else ""))


def b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


# --------------------------------------------------------------- CdpStreamResponse 流协议

def test_stream_flow() -> None:
    from glmrelay.browser.cdp_fetch import CdpStreamResponse

    resp = CdpStreamResponse("f1", "https://chatglm.cn/backend-api/x", keepalive_interval=0.2)
    resp.feed({"t": "meta", "id": "f1", "status": 200, "headers": {"Content-Type": "text/event-stream; charset=utf-8"}})
    resp.feed({"t": "chunk", "id": "f1", "seq": 0, "data": b64("A" * 5000)})  # 微批块大于单次读取量
    resp.feed({"t": "chunk", "id": "f1", "seq": 1, "data": b64("B" * 100)})
    resp.feed({"t": "end", "id": "f1"})

    check(resp.status == 200, "F1 meta 状态透出")
    check(resp.headers.get("content-type") == "text/event-stream; charset=utf-8", "F1-b 头大小写不敏感 get")
    check(resp.headers.get_content_type() == "text/event-stream", "F1-c get_content_type 剥参数")

    first = resp.read(4096)
    check(first == b"A" * 4096, "F2-a 按请求量返回且不丢数据")
    second = resp.read(4096)
    check(second == b"A" * 904 + b"B" * 100, "F2-b 超量残块回灌后续读", repr(len(second)))
    third = resp.read(4096)
    check(third == b"", "F2-c end 后读尽返回空")

    closed = CdpStreamResponse("f2", "u", 0.2)
    closed.feed({"t": "meta", "id": "f2", "status": 200, "headers": {}})
    closed.close()
    check(closed.read(10) == b"", "F2-d close 后 read 返回空")


def test_error_semantics() -> None:
    from glmrelay.browser.cdp_fetch import CdpStreamResponse

    # 4xx → wait_meta 抛 HTTPError，错误体可读
    resp = CdpStreamResponse("f3", "https://chatglm.cn/backend-api/x", 0.2)
    resp.feed({"t": "meta", "id": "f3", "status": 401, "headers": {"Content-Type": "application/json"}})
    resp.feed({"t": "chunk", "id": "f3", "seq": 0, "data": b64('{"message":"unauthorized"}')})
    resp.feed({"t": "end", "id": "f3"})
    raised = None
    try:
        resp.wait_meta(5)
    except urllib.error.HTTPError as exc:
        raised = exc
    check(raised is not None and raised.code == 401, "F3 4xx → HTTPError(code=401)", str(raised))
    check(raised is not None and raised.read() == b'{"message":"unauthorized"}', "F3-b HTTPError 错误体可读")

    # 流中断 → IncompleteRead（_iter_sse_events 按已收内容收尾）
    resp2 = CdpStreamResponse("f4", "u", 0.2)
    resp2.feed({"t": "meta", "id": "f4", "status": 200, "headers": {}})
    resp2.feed({"t": "chunk", "id": "f4", "seq": 0, "data": b64("partial")})
    resp2.feed({"t": "err", "id": "f4", "message": "pump disconnected"})
    raised2 = None
    try:
        resp2.read(4096)
    except http.client.IncompleteRead as exc:
        raised2 = exc
    check(raised2 is not None and raised2.partial == b"partial", "F4 流中断 → IncompleteRead 携带已收数据")

    # keepalive：空闲抛 socket.timeout
    resp3 = CdpStreamResponse("f5", "u", 0.15)
    resp3.feed({"t": "meta", "id": "f5", "status": 200, "headers": {}})
    t0 = time.monotonic()
    raised3 = None
    try:
        resp3.read(4096)
    except socket.timeout:
        raised3 = True
    check(raised3 is True and 0.1 <= time.monotonic() - t0 <= 1.0, "F5 空闲 keepalive 超时抛 socket.timeout")

    # meta 等待超时
    resp4 = CdpStreamResponse("f6", "u", 0.2)
    t0 = time.monotonic()
    raised4 = None
    try:
        resp4.wait_meta(0.2)
    except socket.timeout:
        raised4 = True
    check(raised4 is True and time.monotonic() - t0 < 1.5, "F6 等待响应头超时抛 socket.timeout")


def test_cross_thread_feed() -> None:
    from glmrelay.browser.cdp_fetch import CdpStreamResponse

    resp = CdpStreamResponse("f7", "u", 0.3)
    result: dict = {}

    def reader() -> None:
        result["first"] = resp.read(4096)
        result["second"] = resp.read(4096)

    thread = threading.Thread(target=reader)
    thread.start()
    time.sleep(0.1)
    resp.feed({"t": "meta", "id": "f7", "status": 200, "headers": {}})
    resp.feed({"t": "chunk", "id": "f7", "seq": 0, "data": b64("hello")})
    resp.feed({"t": "end", "id": "f7"})
    thread.join(timeout=5)
    check(result.get("first") == b"hello" and result.get("second") == b"", "F7 跨线程 feed → read 阻塞唤醒")


# --------------------------------------------------------------- 头提取 / bridge / 熔断 / 路由

def test_headers_and_bridge() -> None:
    import urllib.request

    from glmrelay.browser.cdp_fetch import build_bridge_source, extract_fetch_headers

    request = urllib.request.Request(
        "https://chatglm.cn/backend-api/x",
        method="POST",
        data=b"{}",
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer t",
            "User-Agent": "fake-ua",
            "Referer": "https://chatglm.cn/main",
            "Accept-Encoding": "gzip",
            "Cookie": "k=v",
            "X-Sign": "sig",
            "X-Device-Id": "dev",
            "Sec-Ch-Ua": '"Chromium"',
            "Sec-Fetch-Mode": "cors",
            "X-Forwarded-For": "1.2.3.4",
            "Connection": "keep-alive",
            "Content-Length": "2",
        },
    )
    got = extract_fetch_headers(request)
    keys = {k.lower() for k in got}
    check("user-agent" not in keys and "referer" not in keys and "accept-encoding" not in keys,
          "F8-a 伪装 UA/Referer/Accept-Encoding 剔除")
    check("cookie" not in keys and "host" not in keys and "origin" not in keys and "connection" not in keys
          and "content-length" not in keys and "x-forwarded-for" not in keys, "F8-b Cookie/Host/Origin/XFF 剔除")
    check(not any(k.startswith("sec-") for k in keys), "F8-c Sec-* 受限头剔除")
    check("x-sign" in keys and "x-device-id" in keys and "authorization" in keys and "content-type" in keys,
          "F8-d 协议头与鉴权头保留", str(sorted(keys)))

    source = build_bridge_source("__glmFetchabc123", "https://chatglm.cn")
    check('"__glmFetchabc123"' in source and "NAME + '_send'" in source and "NAME + '_abort'" in source,
          "F9 bridge 含随机会话 binding 与 send/abort 入口")
    check("credentials: 'include'" in source and "AbortController" in source, "F9-b bridge 同源携带凭据 + 超时可中止")
    check("location.origin !== ORIGIN" in source, "F9-c bridge 含 origin 守卫")
    check("4096" in source and "20" in source, "F9-d bridge 微批 4KB/20ms")


def test_breaker_and_hint() -> None:
    from glmrelay.browser.cdp_fetch import CdpFetchTransport
    from glm2api.core import transport

    cdp = CdpFetchTransport("_unused_profile", breaker_threshold=3, breaker_seconds=0.3)
    check(not cdp.breaked(), "F10 初始未熔断")
    cdp.record_failure()
    cdp.record_failure()
    check(not cdp.breaked(), "F10-b 阈值内不熔断")
    cdp.record_failure()
    check(cdp.breaked(), "F10-c 连续 3 次失败熔断")
    time.sleep(0.35)
    check(not cdp.breaked(), "F10-d 到期半开恢复")
    cdp.record_success()
    check(cdp._failures == 0, "F10-e 成功清零连续失败计数")

    transport.set_request_transport("cdp")
    check(transport.current_request_transport() == "cdp", "F11 thread-local 提示 cdp")
    transport.set_request_transport("urllib")
    check(transport.current_request_transport() == "urllib", "F11-b 提示 urllib")
    transport.set_request_transport(None)
    check(transport.current_request_transport() is None, "F11-c None 清除")
    transport.set_request_transport("bogus")
    check(transport.current_request_transport() is None, "F11-d 非法值按 None 处理")
    transport.set_request_transport(None)


def test_config_and_variants() -> None:
    from glm2api.model_variants import expand_model_variants, model_requests_cdp, split_model_features

    check(model_requests_cdp("glm-4.6-cdp") is True, "F12 -cdp 后缀识别")
    check(model_requests_cdp("glm-4.6") is False, "F12-b 无后缀不误判")
    base, features = split_model_features("glm-4.6-think-cdp")
    check(base == "glm-4.6" and features == {"think", "cdp"}, "F12-c think+cdp 组合剥离")
    check(model_requests_cdp("glm-4.6-cdp-search") is True, "F12-d cdp+search 组合识别", str(split_model_features("glm-4.6-cdp-search")))
    expanded = expand_model_variants(["glm-4.6"])
    check(not any(m.endswith("-cdp") for m in expanded), "F12-e /models 变体列表不自动展开 -cdp")


def main() -> int:
    test_stream_flow()
    test_error_semantics()
    test_cross_thread_feed()
    test_headers_and_bridge()
    test_breaker_and_hint()
    test_config_and_variants()
    print(f"\nPASS {len(PASS)} / FAIL {len(FAIL)}")
    for name in FAIL:
        print(f"  FAILED: {name}")
    return 0 if not FAIL else 1


if __name__ == "__main__":
    raise SystemExit(main())
