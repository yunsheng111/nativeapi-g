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


def test_context_pool() -> None:
    """P2.5 第二批 D2：BrowserContext 账号隔离池的离线可测面（不启动浏览器）。"""
    from glmrelay.browser.cdp_fetch import CdpFetchTransport, map_cookie_for_context
    from glm2api.core import transport

    # CF cookie 映射
    mapped = map_cookie_for_context(
        {"name": "chatglm_user", "value": "v1", "domain": ".chatglm.cn", "path": "/",
         "expires": 1234.5, "httpOnly": True, "secure": True, "sameSite": "lax", "extra": "drop"}
    )
    check(mapped == {"name": "chatglm_user", "value": "v1", "domain": ".chatglm.cn", "path": "/",
                     "expires": 1234.5, "httpOnly": True, "secure": True, "sameSite": "Lax"},
          "CF-a cookie 映射完整且剥离未知键", str(mapped))
    check(map_cookie_for_context({"value": "v"}) is None, "CF-b 缺 name 的 cookie 丢弃")
    check(map_cookie_for_context({"name": "n", "sameSite": "STRICT"})["sameSite"] == "Strict",
          "CF-c sameSite 大小写归一")

    transport.set_request_account(None)
    try:
        # 无账号提示 → 默认槽（浏览器默认身份，P2.5 第一批形态）
        pool = CdpFetchTransport("_unused_profile", account_contexts=True)
        slot = pool._slot_for_request()
        check(slot.key == "default" and slot.browser_context is False, "CP-a 无提示 → 默认槽")

        # 游客 → 默认槽；非游客 → 专属槽；同账号复用同一槽
        pool2 = CdpFetchTransport(
            "_unused_profile", account_contexts=True,
            guest_resolver=lambda i: i == 0,
        )
        guest_slot = pool2._slot_for_request()
        transport.set_request_account(0)
        same = pool2._slot_for_request()
        check(same.key == "default" and same is guest_slot, "CP-b 游客账号走默认槽")
        transport.set_request_account(2)
        real = pool2._slot_for_request()
        check(real.key == "account-2" and real.browser_context is True, "CP-c 非游客账号懒建专属槽")
        check(pool2._slot_for_request() is real, "CP-d 同账号复用同一槽（不重复建）")
        transport.set_request_account(3)
        other = pool2._slot_for_request()
        check(other is not real and other.binding_name != real.binding_name, "CP-e 不同账号槽隔离且 binding 名独立")

        # 隔离池关闭 → 全部走默认槽
        pool3 = CdpFetchTransport("_unused_profile", account_contexts=False, guest_resolver=lambda i: False)
        transport.set_request_account(1)
        check(pool3._slot_for_request().key == "default", "CP-f account_contexts=false 退回单槽旧形态")
    finally:
        transport.set_request_account(None)

    # cookie_resolver 槽位装配（只查方法存在与绑定，不触发浏览器）
    pool4 = CdpFetchTransport("_unused_profile", cookie_resolver=lambda i: [{"name": "k", "value": "v"}])
    check(pool4.cookie_resolver(0) == [{"name": "k", "value": "v"}], "CP-g cookie_resolver 注入可用")


def test_canary() -> None:
    """P2.5 第二批：canary 传输通道调度（11.4）离线断言。"""
    from glmrelay.browser.cdp_fetch import TransportCanary

    # 默认关闭：pick 不改选路，只记录统计
    off = TransportCanary(enabled=False, default_channel="urllib")
    check(off.pick("urllib") == "urllib", "CY-a 关闭时默认通道不变")
    check(off.pick("cdp") == "cdp", "CY-b 关闭时显式 cdp 不变")
    off.record("cdp", True)
    off.record("urllib", False)
    stats = off.stats()
    check(stats["channels"]["cdp"]["requests"] == 1 and stats["channels"]["urllib"]["failures"] == 1,
          "CY-c 关闭时统计仍记录（transport 记录前置）", str(stats["channels"]))

    # 开启：主力走稳定通道，每 N 次放一次 canary
    canary = TransportCanary(enabled=True, default_channel="urllib", every_n=3, failure_threshold=2, cooldown_seconds=600.0)
    picks = [canary.pick("urllib") for _ in range(2)]
    check(all(p == "urllib" for p in picks), "CY-d N 次内全走稳定通道", str(picks))
    check(canary.pick("urllib") == "cdp", "CY-e 每 N 次放一次 canary 探针")
    check(canary.pick("urllib") == "urllib", "CY-f canary 后回稳定通道")

    # 显式覆盖不参与分流
    check(canary.pick("cdp", explicit=True) == "cdp", "CY-g 显式覆盖直通")
    check(canary.pick("urllib", explicit=True) == "urllib", "CY-h 显式 urllib 直通")

    # 连败淘汰 + 冷却
    for _ in range(2):
        canary.record("cdp", False)
    stats = canary.stats()
    check(stats["channels"]["cdp"]["consecutive_failures"] == 0 and stats["channels"]["cdp"]["failures"] == 2,
          "CY-i 连败达阈值后计数清零（进入冷却）", str(stats["channels"]["cdp"]))
    picks = [canary.pick("urllib") for _ in range(6)]
    check(all(p == "urllib" for p in picks), "CY-j 冷却期不再放 canary", str(picks))

    # 连胜升级建议（翻转判据给数据，不自动翻转）
    promote = TransportCanary(enabled=True, default_channel="urllib", every_n=1, failure_threshold=5, promote_after=3)
    check(promote.pick("urllib") == "cdp", "CY-k every_n=1 每次都放 canary")
    promote.record("cdp", True)
    promote.record("cdp", True)
    check(promote._promote_announced is False, "CY-l 升级阈值前不触发建议")
    promote.record("cdp", True)
    check(promote._promote_announced is True, "CY-m 连胜达阈值触发翻转建议（不自动改配置）")


def main() -> int:
    test_stream_flow()
    test_error_semantics()
    test_cross_thread_feed()
    test_headers_and_bridge()
    test_breaker_and_hint()
    test_config_and_variants()
    test_context_pool()
    test_canary()
    print(f"\nPASS {len(PASS)} / FAIL {len(FAIL)}")
    for name in FAIL:
        print(f"  FAILED: {name}")
    return 0 if not FAIL else 1


if __name__ == "__main__":
    raise SystemExit(main())
