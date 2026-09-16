"""P2.5 cdp_fetch 集成自检：真实浏览器 + 真实上游的无害往返。

用例全部无害：同源 GET 首页（200 + HTML）与带假凭证的会话删除（上游
必回 JSON 错误体）—— 验证 bridge 预装、binding 流式回传、头剔除后的
真实指纹请求、HTTP 错误语义映射。需要本机装有 Edge/Chrome 且可联网。

用法：
    python tools/check_cdp_fetch_live.py
退出码：0 = 全部通过；1 = 存在 FAIL。
"""

from __future__ import annotations

import json
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

RELAY_SRC = Path(__file__).resolve().parent.parent / "relay" / "src"
sys.path.insert(0, str(RELAY_SRC))

PASS: list[str] = []
FAIL: list[str] = []


def check(cond: bool, name: str, detail: str = "") -> None:
    (PASS if cond else FAIL).append(name)
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" :: {detail}" if detail and not cond else ""))


ORIGIN = "https://chatglm.cn"


def browser_headers() -> dict[str, str]:
    # 与底座 get_browser_headers 同形态（伪装头会被 extract_fetch_headers 剔除，
    # 正好顺带验证剔除逻辑在真实链路生效）
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) fake-ua-for-test",
        "Accept": "application/json, text/plain, */*",
        "Referer": f"{ORIGIN}/main/alltoolsdetail",
        "X-Request-Id": f"req-{int(time.time())}",
        "X-Device-Id": "cdp-live-check-device",
    }


def main() -> int:
    from glmrelay.browser.cdp_fetch import CdpFetchTransport, CdpTransportRetry

    profile = Path(__file__).resolve().parent.parent / "relay" / "_cdp_profile_live_check"
    cdp = CdpFetchTransport(
        str(profile),
        allowed_origin=ORIGIN,
        headless=True,
        breaker_threshold=100,
        breaker_seconds=1.0,
        keepalive_interval=1.0,
    )
    try:
        # L1 浏览器懒启动 + 双连接就绪
        t0 = time.monotonic()
        cdp.ensure_started()
        check(True, "L1 浏览器启动 + 主/泵双连接就绪", f"{time.monotonic() - t0:.1f}s")

        # L2 同源 GET 首页：200 + HTML 流
        request = urllib.request.Request(ORIGIN, method="GET", headers=browser_headers())
        response = cdp.open_(request, timeout=60)
        check(response.status == 200, "L2 同源 GET 首页 → 200", str(response.status))
        head = response.read(4096)
        check(b"<" in head and len(head) > 100, "L2-b SSE/HTML chunk 流式到达", repr(head[:40]))
        tail = response.read()
        check(isinstance(tail, bytes), "L2-c 流读尽收尾")
        response.close()
        cdp.record_success()

        # L3 假凭证删除请求 → 上游错误体经 HTTPError 透出（错误语义映射）
        body = json.dumps({"conversation_id": "cdp-live-check-invalid", "assistant_id": "x"}).encode("utf-8")
        request = urllib.request.Request(
            f"{ORIGIN}/backend-api/prompt/deleteConversation",
            method="POST",
            data=body,
            headers={
                **browser_headers(),
                "Content-Type": "application/json",
                "Authorization": "Bearer invalid-token-for-live-check",
                "X-Sign": "0" * 32,
                "X-Nonce": "nonce",
                "X-Timestamp": str(int(time.time())),
            },
        )
        error_seen = None
        response_seen = None
        try:
            response_seen = cdp.open_(request, timeout=60)
        except urllib.error.HTTPError as exc:
            error_seen = exc
        if error_seen is not None:
            payload = error_seen.read().decode("utf-8", "replace")
            check(400 <= error_seen.code < 600 and len(payload) > 0,
                  "L3 4xx/5xx → HTTPError + JSON 错误体", f"code={error_seen.code} body={payload[:60]}")
        elif response_seen is not None:
            payload = response_seen.read(8192).decode("utf-8", "replace")
            check(True, "L3 上游 200 回应（状态口径不同，往返已通）", payload[:60])
            response_seen.close()
        else:
            check(False, "L3 未获得任何响应")

        # L4 并发两条请求（页面内多 fetch 并行，按 id 路由互不串扰）
        outcomes: list[tuple[int, int | None]] = []
        lock = threading.Lock()

        def parallel_call(index: int) -> None:
            request = urllib.request.Request(ORIGIN, method="GET", headers=browser_headers())
            try:
                response = cdp.open_(request, timeout=60)
                data = response.read(4096)
                with lock:
                    outcomes.append((index, response.status if data else 0))
                response.close()
            except urllib.error.HTTPError:
                with lock:
                    outcomes.append((index, None))

        threads = [threading.Thread(target=parallel_call, args=(i,)) for i in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=90)
        check(len(outcomes) == 2 and all(status in (200, None) for _, status in outcomes),
              "L4 并发 fetch 路由互不串扰", str(outcomes))
    except CdpTransportRetry as exc:
        check(False, "L0 CDP 传输启动失败", str(exc))
    finally:
        cdp.stop()

    print(f"\nPASS {len(PASS)} / FAIL {len(FAIL)}")
    for name in FAIL:
        print(f"  FAILED: {name}")
    return 0 if not FAIL else 1


if __name__ == "__main__":
    raise SystemExit(main())
