"""指纹 diff 自检（10.8.6）：真实前端请求 vs bridge fetch 的头集合对比。

「指纹优势」从信仰变成可回归测试的三件套（A2 方法论）：
  1. 抓包：--live 模式用 CDP Network 域抓真实前端自发请求与 bridge fetch
     的请求头样本，落盘 artifacts/fingerprint/（已 ignore）供人工分析；
  2. 分析：对两者头集合做双向 diff —— 「真实有而 bridge 无」是我们缺的
     真头，「bridge 有而真实无」是可能暴露自动化的 tell-tale 假头；
  3. 断言：无 tell-tale 级差异（伪装头不得出现；缺失头限于协议头方向）。

头序说明：CDP 不提供可靠的头顺序观测，头序正确性由结构性事实保证 ——
bridge fetch 与真实前端走同一个浏览器网络栈，排序逻辑天然一致；本脚本
只做头集合与大小写归一后的值形态对比。实测另有一个 CDP 层事实：浏览器
fetch 会把自定义头规范化为 "X-device-id" 形态，头键大小写本身不构成
可靠指纹信号（与真实前端 XHR 保留原大小写不同，归一后对比）。

离线模式（默认）验证 diff 逻辑与已知差异面，不需要浏览器/网络；
--live 模式需要本机 Edge/Chrome 且可联网。

用法：
    python tools/check_fingerprint.py           # 离线
    python tools/check_fingerprint.py --live    # 真实浏览器抓包对比
退出码：0 = 全部通过；1 = 存在 FAIL。
"""

from __future__ import annotations

import json
import sys
import time
import urllib.request
from pathlib import Path

RELAY_SRC = Path(__file__).resolve().parent.parent / "relay" / "src"
sys.path.insert(0, str(RELAY_SRC))

PASS: list[str] = []
FAIL: list[str] = []

ORIGIN = "https://chatglm.cn"
CAPTURE_DIR = Path(__file__).resolve().parent.parent / "artifacts" / "fingerprint"


def check(cond: bool, name: str, detail: str = "") -> None:
    (PASS if cond else FAIL).append(name)
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" :: {detail}" if detail and not cond else ""))


# ------------------------------------------------------------- diff 核心逻辑


def normalize_headers(headers: dict) -> dict[str, str]:
    """头名小写归一；多值头合并（CDP 的 headers 是单值 dict）。"""
    return {str(k).strip().lower(): str(v).strip() for k, v in (headers or {}).items()}


def diff_header_sets(real: dict, bridge: dict) -> dict[str, list[str]]:
    """双向头集合 diff。键：missing_in_bridge（我们缺的真头）/ extra_in_bridge（多出的头）。"""
    real_keys = set(normalize_headers(real))
    bridge_keys = set(normalize_headers(bridge))
    return {
        "missing_in_bridge": sorted(real_keys - bridge_keys),
        "extra_in_bridge": sorted(bridge_keys - real_keys),
    }


# 已知可接受差异（协议头方向）：bridge fetch 携带中转协议头，真实导航请求
# 没有 —— 这些是应用层协议需要，不是指纹 tell-tale。新增差异默认不可接受。
KNOWN_EXTRA_IN_BRIDGE = frozenset(
    {
        "x-sign",
        "x-nonce",
        "x-timestamp",
        "x-request-id",
        "x-device-id",
        "x-app-fr",
        "x-app-platform",
        "x-app-version",
        "x-device-brand",
        "x-device-model",
        "x-lang",
        "app-name",
        "authorization",
        "pragma",
        "cache-control",
        "priority",
        "content-type",  # 真实 XHR 也有；仅对 document 导航样本可接受
    }
)

# tell-tale 级差异（出现即 FAIL）：历史上出过事故的伪装头。
TELLTALE_HEADERS = frozenset({"x-forwarded-for"})

# 已定性差异（live 对比时人工确认过，记录原因）：
# - referer：bridge fetch 不显式设 referrer 时浏览器按默认策略自动补当前页
#   Referer —— 与真实前端 XHR 行为一致；diff 报出它只因为 document 导航样本
#   不带 Referer（方向性差异，非伪装）。
# - upgrade-insecure-requests：document 导航请求特有，fetch/XHR 本就不发。
KNOWN_UNEXPECTED_OK = frozenset({"referer", "upgrade-insecure-requests"})


def classify_diff(diff: dict[str, list[str]]) -> tuple[list[str], list[str]]:
    """把双向 diff 分成（tell_tale, unexpected）。

    tell_tale：明确的伪装/暴露信号（TELLTALE_HEADERS + 伪装 UA 值检测）。
    unexpected：未知方向的差异，留给人工分析（抓包三件套的输入）。
    """
    tell_tale: list[str] = []
    unexpected: list[str] = []
    for name in diff["extra_in_bridge"]:
        if name in TELLTALE_HEADERS:
            tell_tale.append(f"extra_in_bridge:{name}")
        elif name in KNOWN_UNEXPECTED_OK:
            continue  # 已定性差异（见白名单注释）
        elif name not in KNOWN_EXTRA_IN_BRIDGE:
            unexpected.append(f"extra_in_bridge:{name}")
    for name in diff["missing_in_bridge"]:
        if name in ("user-agent", "referer", "cookie"):
            # 真实前端必有而 bridge 缺失的浏览器自动头 —— 剔除逻辑配置错误
            tell_tale.append(f"missing_in_bridge:{name}")
        elif name in KNOWN_UNEXPECTED_OK:
            continue
        elif name not in KNOWN_EXTRA_IN_BRIDGE:
            unexpected.append(f"missing_in_bridge:{name}")
    return tell_tale, unexpected


def check_ua_mismatch(headers: dict) -> list[str]:
    """伪装 UA 值检测（F4 矛盾的可观测化）：urllib 路径 UA 自称浏览器版本。"""
    import re

    conflicts: list[str] = []
    ua = str(normalize_headers(headers).get("user-agent", ""))
    if re.search(r"(?:Edge|Edg|Chrome|Firefox|Safari)/\d+", ua, re.IGNORECASE):
        conflicts.append(f"UA 自称浏览器版本但 TLS/HTTP2 为 Python 栈: {ua}")
    return conflicts


# ------------------------------------------------------------- 离线断言


def test_offline() -> None:
    from glmrelay.browser.cdp_fetch import build_bridge_source, extract_fetch_headers

    # 构造一个带全套伪装头的 urllib 请求（底座历史形态），验证剔除后的差异面
    request = urllib.request.Request(
        f"{ORIGIN}/backend-api/assistant/stream",
        method="POST",
        data=b"{}",
        headers={
            "Accept": "text/event-stream",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Authorization": "Bearer t",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0",
            "Referer": f"{ORIGIN}/main/alltoolsdetail",
            "Cookie": "k=v",
            "X-Forwarded-For": "1.2.3.4",
            "Sec-Ch-Ua": '"Chromium";v="143"',
            "Sec-Fetch-Mode": "cors",
            "X-Sign": "sig",
            "X-Device-Id": "dev",
        },
    )
    bridge_headers = extract_fetch_headers(request)

    # FP-a：历史事故头全部不出现
    normalized = normalize_headers(bridge_headers)
    check(
        not ({"x-forwarded-for", "cookie", "user-agent", "referer"} & set(normalized))
        and not any(k.startswith("sec-") for k in normalized),
        "FP-a bridge 头剔除后无 XFF/Cookie/伪装UA/Referer/Sec-*",
        str(sorted(normalized)),
    )

    # FP-b：协议头保留（对齐真实前端 XHR 的应用层头方向）
    check(
        {"x-sign", "x-device-id", "authorization"} <= set(normalized),
        "FP-b 协议头保留（应用层契约）",
    )

    # FP-c：bridge 结构保证 —— credentials=include 使 cookie 行为与真实前端同机制
    source = build_bridge_source("__fp", ORIGIN)
    check("credentials: 'include'" in source, "FP-c bridge 同源携带凭据（cookie 机制与真实前端一致）")

    # FP-d：diff 分类逻辑
    diff = diff_header_sets(
        {"User-Agent": "real", "Accept-Language": "zh-CN", "X-Unknown-Header": "1"},
        {"x-forwarded-for": "1", "x-sign": "s", "User-Agent": "real"},
    )
    tell_tale, unexpected = classify_diff(diff)
    check(
        "extra_in_bridge:x-forwarded-for" in tell_tale
        and "extra_in_bridge:x-sign" not in tell_tale
        and "missing_in_bridge:x-unknown-header" in unexpected,
        "FP-d diff 分类：tell-tale 与未知差异分离",
        f"tell={tell_tale} unexpected={unexpected}",
    )
    check(
        classify_diff(diff_header_sets({"User-Agent": "r"}, {"User-Agent": "r"})) == ([], []),
        "FP-e 无差异时零分类输出",
    )

    # FP-f：F4 矛盾自检可观测（urllib 路径的已知挂账项 —— 记录为预期存在）
    urllib_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0",
    }
    conflicts = check_ua_mismatch(urllib_headers)
    check(len(conflicts) == 1, "FP-f urllib 伪装 UA 矛盾可被自检枚举（F4 挂账可观测化）", str(conflicts))
    clean = check_ua_mismatch({"User-Agent": "glm2api/0.3"})
    check(clean == [], "FP-g 非浏览器 UA 不误报")


# ------------------------------------------------------------- live 抓包对比


def run_live() -> None:
    import socket as socket_mod
    import threading

    from glmrelay.browser.cdp import (
        CDPClient,
        find_browser,
        find_page_target,
        launch_browser,
        normalize_ws_url,
        wait_for_devtools,
    )
    from glmrelay.browser.cdp_fetch import build_bridge_source, extract_fetch_headers

    with socket_mod.socket(socket_mod.AF_INET, socket_mod.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = int(sock.getsockname()[1])
    profile = Path(__file__).resolve().parent.parent / "relay" / "_cdp_profile_fingerprint"
    browser = find_browser(None)
    proc = launch_browser(browser, port=port, user_data_dir=str(profile), url=ORIGIN, headless=True)
    main_client: CDPClient | None = None
    pump_client: CDPClient | None = None
    try:
        wait_for_devtools(port, timeout=60.0)
        target = find_page_target(port, timeout=60.0)
        ws_url = normalize_ws_url(str(target["webSocketDebuggerUrl"]), port)
        main_client = CDPClient(ws_url).connect()
        main_client.attach()
        main_client.wait_loaded(timeout=60.0)

        # 双连接形态（与传输层一致）：泵连接专收 Network 事件 —— 事件只在
        # 连接的 recv 循环里被消费，单连接靠 call 驱动会漏掉间隔期事件。
        # pump_events 是阻塞循环，与传输层一致必须跑独立线程。
        network_events: list[dict] = []
        pump_client = CDPClient(ws_url).connect()
        pump_client.call("Network.enable", {}, timeout=10.0)
        threading.Thread(
            target=lambda: pump_client.pump_events(
                lambda message: network_events.append(message)
                if message.get("method") == "Network.requestWillBeSent"
                else None
            ),
            daemon=True,
        ).start()
        # 泵就绪后再导航进 SPA 内页：首页主加载的请求发生在泵连接建立之前，
        # 路由跳转会确定性地触发前端自发请求（document + 数据 XHR）
        main_client.call(
            "Page.navigate", {"url": f"{ORIGIN}/main/alltoolsdetail"}, timeout=30.0
        )
        time.sleep(8.0)
        # 记录 (url, headers, resource_type)：type 字段用于选 XHR/Fetch 样本
        real_rows = []
        for e in network_events:
            params = e.get("params") or {}
            req = params.get("request") or {}
            url = str(req.get("url", ""))
            headers = req.get("headers") or {}
            if url.startswith(ORIGIN) and url.split("?")[0] != ORIGIN and headers:
                real_rows.append((url, headers, str(params.get("type") or "")))
        check(len(real_rows) >= 1, "FP-L-a 抓到真实前端请求样本", f"count={len(real_rows)}")

        # bridge fetch 同源端点：binding 在主连接 session 上，meta 事件也回主连接
        binding = "__fpLiveProbe"
        main_client.call("Runtime.addBinding", {"name": binding}, timeout=10.0)
        bridge_source = build_bridge_source(binding, ORIGIN)
        main_client.evaluate(bridge_source, timeout=20.0)
        probe_url = real_rows[0][0] if real_rows else f"{ORIGIN}/"
        request = urllib.request.Request(probe_url, method="GET", headers={"X-Device-Id": "fp-probe"})
        payload = {
            "t": "go",
            "id": "fp-probe-1",
            "url": request.full_url,
            "method": "GET",
            "headers": extract_fetch_headers(request),
            "bodyB64": None,
            "timeoutMs": 30000,
        }
        main_client.evaluate(
            f'window[{json.dumps(binding + "_send")}]({json.dumps(json.dumps(payload, ensure_ascii=False))})',
            timeout=20.0,
        )
        # 主连接的 recv 由轻量 call 驱动消费：等 meta bindingCalled 到达
        meta_seen = False
        for _ in range(50):
            main_client.call("Runtime.evaluate", {"expression": "1", "returnByValue": True}, timeout=5.0)
            meta_seen = any(
                e.get("method") == "Runtime.bindingCalled" and '"fp-probe-1"' in str((e.get("params") or {}).get("payload", ""))
                for e in main_client.events
            )
            if meta_seen:
                break
            time.sleep(0.2)
        check(meta_seen, "FP-L-b bridge fetch 的 meta 事件回传", probe_url)

        # bridge 发出的请求在泵连接的 Network 事件里按自定义头识别。
        # 实测（CDP 观测）：浏览器 fetch 会把自定义头规范化为 "X-device-id"
        # 形态 —— 识别必须大小写不敏感，这本身就是 diff 的输入之一。
        bridge_row = None
        for e in network_events:
            req = (e.get("params") or {}).get("request") or {}
            headers = req.get("headers") or {}
            probe_value = next(
                (v for k, v in headers.items() if str(k).lower() == "x-device-id"), None
            )
            if probe_value == "fp-probe":
                bridge_row = (req.get("url", ""), headers)
                break
        check(bridge_row is not None, "FP-L-c 抓到 bridge fetch 的 CDP 观测头", probe_url)

        if real_rows and bridge_row is not None:
            # diff 样本优先选 XHR/Fetch（与 bridge fetch 同形态；document 导航
            # 请求有导航特有头，会产生方向性错配的假差异）
            xhr_rows = [r for r in real_rows if r[2] in ("XHR", "Fetch")]
            chosen = xhr_rows[-1] if xhr_rows else real_rows[-1]
            real_url, real_headers = chosen[0], chosen[1]
            diff = diff_header_sets(real_headers, bridge_row[1])
            tell_tale, unexpected = classify_diff(diff)

            CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
            capture = {
                "captured_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "probe_url": probe_url,
                "real_sample": {"url": real_url, "headers": real_headers},
                "bridge_sample": {"url": bridge_row[0], "headers": bridge_row[1]},
                "diff": diff,
                "tell_tale": tell_tale,
                "unexpected": unexpected,
                "note": "头序由浏览器网络栈结构性保证（bridge 与前端同栈），CDP 不可观测头序",
            }
            out = CAPTURE_DIR / f"fingerprint-capture-{int(time.time())}.json"
            out.write_text(json.dumps(capture, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

            check(
                not tell_tale,
                "FP-L-d 无 tell-tale 级头差异（无伪装头/无缺失浏览器自动头）",
                str(tell_tale),
            )
            check(
                not unexpected,
                "FP-L-e 无未知方向差异（新增差异需人工定性后并入白名单）",
                f"unexpected={unexpected} 样本落盘 {out}",
            )
            print(f"  抓包样本已落盘: {out}")
    finally:
        for closer in (main_client, pump_client):
            if closer is not None:
                try:
                    closer.close()
                except Exception:  # noqa: BLE001
                    pass
        try:
            proc.terminate()
        except Exception:  # noqa: BLE001
            pass


def main() -> int:
    live = "--live" in sys.argv
    test_offline()
    if live:
        run_live()
    print(f"\nPASS {len(PASS)} / FAIL {len(FAIL)}")
    for name in FAIL:
        print(f"  FAILED: {name}")
    return 0 if not FAIL else 1


if __name__ == "__main__":
    raise SystemExit(main())
