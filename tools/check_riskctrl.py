"""P1-b 抗风控改动卡的验收闸门（D1 / D3 / D4 断言集合）。

纯标准库实现，不引入任何依赖；全部断言离线运行（mock 上游 token 获取），
不打真实网络。每个改动项对应一组断言：

    D4  删除 X-Forwarded-For 伪造头          （源码扫描 + 头集合断言）
    D1  真实 deid 接线 + 废除 8 次轮换        （断言 ①-⑤ + 热更新 + 钩子缺省回退）
    D3  并发节奏：单飞/全忙/冷却/分类/退避     （断言 S1-S9）
    P2  工具契约修复 + 体积治理/信任壳        （断言 B1-B7 + T3 + C1-C6）
    P2#6 DSML 写入 content 抢救              （断言 M1-M7，12.6 失败样本两族回归）
    P2.6/P0-1 状态码分类 + 401 权威标记       （断言 K1-K8，S6 的 401 用例随语义收紧）

用法：
    python tools/check_riskctrl.py
退出码：0 = 全部通过；1 = 存在 FAIL。
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import sys
import tempfile
import threading
import time
import hashlib
from pathlib import Path

RELAY_SRC = Path(__file__).resolve().parent.parent / "relay" / "src"
sys.path.insert(0, str(RELAY_SRC))

PASS: list[str] = []
FAIL: list[str] = []
LOGLINES: list[str] = []


def emit(line: str) -> None:
    LOGLINES.append(line)


def report(ok: bool, name: str, detail: str = "") -> None:
    tag = "PASS" if ok else "FAIL"
    line = f"[{tag}] {name}"
    if detail:
        line += f" :: {detail}"
    emit(line)
    (PASS if ok else FAIL).append(name)


def check(cond: bool, name: str, detail: str = "") -> None:
    report(bool(cond), name, detail if not cond else "")


class LogCapture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


def make_env() -> tuple[Path, str, str, str]:
    """构造临时部署目录（token.txt + accounts.json + .env），返回 (目录, TOK1, TOK2, DEID)。"""
    tmp = Path(tempfile.mkdtemp(prefix="p1b_check_"))
    tok1 = "tok-real-account-aaaaaaaaaaaaaaaaaaaaaa"
    tok2 = "tok-plain-account-bbbbbbbbbbbbbbbbbbbbbb"
    deid = "deid1234567890abcdef1234"
    (tmp / "token.txt").write_text(f"{tok1}\n{tok2}\n__glm_guest__\n", encoding="utf-8")
    fp = hashlib.sha256(tok1.encode()).hexdigest()[:16]
    (tmp / "accounts.json").write_text(
        json.dumps({"version": 1, "accounts": {fp: {"fingerprint": fp, "device_id": deid, "label": "check"}}}),
        encoding="utf-8",
    )
    return tmp, tok1, tok2, deid


# --------------------------------------------------------------- D4

def check_d4(mgr) -> None:
    headers = mgr.get_browser_headers()
    check("X-Forwarded-For" not in headers, "D4-a get_browser_headers 不含 X-Forwarded-For")
    hits = []
    for path in (RELAY_SRC / "glm2api").rglob("*.py"):
        if "X-Forwarded-For" in path.read_text(encoding="utf-8", errors="replace"):
            hits.append(str(path))
    check(not hits, "D4-b src/ 源码零 X-Forwarded-For 命中", ", ".join(hits))


# --------------------------------------------------------------- D1

def check_d1(tmp: Path, deid: str) -> None:
    import glmrelay  # noqa: F401  导入即安装 device_id 钩子（模拟 server.py 行为）
    from glm2api.config import load_config
    from glm2api.services.glm_auth import GLMAccessTokenManager
    from glmrelay.accounts.registry import resolve_device_id

    logs = LogCapture()
    logging.getLogger().addHandler(logs)
    logger = logging.getLogger("check_d1")

    cfg = load_config(str(tmp / ".env"))
    mgr = GLMAccessTokenManager(cfg, logger)

    # ① 真实 deid 接线
    check(mgr.get_device_id_for_account(0) == deid, "D1-① 导入账号使用真实 chatglm-deid",
          f"实际={mgr.get_device_id_for_account(0)[:12]}")
    # ② 连续 20 次请求后 device_id 不变（旧实现第 8 次必变）
    first = mgr.get_device_id_for_account(0)
    for _ in range(20):
        mgr.next_request_id_for_account(0)
    check(mgr.get_device_id_for_account(0) == first, "D1-② 连续 20 次请求 device_id 不变")
    # ③ 无 deid 账号 → 非空且进程内稳定
    d2 = mgr.get_device_id_for_account(1)
    check(bool(d2) and mgr.get_device_id_for_account(1) == d2, "D1-③ 无 deid 账号 → 稳定随机值")
    # ④ 游客槽 → 非空稳定，请求多次仍不变
    d3 = mgr.get_device_id_for_account(2)
    for _ in range(10):
        mgr.next_request_id_for_account(2)
    check(bool(d3) and mgr.get_device_id_for_account(2) == d3, "D1-④ 游客槽 device_id 非空稳定")
    # ⑤ 日志无主动轮换；初始化统计真实身份 1/2
    check(not any("主动轮换 device_id" in m for m in logs.messages), "D1-⑤a 无『主动轮换 device_id』日志")
    check(any("真实设备身份=1/2" in m for m in logs.messages), "D1-⑤b 初始化统计真实设备身份 1/2")
    # 热更新：accounts.json 变化后免重启生效
    tok3 = "tok-new-import-cccccccccccccccccccccc"
    fp3 = hashlib.sha256(tok3.encode()).hexdigest()[:16]
    meta_path = tmp / "accounts.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    meta["accounts"][fp3] = {"fingerprint": fp3, "device_id": "deidNEW888"}
    meta_path.write_text(json.dumps(meta), encoding="utf-8")
    check(resolve_device_id(tok3) == "deidNEW888", "D1-附1 accounts.json 热更新（导入后免重启）")
    # 钩子缺省时回退稳定随机
    saved = GLMAccessTokenManager.device_id_resolver
    GLMAccessTokenManager.device_id_resolver = None
    try:
        mgr2 = GLMAccessTokenManager(load_config(str(tmp / ".env")), logger)
        got = mgr2.get_device_id_for_account(0)
        check(bool(got) and got != deid, "D1-附2 无钩子时回退稳定随机值")
    finally:
        GLMAccessTokenManager.device_id_resolver = saved
    return mgr


# --------------------------------------------------------------- D3

def check_d3(tmp: Path) -> None:
    from glm2api.config import load_config
    from glm2api.services.glm_client import GLMWebClient, UpstreamAPIError

    logger = logging.getLogger("check_d3")
    cfg = load_config(str(tmp / ".env"))
    cfg.glm_request_jitter_ms = 0
    cfg.glm_guest_stagger_seconds = 0
    client = GLMWebClient(cfg, logger)
    client.auth.get_access_token_for_account = lambda i: f"fake-token-{i}"  # 单测不打真网

    # S1 单身份单飞：并发同一起始账号 → 落不同账号、无重叠
    inflight: dict[int, str] = {}
    order: list[tuple[str, int]] = []
    lock = threading.Lock()

    def op_factory(tag: str, dur: float):
        def op(account_index: int, access_token: str):
            with lock:
                assert account_index not in inflight, f"account {account_index} 并发重叠"
                inflight[account_index] = tag
                order.append(("enter", account_index))
            time.sleep(dur)
            with lock:
                del inflight[account_index]
                order.append(("exit", account_index))
            return tag
        return op

    t1 = threading.Thread(target=lambda: client._call_with_account_failover("req1", op_factory("r1", 0.3), preferred_account_index=0))
    t2 = threading.Thread(target=lambda: client._call_with_account_failover("req2", op_factory("r2", 0.0), preferred_account_index=0))
    t1.start(); time.sleep(0.05); t2.start(); t1.join(); t2.join()
    enters = [i for a, i in order if a == "enter"]
    check(enters == [0, 1], "S1 单身份单飞：并发同起始账号 → 落 0/1 无重叠", f"落点={enters}")

    # S2 全忙（全部账号锁占满）→ 整体等待后成功，无死锁
    acquired = [threading.Event() for _ in range(client.auth.get_account_count())]

    def long_op_factory(ev: threading.Event):
        def op(i: int, tk: str):
            ev.set()
            time.sleep(0.6)
            return "long"
        return op

    busy_threads = []
    for slot in range(client.auth.get_account_count()):
        th = threading.Thread(
            target=lambda slot=slot: client._call_with_account_failover(
                f"busy{slot}", long_op_factory(acquired[slot]), preferred_account_index=slot
            )
        )
        busy_threads.append(th)
        th.start()
    for ev in acquired:
        check(ev.wait(timeout=3), "S2-pre 占满线程全部拿到账号锁")
    cfg.glm_busy_retry_interval = 0.1
    t0 = time.monotonic()
    result = client._call_with_account_failover("req5", lambda i, tk: ("ok", i))
    elapsed = time.monotonic() - t0
    for th in busy_threads:
        th.join()
    check(result[0] == "ok" and elapsed >= 0.4, "S2 全忙 → 等待后成功无死锁", f"{result} {elapsed:.2f}s")

    # S3 403 三连 → 冷却 + 安全阀轮换 + 日志
    dev_before = client.auth.get_device_id_for_account(0)
    exc403 = UpstreamAPIError(403, "forbidden")
    for _ in range(3):
        client.auth.register_risk_event(0, exc403)
    check(client.auth.is_account_cooling_down(0), "S3-a 403 三连 → 进入冷却")
    check(client.auth.get_device_id_for_account(0) != dev_before, "S3-b 冷却触发安全阀轮换 device_id")

    # S4 冷却账号被 failover 跳过
    seen: list[int] = []
    client._call_with_account_failover("skip", lambda i, tk: seen.append(i) or "ok", preferred_account_index=0)
    check(seen == [1], "S4 冷却账号被跳过 → 落健康账号", f"落点={seen}")

    # S5 全冷却 → 显式 429，不硬打上游
    for slot in range(client.auth.get_account_count()):
        for _ in range(3):
            client.auth.register_risk_event(slot, exc403)
        check(client.auth.is_account_cooling_down(slot), f"S5-pre 账号 {slot} 已冷却")
    raised: Exception | None = None
    try:
        client._call_with_account_failover("allcool", lambda i, tk: "never")
    except UpstreamAPIError as exc:
        raised = exc
    check(raised is not None and "冷却" in str(raised), "S5 全冷却 → 显式 UpstreamAPIError(429)", str(raised))
    for i in range(client.auth.get_account_count()):
        client.auth._accounts[i].cooldown_until = 0.0

    # S6 风控分类：busy 10061 豁免；真限流 429 / 403 / 405 计入；500 不计入；
    # 401 按 P0-1 收紧 —— 无权威 body 标记不计风控，带标记才计。
    busy = UpstreamAPIError(429, "x | status=10061 | 请等待其他对话生成完毕", {"status": 10061, "message": "请等待其他对话生成完毕"})
    cases = [
        (busy, False, "busy 10061 豁免"),
        (UpstreamAPIError(429, "too many", {"message": "too many"}), True, "真限流 429 计入"),
        (UpstreamAPIError(401, "f", {}), False, "401 无权威标记不计风控（P0-1 收紧）"),
        (UpstreamAPIError(401, "token 已失效", {"code": 401, "message": "token 已失效"}), True, "401 带权威失效标记计入（P0-1）"),
        (UpstreamAPIError(403, "f", {}), True, "403 计入"),
        (UpstreamAPIError(405, "f", {}), True, "405 计入"),
        (UpstreamAPIError(500, "f", {}), False, "500 不计入"),
    ]
    for exc, want, name in cases:
        got = client.auth.classify_risk_event(exc)
        check(got == want, f"S6 {name}", f"期望 {want} 实际 {got}")

    # S7 退避公式 min(60, 2^n) + 抖动
    check(1.0 <= client.auth.next_risk_backoff(0) <= 1.5, "S7-a attempt0 退避 ∈ [1, 1.5]")
    check(60.0 <= client.auth.next_risk_backoff(6) <= 90.0, "S7-b attempt6 退避 ∈ [60, 90]")

    # S8 游客错峰：首次随机延迟一次，之后为零
    gc = load_config(str(tmp / ".env"))
    gc.glm_refresh_tokens = ["__glm_guest__"]
    gc.glm_request_jitter_ms = 0
    gc.glm_guest_stagger_seconds = 1.0
    gclient = GLMWebClient(gc, logger)
    t0 = time.monotonic(); gclient.auth.apply_guest_stagger(0); d1 = time.monotonic() - t0
    t0 = time.monotonic(); gclient.auth.apply_guest_stagger(0); d2 = time.monotonic() - t0
    check(0 < d1 <= 1.2 and d2 < 0.05, "S8 游客错峰仅首次延迟", f"first={d1:.2f}s second={d2:.3f}s")

    # S9 抖动可关闭：jitter=0 时 pacing 零延迟
    cfg.glm_request_jitter_ms = 0
    t0 = time.monotonic(); client._apply_request_pacing(0); took = time.monotonic() - t0
    check(took < 0.05, "S9 抖动=0 时零延迟（可关闭性）", f"{took:.3f}s")


# --------------------------------------------------------------- P1-b 配额/熔断/探活

def check_runtime(tmp: Path) -> None:
    from glm2api.config import load_config
    from glm2api.services.glm_auth import GLMAccessTokenManager

    logger = logging.getLogger("check_runtime")
    cfg = load_config(str(tmp / ".env"))
    mgr = GLMAccessTokenManager(cfg, logger)
    GLMAccessTokenManager.last_instance = mgr

    # R1 配额统计：请求/成功/失败计数与成功率
    mgr.record_request(0); mgr.record_result(0, True)
    mgr.record_request(0); mgr.record_result(0, True)
    mgr.record_request(0); mgr.record_result(0, False, "boom")
    row = mgr.get_account_stats()[0]
    check(
        row["total_requests"] == 3 and row["total_failures"] == 1 and row["success_rate"] == round(2 / 3, 4),
        "R1 配额统计：请求数/失败数/成功率",
        str(row),
    )
    check(row["consecutive_failures"] == 1 and row["last_error"] == "boom", "R1-b 失败计数与 last_error")

    # R2 成功重置连续失败
    mgr.record_result(0, True)
    check(mgr.get_account_stats()[0]["consecutive_failures"] == 0, "R2 一次成功清零连续失败")

    # R3 连续 3 次失败 → 熔断摘除 + failover 跳过
    for _ in range(3):
        mgr.record_request(1); mgr.record_result(1, False, "down")
    check(mgr.is_account_breaked(1) and not mgr.is_account_cooling_down(1), "R3-a 连续失败 3 次 → 熔断（非风控冷却）")
    check(not mgr.is_account_available(1), "R3-b 熔断账号对 failover 不可用")
    check(mgr.get_account_stats()[1]["breaked"] is True, "R3-c stats 视图含 breaked 标记")
    for i in range(mgr.get_account_count()):
        mgr._accounts[i].breaker_until = 0.0
        mgr._accounts[i].cooldown_until = 0.0

    # R4 半开：breaker_until 过期后 failover 恢复使用
    check(mgr.is_account_available(1), "R4 熔断到期后半开恢复（failover 可重新选它）")

    # R5 探活：缓存命中零上游请求；失败计数与摘除
    # mock 必须走 seam 注入 —— transport 的 _open 在 import 时绑定 urlopen 引用，
    # patch urllib.request.urlopen 拦不到 seam 调用（探活会真实打到上游）。
    from glm2api.core import transport
    from glm2api.services.glm_auth import AccessToken
    from glmrelay.accounts.health import probe_once
    probe_calls = {"n": 0}
    real_urlopen = transport._open

    def counting_opener(request, timeout=None):
        probe_calls["n"] += 1
        raise RuntimeError("network disabled in test")

    transport.set_upstream_transport(counting_opener)
    try:
        # 有效缓存 → 探活零上游请求
        for i in range(mgr.get_account_count()):
            mgr._accounts[i].cached_token = AccessToken(access_token="t", refresh_token="r", expires_at=time.time() + 3000)
            mgr._accounts[i].breaker_until = 0.0
            mgr._accounts[i].probe_failures = 0
        n_before = probe_calls["n"]
        probed = probe_once(logging.getLogger("probe"))
        check(probe_calls["n"] == n_before, "R5-a 缓存命中账号探活零上游请求", f"{n_before}->{probe_calls['n']}")
        check(probed == mgr.get_account_count(), "R5-b probe_once 返回探活账号数", f"probed={probed}")
        # 无缓存 → 探活打上游（mock 失败）；连续 3 轮失败 → 全部熔断摘除
        for i in range(mgr.get_account_count()):
            mgr._accounts[i].cached_token = None
        for _ in range(3):
            probe_once(logging.getLogger("probe"))
        stats = mgr.get_account_stats()
        check(
            all(s["breaked"] for s in stats) and all("network disabled" in s["last_error"] for s in stats),
            "R5-c 探活连续失败 3 轮 → 全部熔断摘除且记录 last_error",
            str([(s["index"], s["breaked"]) for s in stats]),
        )
    finally:
        transport.set_upstream_transport(None)
        GLMAccessTokenManager.last_instance = None

    # R6 探活可关闭：GLM_HEALTH_PROBE_SECONDS=0 时不启动线程
    import threading
    cfg.glm_health_probe_seconds = 0
    from glmrelay.accounts.health import ensure_health_probe, _started as _probe_started_flag
    import glmrelay.accounts.health as health_mod
    prev_started = health_mod._started
    try:
        health_mod._started = False
        launched = ensure_health_probe(cfg, logging.getLogger("probe"))
        check(launched is False, "R6 探活间隔=0 时不启动线程")
    finally:
        health_mod._started = prev_started


# --------------------------------------------------------------- P2 工具契约

def check_p2(tmp: Path) -> None:
    from glm2api.services.translator import convert_messages
    from glm2api.utils.tool_parser import _is_allowed_tool_name

    # B1 客户端声明的撞名工具放行（7.3：黑名单改为按名字 + 来源匹配）
    check(
        _is_allowed_tool_name("web_search", {"web_search"}) is True,
        "B1 客户端声明的 web_search → 解析放行",
    )
    check(
        _is_allowed_tool_name("web_search", {"other_tool"}) is False,
        "B2 客户端未声明 → 上游原生名单仍拒（防模型幻觉）",
    )
    check(
        _is_allowed_tool_name("get_weather", None) is True,
        "B3 无声明约束时普通工具名放行",
    )

    # B4 注入过滤：撞名工具不再被 NATIVE 名单剔除（仅 env 黑名单生效）
    from glm2api.utils.tool_protocol import filter_tools

    tools = [{"type": "function", "function": {"name": "web_search", "parameters": {}}}]
    kept = filter_tools(tools, set())  # NATIVE 名单不再传入
    check(kept is not None and len(kept) == 1, "B4 撞名客户端工具不再被注入过滤剔除")
    kept2 = filter_tools(tools, {"web_search"})
    check(kept2 is None, "B4-b 环境变量黑名单仍无条件剔除")

    # B5 tool_call_id 不匹配 → 显式 ValueError（400 invalid_request）
    msgs_mismatch = [
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "call_abc", "type": "function", "function": {"name": "t", "arguments": "{}"}}
        ]},
        {"role": "tool", "tool_call_id": "call_XXX", "content": "结果"},
    ]
    raised = None
    try:
        convert_messages(msgs_mismatch, None)
    except ValueError as exc:
        raised = exc
    check(raised is not None and "tool_call_id" in str(raised), "B5 id 不匹配 → 显式报错（不再静默丢弃）", str(raised))

    # B6 repaired id 的结果照常回灌（不再静默丢失）
    msgs_repaired = [
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "call_repaired_1", "type": "function", "function": {"name": "t", "arguments": "{}"}, "_repaired": True}
        ]},
        {"role": "tool", "tool_call_id": "call_repaired_1", "content": "修复路径结果"},
    ]
    try:
        converted = convert_messages(msgs_repaired, None)
        flat = json.dumps(converted, ensure_ascii=False)
        check("修复路径结果" in flat, "B6 repaired id 结果回灌不丢失")
    except ValueError as exc:
        check(False, "B6 repaired id 结果回灌不丢失", f"误报错: {exc}")

    # B7 仅发 tool 结果（无 assistant tool_calls 前文）→ 短路通过（兼容保留）
    converted7 = convert_messages([{"role": "tool", "tool_call_id": "call_orphan", "content": "孤儿结果"}], None)
    flat7 = json.dumps(converted7, ensure_ascii=False)
    check("孤儿结果" in flat7, "B7 无前文时 tool 结果短路通过")

    # ── C 组：工具结果体积治理（7.5.2）+ 不可信输入包裹（7.5.4）──
    from glm2api.utils.tool_protocol import (
        TOOL_RESULT_END_MARKER,
        TOOL_RESULT_TRUST_NOTICE,
        serialize_tool_result_block,
        truncate_tool_result,
    )

    # C1 声明壳：信任声明前缀 + 结束标记
    normal = serialize_tool_result_block("call_1", "fetch", "正常长度结果")
    check(
        normal.startswith(TOOL_RESULT_TRUST_NOTICE) and normal.endswith(TOOL_RESULT_END_MARKER),
        "C1 工具结果带信任声明前缀与结束标记",
    )

    # C2 正常长度不截断
    check("正常长度结果" in normal and "已截断" not in normal, "C2 未超限内容原样保留")

    # C3 超长截断：保留首尾、注明原始长度、总长受控
    big = "A" * 5000 + "MIDDLE" + "B" * 5000
    truncated = serialize_tool_result_block("call_2", "fetch", big, max_chars=1000)
    check(
        "原始 10006 字符" in truncated and truncated.startswith(TOOL_RESULT_TRUST_NOTICE),
        "C3-a 超长结果截断并注明原始长度",
    )
    check("A" in truncated and "B" in truncated and "MIDDLE" not in truncated, "C3-b 保留首尾丢弃中段")
    body_len = truncated.index(TOOL_RESULT_END_MARKER) - truncated.index("<|DSML|tool_result")
    check(
        body_len < 2000,
        "C3-c 截断后结果块长度受控",
        f"body≈{body_len}",
    )

    # C4 关闭开关：max_chars=0 不截断
    unbounded = serialize_tool_result_block("call_3", "fetch", big, max_chars=0)
    check("MIDDLE" in unbounded and "已截断" not in unbounded, "C4 max_chars=0 时不截断（可关闭性）")

    # C5 CDATA 转义在截断前后都工作
    cdata_break = serialize_tool_result_block("call_4", "t", "x]]>y", max_chars=None)
    check("]]]]><![CDATA[>" in cdata_break, "C5 CDATA 闭合序列转义仍工作")

    # C6 端到端：convert_messages 传 max_chars → 拍平消息含截断标记
    msgs_big = [
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "call_big", "type": "function", "function": {"name": "fetch", "arguments": "{}"}}
        ]},
        {"role": "tool", "tool_call_id": "call_big", "content": big},
    ]
    converted_c = convert_messages(msgs_big, None, tool_result_max_chars=1000)
    flat_c = json.dumps(converted_c, ensure_ascii=False)
    check(
        "原始 10006 字符" in flat_c and TOOL_RESULT_TRUST_NOTICE[:12] in flat_c,
        "C6 端到端：截断与信任声明进入拍平消息",
    )


# --------------------------------------------------------------- P2 用例 #6：DSML 写入 content 的抢救

# 12.6 失败样本两族（artifacts/fail_samples/fail_2-6），原样内嵌作为回归基准
MALFORMED_FAMILY_A = (
    '<DStool_calls>\n  <|DSML|invoke name="getML|parameter|DSML|tool_calls>\n'
    '  <|DSML|invoke name="get_weather">\n    <|DSML|parameter name="city"><![CDATA[上海]]></|DSML|parameter>\n'
    '  </|DSML|invoke>\n</|DSML|tool_calls>'
)
MALFORMED_FAMILY_B = (
    '<DStool_calls>\n  <|DSML|invoke namer name="city>name="get_weather">\n'
    '    <|DSML|parameter name="city"><![CDATA[上海]]></|DSML|parameter>\n'
    '  </|DSML|invoke>\n</|DSML|tool_calls>'
)


def _is_rescued_weather_call(calls) -> bool:
    return (
        len(calls) == 1
        and calls[0]["function"]["name"] == "get_weather"
        and calls[0]["function"]["arguments"] == '{"city":"上海"}'
    )


def check_p6(tmp: Path) -> None:
    from glm2api.utils.tool_parser import StreamingToolParser, parse_tool_calls_from_text

    # M1/M2 两族样本非流式：产出工具调用 + 可见文本零标记泄漏
    for tag, sample in (("A", MALFORMED_FAMILY_A), ("B", MALFORMED_FAMILY_B)):
        visible, calls = parse_tool_calls_from_text(sample, {"get_weather"})
        check(_is_rescued_weather_call(calls), f"M{1 if tag == 'A' else 2}-{tag} 畸形样本抢救出 get_weather(city=上海)")
        check(visible == "", f"M{1 if tag == 'A' else 2}-vis{tag} 可见文本零 DSML 残留", repr(visible))

    # M3 搅碎开标签变体归一化（|DStool_calls / DSMLtool_calls）
    for head in ("<|DStool_calls>", "<DSMLtool_calls>"):
        _, calls = parse_tool_calls_from_text(head + MALFORMED_FAMILY_A[len("<DStool_calls>"):], {"get_weather"})
        check(len(calls) == 1, f"M3 变体头 {head} 归一化")

    # M4 流式整帧：样本实测形态（SSE 单 delta 全量 content）
    parser = StreamingToolParser(allowed_tool_names={"get_weather"})
    visible = parser.consume(MALFORMED_FAMILY_A)
    tail, calls = parser.flush()
    check(_is_rescued_weather_call(calls), "M4 流式整帧产出 tool_calls")
    check(not (("<|" in visible + tail) or ("DSt" in visible + tail)), "M4 流式整帧零泄漏", repr(visible + tail))

    # M5 流式逐行帧 + 半截切点（<DSt 半个标记起头）
    parser = StreamingToolParser(allowed_tool_names={"get_weather"})
    for line in MALFORMED_FAMILY_A.splitlines(keepends=True):
        parser.consume(line)
    tail, calls = parser.flush()
    check(_is_rescued_weather_call(calls), "M5-a 流式逐行帧产出 tool_calls")
    parser = StreamingToolParser(allowed_tool_names={"get_weather"})
    check(parser.consume(MALFORMED_FAMILY_A[:4]) == "", "M5-b 半截 <DSt 帧 hold 不泄漏")
    parser.consume(MALFORMED_FAMILY_A[4:])
    tail, calls = parser.flush()
    check(_is_rescued_weather_call(calls), "M5-c 半截切点后续帧产出 tool_calls")

    # M6 抢救命中留痕（失败不可伪装成成功）
    logs = LogCapture()
    parser_logger = logging.getLogger("glm2api.tool_parser")
    parser_logger.addHandler(logs)
    try:
        parse_tool_calls_from_text(MALFORMED_FAMILY_A, {"get_weather"})
    finally:
        parser_logger.removeHandler(logs)
    check(any("抢救归一化" in m for m in logs.messages), "M6 抢救命中输出可观测日志")

    # M7 正常路径回归：完好块照常解析、正文保留、普通文本不受影响
    good_block = (
        '<|DSML|tool_calls>\n  <|DSML|invoke name="get_weather">\n'
        '    <|DSML|parameter name="city"><![CDATA[上海]]></|DSML|parameter>\n'
        '  </|DSML|invoke>\n</|DSML|tool_calls>'
    )
    visible, calls = parse_tool_calls_from_text("前文说明 " + good_block + " 后记", {"get_weather"})
    check(len(calls) == 1, "M7-a 完好块照常解析")
    check("前文说明" in visible and "后记" in visible, "M7-b 完好块前后正文保留", repr(visible))
    plain = '介绍 <DS 结构与 name="a|b" 的写法，纯属正文。'
    visible, calls = parse_tool_calls_from_text(plain, None)
    check(calls == [] and visible == plain, "M7-c 普通正文不被误判", repr(visible))


# --------------------------------------------------------------- P2.6 P0-1 状态码分类

def check_p01(tmp: Path) -> None:
    import urllib.error as ue
    from glm2api.config import load_config
    from glm2api.services.glm_client import GLMWebClient, UpstreamAPIError

    logger = logging.getLogger("check_p01")
    cfg = load_config(str(tmp / ".env"))
    cfg.glm_request_jitter_ms = 0
    cfg.glm_guest_stagger_seconds = 0
    client = GLMWebClient(cfg, logger)
    client.auth.get_access_token_for_account = lambda i: f"fake-token-{i}"
    auth = client.auth
    dev_before = auth.get_device_id_for_account(0)

    # K1 TRANSIENT 状态码不切号（404/409/423/5xx）
    for code in (404, 409, 423, 500, 502, 503):
        check(
            auth.should_switch_account(UpstreamAPIError(code, "x", {})) is False,
            f"K1 HTTP {code} 不切号（TRANSIENT，旧实现一律切号）",
        )
    # K2 网络层错误不切号（切号救不了链路问题）
    check(auth.should_switch_account(ue.URLError("conn refused")) is False, "K2-a URLError 不切号")
    check(auth.should_switch_account(TimeoutError("timed out")) is False, "K2-b TimeoutError 不切号")
    # K3 BUSY / AUTH / RISK 仍切号
    check(
        auth.should_switch_account(UpstreamAPIError(429, "x", {"status": 10061, "message": "请等待其他对话生成完毕"})) is True,
        "K3-a BUSY 仍切号（找空闲身份）",
    )
    check(auth.should_switch_account(UpstreamAPIError(401, "f", {})) is True, "K3-b AUTH 仍切号")
    check(auth.should_switch_account(UpstreamAPIError(403, "f", {})) is True, "K3-c RISK 仍切号")
    # K4 TRANSIENT 不计风控
    check(auth.classify_upstream_error(UpstreamAPIError(404, "x", {})) == "TRANSIENT", "K4-a 404 分类为 TRANSIENT")
    check(auth.classify_risk_event(UpstreamAPIError(404, "x", {})) is False, "K4-b 404 不计风控")
    check(auth.classify_risk_event(UpstreamAPIError(500, "x", {})) is False, "K4-c 500 不计风控")
    # K5 401 权威标记判定
    check(auth.classify_upstream_error(UpstreamAPIError(401, "f", {})) == "AUTH", "K5-a 401 分类为 AUTH")
    check(auth.is_authoritative_auth_failure(UpstreamAPIError(401, "f", {})) is False, "K5-b 401 无标记 → 非权威失效")
    check(auth.classify_risk_event(UpstreamAPIError(401, "f", {})) is False, "K5-c 401 无标记不计风控（不冷却）")
    check(
        auth.is_authoritative_auth_failure(UpstreamAPIError(401, "x", {"code": 401, "message": "x"})) is True,
        "K5-d 401 body code=401 → 权威失效",
    )
    check(
        auth.classify_risk_event(UpstreamAPIError(401, "登录状态失效", {"message": "登录状态失效"})) is True,
        "K5-e 401 失效文案计风控",
    )

    # K6 failover 消费：404 不切号 —— 异常上抛、账号不前进、身份不变、不冷却
    seen: list[int] = []

    def op404(i: int, tk: str):
        seen.append(i)
        raise UpstreamAPIError(404, "not found", {})

    raised: Exception | None = None
    try:
        client._call_with_account_failover("k404", op404, preferred_account_index=0)
    except UpstreamAPIError as exc:
        raised = exc
    check(raised is not None and raised.status_code == 404, "K6-a 404 显式上抛（失败不伪装成成功）", str(raised))
    check(seen == [0], "K6-b 404 只尝试起始账号，不切号", f"seen={seen}")
    check(auth.get_current_account_index() == 0, "K6-c 轮换游标未前进")
    check(auth.get_device_id_for_account(0) == dev_before, "K6-d device_id 未变")
    check(not auth.is_account_cooling_down(0), "K6-e 404 不进风控冷却")

    # K7 failover 消费：401 无权威标记 → 切号继续服务，但不冷却不换身份（走通用熔断）
    def op401_plain(i: int, tk: str):
        if i == 0:
            raise UpstreamAPIError(401, "f", {})
        return ("ok", i)

    result = client._call_with_account_failover("k401", op401_plain, preferred_account_index=0)
    check(result == ("ok", 1), "K7-a 401 切号到下一账号继续服务", str(result))
    check(not auth.is_account_cooling_down(0), "K7-b 401 无标记不进冷却（P0-1 核心）")
    check(auth.get_device_id_for_account(0) == dev_before, "K7-c 401 无标记不换 device_id")

    # K8 401 权威失效标记 → 计风控：三连 → 冷却 + 换身份
    # （先清掉 K6/K7 累积的通用熔断计数，避免熔断先于风控阈值把账号摘出轮换）
    auth._accounts[0].consecutive_failures = 0
    auth._accounts[0].breaker_until = 0.0

    def op401_dead(i: int, tk: str):
        raise UpstreamAPIError(401, "token 已失效", {"code": 401, "message": "token 已失效"})

    for _ in range(3):
        try:
            client._call_with_account_failover("k401dead", op401_dead, preferred_account_index=0)
        except Exception:
            pass
    check(auth.is_account_cooling_down(0), "K8-a 401 权威失效三连 → 冷却")
    check(auth.get_device_id_for_account(0) != dev_before, "K8-b 冷却触发 device_id 安全阀轮换")


def main() -> int:
    os.environ.pop("GLM_TOKEN_FILE", None)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    tmp, _tok1, _tok2, _deid = make_env()
    prev_cwd = os.getcwd()
    try:
        # 模拟服务从部署目录启动：load_config 与 registry 均按 cwd 解析 token/accounts
        os.chdir(tmp)
        from glm2api.config import load_config
        from glm2api.services.glm_auth import GLMAccessTokenManager
        import glmrelay  # noqa: F401

        cfg = load_config(str(tmp / ".env"))
        mgr = GLMAccessTokenManager(cfg, logging.getLogger("check_env"))
        check_d4(mgr)
        check_d1(tmp, _deid)
        check_d3(tmp)
        check_p01(tmp)
        check_runtime(tmp)
        check_p2(tmp)
        check_p6(tmp)
    finally:
        os.chdir(prev_cwd)
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"PASS {len(PASS)} / FAIL {len(FAIL)}", flush=True)
    for name in FAIL:
        print(f"  FAILED: {name}", flush=True)
    out = Path("D:/GLM2api/artifacts/check_riskctrl.txt")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(LOGLINES) + "\n", encoding="utf-8")
    return 0 if not FAIL else 1


if __name__ == "__main__":
    raise SystemExit(main())
