"""P1-b 抗风控改动卡的验收闸门（D1 / D3 / D4 断言集合）。

纯标准库实现，不引入任何依赖；全部断言离线运行（mock 上游 token 获取），
不打真实网络。每个改动项对应一组断言：

    D4  删除 X-Forwarded-For 伪造头          （源码扫描 + 头集合断言）
    D1  真实 deid 接线 + 废除 8 次轮换        （断言 ①-⑤ + 热更新 + 钩子缺省回退）
    D3  并发节奏：单飞/全忙/冷却/分类/退避     （断言 S1-S9）

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

    # S6 风控分类：busy 10061 豁免；真限流 429 / 401 / 403 / 405 计入；500 不计入
    busy = UpstreamAPIError(429, "x | status=10061 | 请等待其他对话生成完毕", {"status": 10061, "message": "请等待其他对话生成完毕"})
    cases = [
        (busy, False, "busy 10061 豁免"),
        (UpstreamAPIError(429, "too many", {"message": "too many"}), True, "真限流 429 计入"),
        (UpstreamAPIError(401, "f", {}), True, "401 计入"),
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
    import urllib.request as _ur
    from glm2api.services.glm_auth import AccessToken
    from glmrelay.accounts.health import probe_once
    probe_calls = {"n": 0}
    real_urlopen = _ur.urlopen

    def counting_urlopen(*a, **kw):
        probe_calls["n"] += 1
        raise RuntimeError("network disabled in test")

    _ur.urlopen = counting_urlopen
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
        _ur.urlopen = real_urlopen
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
        check_runtime(tmp)
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
