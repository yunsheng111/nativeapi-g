"""P1-b 抗风控改动卡的验收闸门（D1 / D3 / D4 断言集合）。

纯标准库实现，不引入任何依赖；全部断言离线运行（mock 上游 token 获取），
不打真实网络。每个改动项对应一组断言：

    D4  删除 X-Forwarded-For 伪造头          （源码扫描 + 头集合断言）
    D1  真实 deid 接线 + 废除 8 次轮换        （断言 ①-⑤ + 热更新 + 钩子缺省回退）
    D3  并发节奏：单飞/全忙/冷却/分类/退避     （断言 S1-S9）
    P2  工具契约修复 + 体积治理/信任壳        （断言 B1-B7 + T3 + C1-C6）
    P2#6 DSML 写入 content 抢救              （断言 M1-M7，12.6 失败样本两族回归）
    P2.6/P0-1 状态码分类 + 401 权威标记       （断言 K1-K8，S6 的 401 用例随语义收紧）
    P2.6/I1  身份字段单一数据源 + 矛盾自检     （断言 I1-a..I1-g，F4 观测性回归）
    B2  token 别名表 + CAS 替换               （断言 A1-a~f：轮换后真实 deid 不断链）
    P3  模式 B 内置工具运行时                 （断言 T1-T5：fs/shell/todo + registry 物理隔离与执行契约）

用法：
    python tools/check_riskctrl.py
退出码：0 = 全部通过；1 = 存在 FAIL。
"""

from __future__ import annotations

import io
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


# --------------------------------------------------------------- B2 token 别名链

def check_alias(tmp: Path, tok1: str, deid: str) -> None:
    """B2（生态调研）：token 别名表 + CAS 替换 —— 上游轮换 refresh_token 重写
    token.txt 后，accounts.json 挂在旧指纹上的真实设备身份不断链。

    前置：check_d1 已为 tok1 写入 deid 条目；glmrelay 已导入（轮换监听器已安装）。
    """
    from glm2api.services.glm_auth import GLMAccessTokenManager
    from glmrelay.accounts.registry import resolve_device_id
    from glmrelay.accounts.store import TokenStore, fingerprint

    store = TokenStore(tmp / "token.txt", tmp / "accounts.json")
    new1 = "tok-rotated-" + "c" * 24
    new2 = "tok-rotated2-" + "d" * 24

    # A1-a 轮换后按新 token 解析出原 device_id（别名继承生效）
    rotated = store.rotate_token_alias(tok1, new1)
    check(
        rotated is not None and resolve_device_id(new1) == deid,
        "A1-a 轮换后 resolve_device_id(新token) 解析出真实 deid",
        f"got={resolve_device_id(new1)!r}",
    )

    # A1-b 条目形态：旧条目挂 rotated_to 指针；新条目继承 device_id
    meta = store.load_meta()
    fp_old, fp_new = fingerprint(tok1), fingerprint(new1)
    check(
        meta.get(fp_old) is not None and meta[fp_old].rotated_to == fp_new,
        "A1-b-a 旧条目 rotated_to 指向新指纹",
    )
    check(
        meta.get(fp_new) is not None and meta[fp_new].device_id == deid,
        "A1-b-b 新条目继承 device_id",
    )

    # A1-c 幂等：同参数重复登记不产生新条目（CAS 命中直接返回已有条目）
    before = set(meta)
    again = store.rotate_token_alias(tok1, new1)
    check(
        again is not None and set(store.load_meta()) == before,
        "A1-c 重复 rotate 幂等（不新增条目）",
    )

    # A1-d 旧条目缺失 → 返回 None（无从继承，调用方自行 record 全新条目）
    orphan = "tok-orphan-" + "e" * 24
    check(store.rotate_token_alias(orphan, new2) is None, "A1-d 旧条目缺失时 rotate 返回 None")

    # A1-e 链上解析：TOK1→NEW→NEW2 连续两轮轮换后仍解析出原 deid
    check(
        store.rotate_token_alias(new1, new2) is not None and resolve_device_id(new2) == deid,
        "A1-e 连续两轮轮换后 resolve_device_id 仍解析出真实 deid",
        f"got={resolve_device_id(new2)!r}",
    )

    # A1-f 底座钩子形态：glmrelay 导入时已安装，且可置 None 恢复（可关闭性）。
    # 不真跑刷新，只断言类属性存在且可置空。
    saved = GLMAccessTokenManager.token_rotation_listener
    try:
        check(saved is not None, "A1-f-a 轮换监听器已由 glmrelay 导入安装")
        GLMAccessTokenManager.token_rotation_listener = None
        check(GLMAccessTokenManager.token_rotation_listener is None, "A1-f-b 监听器可置 None（可关闭性）")
    finally:
        GLMAccessTokenManager.token_rotation_listener = saved


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
    cfg.glm_account_grace_seconds = 0  # 本组测熔断语义本身；宽限语义见 check_p07
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

    # R7 keepalive 批处理（P2.5 第二批 B3）：临期才续命 + 每轮限量 + 摘除账号跳过
    from glmrelay.accounts.health import probe_once as probe_once_r7

    def failing_opener_r7(request, timeout=None):
        probe_calls["n"] += 1
        raise RuntimeError("network disabled in test")

    # R5 的 finally 已把 last_instance 置 None，本组自建 manager
    mgr7 = GLMAccessTokenManager(load_config(str(tmp / ".env")), logging.getLogger("check_r7"))
    GLMAccessTokenManager.last_instance = mgr7
    transport.set_upstream_transport(failing_opener_r7)
    try:
        # 场景 1：全部临期（缓存剩 100s < 300s 阈值），batch_limit=1 → 只有 1 次续命尝试
        for i in range(mgr7.get_account_count()):
            mgr7._accounts[i].cached_token = AccessToken(access_token="t", refresh_token="r", expires_at=time.time() + 100)
            mgr7._accounts[i].breaker_until = 0.0
            mgr7._accounts[i].probe_failures = 0
        n0 = probe_calls["n"]
        probed = probe_once_r7(logging.getLogger("probe"), batch_limit=1)
        check(probe_calls["n"] - n0 == 1, "R7-a 临期账号 keepalive 每轮限量 1 次续命尝试（失败也占名额）", f"{probe_calls['n'] - n0}")
        # index0 强制续命失败不计数；index1 名额用尽；index2 游客缓存命中零成本确认 → 仅 1
        check(probed == 1, "R7-b 续命失败不计数、游客缓存命中零成本确认", f"probed={probed}")
        # 场景 2：摘除中的账号跳过，不占名额也不打上游（不限量时其余账号全量探）
        for i in range(mgr7.get_account_count()):
            mgr7._accounts[i].cached_token = None
        mgr7._accounts[0].breaker_until = time.time() + 600
        mgr7._accounts[0].probe_failures = 0
        n1 = probe_calls["n"]
        probe_once_r7(logging.getLogger("probe"), batch_limit=0)
        check(probe_calls["n"] - n1 == mgr7.get_account_count() - 1, "R7-c 摘除中账号探活跳过不打上游", f"{probe_calls['n'] - n1}")
        # 场景 3：缓存健康的账号零成本确认且不占批量名额
        for i in range(mgr7.get_account_count()):
            mgr7._accounts[i].cached_token = AccessToken(access_token="t", refresh_token="r", expires_at=time.time() + 3000)
            mgr7._accounts[i].breaker_until = 0.0
            mgr7._accounts[i].probe_failures = 0
        n2 = probe_calls["n"]
        probed = probe_once_r7(logging.getLogger("probe"), batch_limit=1)
        check(probe_calls["n"] == n2, "R7-d 缓存健康账号零成本确认不占批量名额", f"{probe_calls['n'] - n2}")
        check(probed == mgr7.get_account_count(), "R7-e 零成本确认计入健康账号数", f"probed={probed}")
    finally:
        transport.set_upstream_transport(None)
        GLMAccessTokenManager.last_instance = None


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


def check_streamguard() -> None:
    """P2 收尾小批：标记前置截断（事前防线，对照 chatgpt2api streamable_text）。"""
    from glm2api.utils.tool_parser import StreamingToolParser, parse_tool_calls_from_text

    # 抢救层覆盖之外的搅碎变体（双 t <DSttool_calls>，12.10 有意不做无限泛化）
    corrupted = '天气预报如下 <DSttool_calls>invoke namer name="get_weather">'

    # SG-a 非流式：无法恢复的搅碎标记及其后内容零下发（截断在标记前，正文保留）
    visible, calls = parse_tool_calls_from_text(corrupted, {"get_weather"})
    check(visible == "天气预报如下 ", "SG-a 无法恢复的搅碎标记被前置截断", repr(visible))

    # SG-b 流式逐 delta：标记出现即截断并锁定，后续 delta 一律不再下发
    parser = StreamingToolParser(allowed_tool_names={"get_weather"})
    out1 = parser.consume("今天天气不错。")
    out2 = parser.consume(" <DSttool_calls>垃圾内容")
    out3 = parser.consume("更多污染文本")
    check(out1 == "今天天气不错。", "SG-b-a 标记前的正文正常下发", repr(out1))
    check(out2 == " " and out3 == "", "SG-b-b 标记出现即截断且锁定后续 delta", repr(out2 + "|" + out3))
    tail, _calls = parser.flush()
    check(tail == "", "SG-b-c 锁定后 flush 不再下发可见文本", repr(tail))

    # SG-c 代码围栏内的 DSML 字面量是合法展示内容（用户让模型解释协议格式），
    # 不触发防线 —— 与 _mask_code_fences 的提取遮蔽同一立场
    fenced = '格式说明：\n```\n<|DSML|tool_calls>示例\n```\n完毕。'
    visible, calls = parse_tool_calls_from_text(fenced, None)
    check(calls == [] and visible == fenced, "SG-c 围栏内字面量不误伤", repr(visible))

    # SG-d 完好块回归：事前防线不影响正常工具桥（M7 同型复验）
    good_block = (
        '<|DSML|tool_calls>\n  <|DSML|invoke name="get_weather">\n'
        '    <|DSML|parameter name="city"><![CDATA[上海]]></|DSML|parameter>\n'
        "  </|DSML|invoke>\n</|DSML|tool_calls>"
    )
    visible, calls = parse_tool_calls_from_text("前文 " + good_block + " 后记", {"get_weather"})
    check(len(calls) == 1 and "前文" in visible and "后记" in visible, "SG-d 完好块路径回归不受影响")

    # SG-e 防线触发留痕（失败不可伪装成成功）
    logs = LogCapture()
    parser_logger = logging.getLogger("glm2api.tool_parser")
    parser_logger.addHandler(logs)
    try:
        parse_tool_calls_from_text(corrupted, {"get_weather"})
    finally:
        parser_logger.removeHandler(logs)
    check(any("前置截断" in m for m in logs.messages), "SG-e 防线触发输出可观测日志")


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


# --------------------------------------------------------------- P2.6 P0-2 Retry-After

def check_p02(tmp: Path) -> None:
    import urllib.error as ue
    from glm2api.config import load_config
    from glm2api.services.glm_client import GLMWebClient, UpstreamAPIError
    from glm2api.services.glm_auth import RETRY_AFTER_MAX_SECONDS

    logger = logging.getLogger("check_p02")
    cfg = load_config(str(tmp / ".env"))
    client = GLMWebClient(cfg, logger)
    auth = client.auth

    # RA1 HTTP 头形态：纯秒数；0 必须存活（不得被 falsy 吞掉）
    check(auth.parse_retry_after(UpstreamAPIError(429, "x", {}, {"Retry-After": "0"})) == 0.0, "RA1-a Retry-After: 0 → 0.0（is not None 语义）")
    check(auth.parse_retry_after(UpstreamAPIError(429, "x", {}, {"Retry-After": "120"})) == 120.0, "RA1-b Retry-After: 120 → 120s")
    # RA2 中文文案形态（本项目上游是中文站，直接对口）
    check(auth.parse_retry_after(UpstreamAPIError(429, "请 5 分钟 后重试", {})) == 300.0, "RA2-a 『5 分钟』→ 300s")
    check(auth.parse_retry_after(UpstreamAPIError(429, "请等待 30秒 后重试", {})) == 30.0, "RA2-b 『30秒』→ 30s")
    check(auth.parse_retry_after(UpstreamAPIError(429, "冷却 1小时30分钟", {})) == 5400.0, "RA2-c 『1小时30分钟』叠加 → 5400s")
    # RA3 英文文案形态（对照 gptGrok B pool.go 双语正则）
    check(auth.parse_retry_after(UpstreamAPIError(429, "retry after 2 minutes", {})) == 120.0, "RA3-a 『2 minutes』→ 120s")
    check(auth.parse_retry_after(UpstreamAPIError(429, "come back in 30s", {})) == 30.0, "RA3-b 『30s』→ 30s")
    check(auth.parse_retry_after(ue.HTTPError("u", 429, "wait 5 minutes", {"Content-Type": "text/plain"}, io.BytesIO(b""))) == 300.0, "RA3-c 裸 HTTPError 无头 → 文案 300s")
    # RA4 无信息 → None（走原指数退避）
    check(auth.parse_retry_after(UpstreamAPIError(429, "too many", {})) is None, "RA4-a 无头无文案 → None")
    check(auth.parse_retry_after(RuntimeError("普通错误")) is None, "RA4-b 普通异常 → None")
    # RA5 退避合并：0 → 立即重试；大值取大；无值原公式
    check(auth.next_risk_backoff(0, 0.0) == 0.0, "RA5-a retry_after=0 → 立即重试")
    check(auth.next_risk_backoff(0, 300.0) == 300.0, "RA5-b max(指数, 300) → 300s")
    got = auth.next_risk_backoff(6)
    check(60.0 <= got <= 90.0, "RA5-c 无 Retry-After → 原指数公式不变", f"{got}")
    check(auth.next_risk_backoff(6, 7200.0) == RETRY_AFTER_MAX_SECONDS, "RA5-d 超限裁剪到上限", f"{RETRY_AFTER_MAX_SECONDS}")
    # RA6 端到端：payload 携带 retry_after 字段也可解析
    check(auth.parse_retry_after(UpstreamAPIError(429, "x", {"retry_after": 45})) == 45.0, "RA6 payload retry_after 字段")


# --------------------------------------------------------------- P2.6 P0-3 信任壳去累积

def check_p03(tmp: Path) -> None:
    from glm2api.services.translator import convert_messages
    from glm2api.utils.tool_protocol import (
        TOOL_RESULT_END_MARKER,
        TOOL_RESULT_TRUST_NOTICE,
        serialize_tool_result_block,
    )

    def assistant_tc(call_id: str):
        return {"role": "assistant", "content": "", "tool_calls": [
            {"id": call_id, "type": "function", "function": {"name": "t", "arguments": "{}"}}
        ]}

    # P03-1 三轮工具对话：只有当轮（尾部未回应）结果带壳，历史结果剥壳
    msgs3 = [
        {"role": "user", "content": "问1"},
        assistant_tc("call_r1"),
        {"role": "tool", "tool_call_id": "call_r1", "content": "第一轮结果"},
        {"role": "assistant", "content": "答1"},
        {"role": "user", "content": "问2"},
        assistant_tc("call_r2"),
        {"role": "tool", "tool_call_id": "call_r2", "content": "第二轮结果"},
        {"role": "assistant", "content": "答2"},
        {"role": "user", "content": "问3"},
        assistant_tc("call_r3"),
        {"role": "tool", "tool_call_id": "call_r3", "content": "第三轮结果"},
    ]
    flat3 = json.dumps(convert_messages(msgs3, None), ensure_ascii=False)
    check(
        flat3.count(TOOL_RESULT_TRUST_NOTICE) == 1,
        "P03-1a 三轮工具对话后声明仅 1 份（旧实现 3 份）",
        f"出现 {flat3.count(TOOL_RESULT_TRUST_NOTICE)} 次",
    )
    check(
        "第一轮结果" in flat3 and "第二轮结果" in flat3 and "第三轮结果" in flat3,
        "P03-1b 历史结果内容剥壳不剥内容",
    )

    # P03-2 真同轮双工具（一条 assistant 两个 tool_calls + 两条结果）都带壳
    msgs2 = [
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "call_a", "type": "function", "function": {"name": "t", "arguments": "{}"}},
            {"id": "call_b", "type": "function", "function": {"name": "t", "arguments": "{}"}},
        ]},
        {"role": "tool", "tool_call_id": "call_a", "content": "A 结果"},
        {"role": "tool", "tool_call_id": "call_b", "content": "B 结果"},
    ]
    flat2 = json.dumps(convert_messages(msgs2, None), ensure_ascii=False)
    check(flat2.count(TOOL_RESULT_TRUST_NOTICE) == 2, "P03-2 同轮双工具结果都带壳", f"出现 {flat2.count(TOOL_RESULT_TRUST_NOTICE)} 次")

    # P03-2b 链式两轮（轮 1 已被轮 2 的 tool_calls 消费）→ 只有当轮带壳
    chain = [
        assistant_tc("call_c1"),
        {"role": "tool", "tool_call_id": "call_c1", "content": "链式第一轮"},
        assistant_tc("call_c2"),
        {"role": "tool", "tool_call_id": "call_c2", "content": "链式第二轮"},
    ]
    flat_chain = json.dumps(convert_messages(chain, None), ensure_ascii=False)
    check(
        flat_chain.count(TOOL_RESULT_TRUST_NOTICE) == 1 and "链式第一轮" in flat_chain,
        "P03-2b 链式调用仅末轮带壳、历史内容保留",
        f"出现 {flat_chain.count(TOOL_RESULT_TRUST_NOTICE)} 次",
    )

    # P03-3 回显内容内嵌声明/结束标记 → 剥离后只保留中转补的真壳
    echoed = (
        f"{TOOL_RESULT_TRUST_NOTICE}\n"
        '<|DSML|tool_result call_id="call_e" name="t"><content><![CDATA[回显内容]]></content></|DSML|tool_result>\n'
        f"{TOOL_RESULT_END_MARKER}"
    )
    msgs_e = [assistant_tc("call_e"), {"role": "tool", "tool_call_id": "call_e", "content": echoed}]
    flat_e = json.dumps(convert_messages(msgs_e, None), ensure_ascii=False)
    check(
        flat_e.count(TOOL_RESULT_TRUST_NOTICE) == 1 and flat_e.count(TOOL_RESULT_END_MARKER) == 1,
        "P03-3 回显壳剥离、真壳唯一（防伪造收尾 + 去累积）",
        f"notice={flat_e.count(TOOL_RESULT_TRUST_NOTICE)} end={flat_e.count(TOOL_RESULT_END_MARKER)}",
    )
    check("回显内容" in flat_e, "P03-3b 回显数据内容保留")

    # P03-4 wrap_notice=False 直接序列化：裸块无声明
    bare = serialize_tool_result_block("call_b", "t", "裸块内容", wrap_notice=False)
    check(
        TOOL_RESULT_TRUST_NOTICE not in bare and "裸块内容" in bare and bare.startswith("<|DSML|tool_result"),
        "P03-4 wrap_notice=False → 裸 DSML 块",
    )

    # P03-5 当轮结果截断与单份声明共存（对齐 C3 语义）
    big = "A" * 5000 + "MIDDLE" + "B" * 5000
    msgs_big = [assistant_tc("call_big"), {"role": "tool", "tool_call_id": "call_big", "content": big}]
    flat_big = json.dumps(convert_messages(msgs_big, None, tool_result_max_chars=1000), ensure_ascii=False)
    check(
        "原始 10006 字符" in flat_big and flat_big.count(TOOL_RESULT_TRUST_NOTICE) == 1,
        "P03-5 当轮结果截断 + 单份声明",
    )


# --------------------------------------------------------------- P2.6 P0-4 上下文长度保护

def check_p04(tmp: Path) -> None:
    from glm2api.services.translator import convert_messages

    def tc(cid: str, name: str = "t"):
        return {"role": "assistant", "content": "", "tool_calls": [
            {"id": cid, "type": "function", "function": {"name": name, "arguments": "{}"}}
        ]}

    big_text = "长" * 2000  # 中文 1 字 ≈ 1 token，每轮问题 ≈ 2000 tokens
    msgs = [
        {"role": "system", "content": "你是测试助手"},
        {"role": "user", "content": f"第一轮问题 {big_text}"},
        tc("call_x1"),
        {"role": "tool", "tool_call_id": "call_x1", "content": "第一轮工具结果"},
        {"role": "assistant", "content": "第一轮回答"},
        {"role": "user", "content": f"第二轮问题 {big_text}"},
        tc("call_x2"),
        {"role": "tool", "tool_call_id": "call_x2", "content": "第二轮工具结果"},
        {"role": "assistant", "content": "第二轮回答"},
        {"role": "user", "content": "最新问题"},
    ]

    # CX1 关闭（默认 0=关闭）与旧行为逐字节一致
    check(
        convert_messages(msgs, None, context_max_tokens=0) == convert_messages(msgs, None),
        "CX1 context_max_tokens=0 与默认行为逐字节一致（可关闭性）",
    )

    # CX2 超预算 → 成对裁剪：整轮丢弃（问题 + tool_calls + 结果一起走/一起留）
    logs = LogCapture()
    tr_logger = logging.getLogger("glm2api.services.translator")
    tr_logger.addHandler(logs)
    try:
        out = convert_messages(msgs, None, context_max_tokens=3000)
    finally:
        tr_logger.removeHandler(logs)
    flat = json.dumps(out, ensure_ascii=False)
    check("最新问题" in flat, "CX2-a 当前问题始终保留")
    check("你是测试助手" in flat, "CX2-b 开头 system 消息不被裁掉")
    check(
        "第一轮问题" not in flat and "第一轮工具结果" not in flat and "call_x1" not in flat,
        "CX2-c 最旧一轮被成对丢弃（不留孤立 tool_calls / 结果）",
    )
    check(
        "第二轮问题" in flat and "第二轮工具结果" in flat and "call_x2" in flat,
        "CX2-d 保留轮次完整成对",
    )
    check(
        any("已裁剪" in m for m in logs.messages),
        "CX2-e 裁剪显式告警（失败/降级不静默）",
        f"logs={logs.messages[:3]}",
    )

    # CX3 预算小到连 system+最新问题都放不下 → 兜底最大有效切点，仍保持配对与 system
    logs3 = LogCapture()
    tr_logger.addHandler(logs3)
    try:
        out3 = convert_messages(msgs, None, context_max_tokens=5)
    finally:
        tr_logger.removeHandler(logs3)
    flat3 = json.dumps(out3, ensure_ascii=False)
    check(
        "最新问题" in flat3 and "你是测试助手" in flat3 and "call_x2" not in flat3,
        "CX3 极小预算兜底：保留 system + 最新问题且不成对破坏",
    )
    check(any("仍超预算" in m for m in logs3.messages), "CX3-b 兜底仍超预算时显式告警", f"logs={logs3.messages[:3]}")

    # CX4 未超预算时输出与关闭态一致（零扰动）
    check(
        convert_messages(msgs, None, context_max_tokens=999999) == convert_messages(msgs, None),
        "CX4 预算充足时与关闭态逐字节一致",
    )


# --------------------------------------------------------------- P2.6 P0-5 SSE 首帧预取

def check_p05(tmp: Path) -> None:
    from glm2api.server import prefetch_stream_first_frame

    # PF1 首帧即异常 → 原样穿透（在发 200 之前，由 do_POST 映射为真实状态码）
    class UpstreamAPIErrorShim(Exception):
        pass

    def bad_iter():
        raise UpstreamAPIErrorShim("upstream 401")
        yield b""  # pragma: no cover

    raised = None
    try:
        prefetch_stream_first_frame(bad_iter())
    except UpstreamAPIErrorShim as exc:
        raised = exc
    check(raised is not None, "PF1 首帧异常在预取时穿透（不再 200+流内错误）", str(raised))

    # PF2 正常流：预取帧 + 余下流按序链式回放
    def stream():
        yield b"a"
        yield b"b"
        yield b"c"

    got = list(prefetch_stream_first_frame(stream()))
    check(got == [b"a", b"b", b"c"], "PF2 链式迭代器保序回放", str(got))

    # PF3 空流 → 原样返回（200 + finalize 收尾路径，与旧行为一致）
    check(list(prefetch_stream_first_frame(iter(()))) == [], "PF3 空流透传")

    # PF4 结构断言：三处 _stream_* 都在 send_response 之前接入预取
    source = (RELAY_SRC / "glm2api" / "server.py").read_text(encoding="utf-8")
    wired = source.count("stream_iter = prefetch_stream_first_frame(stream_iter)")
    check(
        wired == 3,
        "PF4 三处流式函数均已接入首帧预取",
        f"命中 {wired} 处",
    )


# --------------------------------------------------------------- P2.6 P0-6 SSE 硬超时看门狗

def check_p06(tmp: Path) -> None:
    from glm2api.config import load_config
    from glm2api.services.glm_client import GLMWebClient

    logger = logging.getLogger("check_p06")
    logs = LogCapture()
    logger.addHandler(logs)

    cfg = load_config(str(tmp / ".env"))
    cfg.glm_stream_max_seconds = 1
    client = GLMWebClient(cfg, logger)

    class HangingResponse:
        """read 阻塞直到被外部 close 的假响应（模拟挂死的上游流）。"""

        def __init__(self) -> None:
            self.closed = False

        def read(self, size: int = -1) -> bytes:
            deadline = time.time() + 5
            while time.time() < deadline and not self.closed:
                time.sleep(0.02)
            if self.closed:
                raise ValueError("I/O operation on closed file.")
            return b""

        def close(self) -> None:
            self.closed = True

    # WD1 挂死流 → 看门狗到点强制关流，迭代器在时限内收尾并留痕
    resp = HangingResponse()
    t0 = time.monotonic()
    events = list(client._iter_sse_events(resp))
    elapsed = time.monotonic() - t0
    check(elapsed < 3.0, "WD1-a 看门狗解除阻塞读（<3s 内收尾，mock 上限 5s）", f"elapsed={elapsed:.2f}s")
    check(resp.closed, "WD1-b 看门狗确实关闭了响应")
    check(any("看门狗" in m for m in logs.messages), "WD1-c 强制关流显式留痕（失败不静默）", f"logs={logs.messages[:2]}")
    check(events == [], "WD1-d 挂死流无事件产出")

    # WD2 看门狗可关闭：max_seconds=0 时不强制干预
    logs.messages.clear()
    cfg.glm_stream_max_seconds = 0

    class OneShotResponse:
        def __init__(self) -> None:
            self.sent = False
            self.closed = False

        def read(self, size: int = -1) -> bytes:
            if not self.sent:
                self.sent = True
                return b"data: {\"ping\": 1}\n\n"
            return b""

        def close(self) -> None:
            self.closed = True

    resp2 = OneShotResponse()
    t0 = time.monotonic()
    events2 = list(client._iter_sse_events(resp2))
    elapsed2 = time.monotonic() - t0
    check(elapsed2 < 1.0 and events2 == [{"ping": 1}], "WD2 关闭看门狗后正常流不受影响", f"events={events2} {elapsed2:.2f}s")
    check(not any("看门狗" in m for m in logs.messages), "WD2-b 关闭时不触发看门狗")

    # WD3 正常流完整体：两帧数据 + EOF
    class TwoFrameResponse:
        def __init__(self) -> None:
            self.frames = [b"data: {\"n\": 1}\n\n", b"data: {\"n\": 2}\n\n", b""]

        def read(self, size: int = -1) -> bytes:
            return self.frames.pop(0) if self.frames else b""

        def close(self) -> None:
            pass

    events3 = list(client._iter_sse_events(TwoFrameResponse()))
    check(events3 == [{"n": 1}, {"n": 2}], "WD3 正常两帧流完整解析", str(events3))


# --------------------------------------------------------------- P2.6 P0-7 新账号宽限

def check_p07(tmp: Path) -> None:
    from glm2api.config import load_config
    from glm2api.services.glm_auth import GLMAccessTokenManager
    from glm2api.services.glm_client import UpstreamAPIError

    logger = logging.getLogger("check_p07")
    cfg = load_config(str(tmp / ".env"))
    cfg.glm_account_grace_seconds = 600
    mgr = GLMAccessTokenManager(cfg, logger)

    # GR1 宽限期内连续 3 次失败不摘除（账号稀缺，网络抖动不该误摘）
    for _ in range(3):
        mgr.record_request(0)
        mgr.record_result(0, False, "transient")
    check(not mgr.is_account_breaked(0), "GR1-a 宽限期内连续 3 败不进熔断")
    check(mgr.is_account_available(0), "GR1-b failover 仍可选该账号")
    stats = mgr.get_account_stats()[0]
    check(
        stats["total_failures"] == 3 and stats["consecutive_failures"] == 0,
        "GR1-c 失败有记录但不进熔断计数",
        str(stats),
    )
    check(stats["last_error"] == "transient", "GR1-d last_error 照常记录")

    # GR2 宽限期后行为不变（回拨 created_at 11 分钟）
    mgr._accounts[0].created_at = time.time() - 660
    for _ in range(3):
        mgr.record_request(0)
        mgr.record_result(0, False, "down")
    check(mgr.is_account_breaked(0), "GR2 宽限期满后连续 3 败照常摘除")
    for i in range(mgr.get_account_count()):
        mgr._accounts[i].breaker_until = 0.0

    # GR3 宽限期内风控冷却照常生效（拍板点 3：封禁信号不被宽限吞掉）
    mgr2 = GLMAccessTokenManager(load_config(str(tmp / ".env")), logger)
    mgr2.config.glm_account_grace_seconds = 600
    exc403 = UpstreamAPIError(403, "f", {})
    for _ in range(3):
        mgr2.register_risk_event(0, exc403)
    check(mgr2.is_account_cooling_down(0), "GR3-a 宽限期内风控三连 → 照常冷却")
    check(not mgr2.is_account_breaked(0), "GR3-b 熔断与风控分源，宽限不混淆两者")

    # GR4 宽限可关闭：grace=0 时行为与旧版一致
    cfg0 = load_config(str(tmp / ".env"))
    cfg0.glm_account_grace_seconds = 0
    mgr3 = GLMAccessTokenManager(cfg0, logger)
    for _ in range(3):
        mgr3.record_request(0)
        mgr3.record_result(0, False, "down")
    check(mgr3.is_account_breaked(0), "GR4 grace=0 连续 3 败立即摘除（可关闭性）")


# --------------------------------------------------------------- P2.6 P0-8 全局最小间隔节流

def check_p08(tmp: Path) -> None:
    from glm2api.config import load_config
    from glm2api.services.glm_client import GLMWebClient, GlobalRequestPacer

    # PT1 节流器单元：min_interval=200ms → 到达间隔 ≥200ms
    pacer = GlobalRequestPacer()
    fires: list[float] = []
    for _ in range(6):
        wait_for = pacer.wait(200.0)
        if wait_for > 0:
            time.sleep(wait_for)
        fires.append(time.monotonic())
    gaps = [b - a for a, b in zip(fires, fires[1:])]
    check(all(g >= 0.19 for g in gaps), "PT1 串行 6 次分配到达间隔 ≥200ms", f"gaps={[round(g, 3) for g in gaps]}")

    # PT2 =0 关闭 → 零等待
    pacer0 = GlobalRequestPacer()
    t0 = time.monotonic()
    for _ in range(5):
        pacer0.wait(0)
    check(time.monotonic() - t0 < 0.05, "PT2 min_interval=0 零等待（可关闭性）")

    # PT3 并发线程全部经 _apply_request_pacing → 到达间隔仍 ≥200ms（补 6 线程同时醒来的漏洞）
    logger = logging.getLogger("check_p08")
    cfg = load_config(str(tmp / ".env"))
    cfg.glm_request_jitter_ms = 0
    cfg.glm_guest_stagger_seconds = 0
    cfg.glm_min_request_interval_ms = 200
    client = GLMWebClient(cfg, logger)
    arrivals: list[float] = []
    lock = threading.Lock()

    def worker() -> None:
        client._apply_request_pacing(0)
        with lock:
            arrivals.append(time.monotonic())

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    arrivals.sort()
    gaps3 = [b - a for a, b in zip(arrivals, arrivals[1:])]
    # 容差 0.17s：Windows 时钟粒度 ~15.6ms，落表测量有 ±1 tick 噪声；
    # slot 数学本身保证 ≥ interval（见 GlobalRequestPacer.wait）
    check(
        len(arrivals) == 6 and all(g >= 0.17 for g in gaps3),
        "PT3 6 并发 pacing 后到达间隔 ≥200ms（±时钟粒度容差）",
        f"gaps={[round(g, 3) for g in gaps3]}",
    )

    # PT4 关闭后 pacing 零延迟（旧行为保持）
    cfg.glm_min_request_interval_ms = 0
    t0 = time.monotonic()
    client._apply_request_pacing(0)
    check(time.monotonic() - t0 < 0.05, "PT4 min_interval=0 时 pacing 零延迟")


# --------------------------------------------------------------- P2.6 P0-9 importer settle 窗口

def check_p09(tmp: Path) -> None:
    from glmrelay.accounts.importer import LoginImportSession

    class FakeEntry:
        fingerprint = "fp123"

    class FakeStore:
        def __init__(self) -> None:
            self.added: list[str] = []
            self.recorded: list[dict] = []

        def has_token(self, token: str) -> bool:
            return False

        def add_token(self, token: str) -> bool:
            self.added.append(token)
            return True

        def record(self, token: str, **kw):
            self.recorded.append({"token": token, **kw})
            return FakeEntry()

        def load_tokens(self) -> list[str]:
            return list(self.added)

    class FakeClient:
        def page_state(self):
            return {}

    def make_session(seq: list[dict], settle: float):
        store = FakeStore()
        s = LoginImportSession(store=store, profile_dir=tmp / "imp", settle_seconds=settle)
        s._client = FakeClient()
        s.state = "waiting_login"
        s._snapshot_done = True  # 跳过诊断快照落盘
        it = iter(seq)
        s._read_local_storage = lambda: next(it)
        return s, store

    # ST1 候选在观察窗内被更新 → 取最终值入库（A → B 稳定）
    s, store = make_session(
        [
            {"chatglm_refresh_token": "tokA"},
            {"chatglm_refresh_token": "tokB"},
            {"chatglm_refresh_token": "tokB"},
        ],
        settle=0.15,
    )
    added = s.poll_once()
    check(bool(added) and store.added == ["tokB"], "ST1 settle 窗口内候选被更新 → 取最终值", f"added={store.added}")

    # ST2 稳定候选观察一窗即入库，不空等
    s2, store2 = make_session(
        [
            {"chatglm_refresh_token": "tokS"},
            {"chatglm_refresh_token": "tokS"},
        ],
        settle=0.15,
    )
    t0 = time.monotonic()
    added2 = s2.poll_once()
    took = time.monotonic() - t0
    check(
        bool(added2) and store2.added == ["tokS"] and took < 2.0,
        "ST2 稳定候选按窗口入库不空等",
        f"{took:.2f}s",
    )

    # ST3 settle=0 → 旧行为（抓到即入库，可关闭性）
    s3, store3 = make_session([{"chatglm_refresh_token": "tokOld"}], settle=0.0)
    added3 = s3.poll_once()
    check(bool(added3) and store3.added == ["tokOld"], "ST3 settle=0 保持抓到即入库")


# --------------------------------------------------------------- P2.6 P0-10/P0-11

def check_p10(tmp: Path) -> None:
    from glm2api.utils.tool_protocol import build_tool_call_instructions

    # FL1 required 模式：反例语在场（对照 gptGrok A "Do NOT write any plain-text reply"）
    required_prompt = build_tool_call_instructions(["get_weather"], tool_choice_policy={"mode": "required", "tool_name": None})
    check(
        "Do NOT write any plain-text reply" in required_prompt and "entire response must be the executable tool call block" in required_prompt,
        "FL1 required 模式含纯文本禁令反例语",
    )
    # FL2 specific 模式：同样补反例语
    specific_prompt = build_tool_call_instructions(["get_weather", "search"], tool_choice_policy={"mode": "specific", "tool_name": "search"})
    check(
        "Do NOT write any plain-text reply" in specific_prompt and "exactly `search`" in specific_prompt,
        "FL2 specific 模式含纯文本禁令反例语",
    )
    # FL3 auto / none 模式不受影响（不约束普通对话）
    auto_prompt = build_tool_call_instructions(["get_weather"], tool_choice_policy={"mode": "auto", "tool_name": None})
    none_prompt = build_tool_call_instructions(["get_weather"], tool_choice_policy={"mode": "none", "tool_name": None})
    check(
        "Do NOT write any plain-text reply" not in auto_prompt and "Do NOT write any plain-text reply" not in none_prompt,
        "FL3 auto/none 模式不注入强制反例语",
    )


def check_p11(tmp: Path) -> None:
    # GH1 .gitignore 覆盖抓包产物三类模式
    gitignore = (RELAY_SRC.parent.parent / ".gitignore").read_text(encoding="utf-8")
    for pattern in ("*.har", "*capture*.jsonl", "Default-*.json"):
        check(pattern in gitignore, f"GH1 .gitignore 含 {pattern}")
    # GH2 当前索引内没有命中这些模式的已跟踪文件
    import subprocess

    tracked = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, cwd=str(RELAY_SRC.parent.parent)
    ).stdout.splitlines()
    hits = [
        f for f in tracked
        if f.endswith(".har") or ("capture" in f and f.endswith(".jsonl")) or (f.startswith("Default-") and f.endswith(".json"))
    ]
    check(not hits, "GH2 已跟踪文件零抓包产物命中", ", ".join(hits[:5]))


def check_statspersist(tmp: Path, tok1: str) -> None:
    """P2 收尾小批：运行统计事件驱动持久化（P2-5，不做 debounce）。

    SP-a（钩子安装形态断言）在 main() 里 import glmrelay 后立即执行；
    本组随后各场景自行临时安装/恢复钩子。
    """
    import threading as th
    from glm2api.config import load_config
    from glm2api.services.glm_auth import GLMAccessTokenManager

    # SP-b 统计变更点触发 listener：快照含累计计数（临时替换，测完恢复）
    captured: list[tuple[int, dict]] = []
    prev_listener = GLMAccessTokenManager.stats_persist_listener
    prev_provider = GLMAccessTokenManager.stats_restore_provider
    try:
        GLMAccessTokenManager.stats_persist_listener = lambda i, snap: captured.append((i, snap))
        GLMAccessTokenManager.stats_restore_provider = None
        cfg = load_config(str(tmp / ".env"))
        mgr = GLMAccessTokenManager(cfg, logging.getLogger("check_sp"))
        mgr.record_request(0)
        mgr.record_result(0, False, "boom")
        mgr.record_probe_result(0, False, "probe: x")
        check(len(captured) >= 3, "SP-b-a record_request/result/probe 各触发一次落盘通报", str(len(captured)))
        last = captured[-1][1]
        check(
            last.get("total_requests") == 1 and last.get("total_failures") == 1 and last.get("probe_failures") == 1,
            "SP-b-b 快照含累计计数与观测字段",
            str(last),
        )
        # 钩子抛异常不阻断统计主流程
        def broken_listener(index, snapshot):
            raise RuntimeError("disk full")

        GLMAccessTokenManager.stats_persist_listener = broken_listener
        mgr.record_request(0)
        check(mgr.get_account_stats()[0]["total_requests"] == 2, "SP-b-c 落盘失败不影响内存统计")
    finally:
        GLMAccessTokenManager.stats_persist_listener = prev_listener
        GLMAccessTokenManager.stats_restore_provider = prev_provider

    # SP-c 启动回填：restore_provider 提供的快照回填白名单字段；时间性状态不回填
    def fake_provider(index: int) -> dict:
        return {
            "total_requests": 42,
            "total_failures": 7,
            "last_error": "历史错误",
            "breaker_until": 12345.0,  # 白名单外：不得回填
            "cooldown_until": 6789.0,
        }

    prev_listener2 = GLMAccessTokenManager.stats_persist_listener
    GLMAccessTokenManager.stats_restore_provider = fake_provider
    try:
        mgr2 = GLMAccessTokenManager(load_config(str(tmp / ".env")), logging.getLogger("check_sp2"))
        row = mgr2.get_account_stats()[0]
        check(
            row["total_requests"] == 42 and row["total_failures"] == 7,
            "SP-c-a 累计计数跨进程回填",
            str(row),
        )
        acc2 = mgr2._accounts[0]
        check(
            acc2.breaker_until == 0.0 and acc2.cooldown_until == 0.0,
            "SP-c-b 时间性状态（熔断/冷却）不跨进程恢复（重启即新鲜状态）",
        )
    finally:
        GLMAccessTokenManager.stats_restore_provider = prev_provider
        GLMAccessTokenManager.stats_persist_listener = prev_listener2

    # SP-d TokenStore stats 旁挂：index→指纹翻译 + 原子写读一致 + 越界安全
    from glmrelay.accounts.store import TokenStore

    store = TokenStore(tmp / "token.txt")
    snapshot = {"total_requests": 5, "total_failures": 1, "last_error": "e"}
    store.record_stats_for_index(0, snapshot)
    check(store.stats_for_index(0).get("total_requests") == 5, "SP-d-a 写读一致（按 index 翻译指纹）")
    check(store.stats_for_index(99) == {}, "SP-d-b 越界 index 安全返回空")
    # token.txt 行序变化（删除首个账号）后旧指纹失配 → 数据不误挂到别的账号
    store.remove_token(tok1)
    check(store.stats_for_index(0) in ({}, None) or store.stats_for_index(0).get("total_requests") != 5,
          "SP-d-c 行序变化后旧数据失配不误挂", str(store.stats_for_index(0)))

    # SP-e 并发写不丢更新（两线程并发写同一 store）
    errors: list[str] = []
    def writer(offset: int) -> None:
        try:
            for i in range(10):
                store.record_stats_for_index(1, {"total_requests": offset * 100 + i})
        except Exception as exc:  # noqa: BLE001
            errors.append(str(exc))

    threads = [th.Thread(target=writer, args=(k,)) for k in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    check(not errors and store.stats_for_index(1) != {}, "SP-e 并发落盘无异常且文件可读", str(errors))

    # SP-f token 行数不足（游客槽 / env 单账号）→ 槽位键回退，游客部署统计也持久
    import json as _json
    store2 = TokenStore(tmp / "guest_token.txt")
    store2.record_stats_for_index(3, {"total_requests": 9})
    check(store2.stats_for_index(3).get("total_requests") == 9, "SP-f-a 无 token 行时按槽位键落盘")
    raw = _json.loads(store2.stats_file.read_text(encoding="utf-8"))
    check(
        any(str(key).startswith("idx-") for key in (raw.get("stats") or {})),
        "SP-f-b 槽位键形态为 idx-N",
        str(list((raw.get("stats") or {}).keys())),
    )


def check_p3agent(tmp: Path) -> None:
    """P3：模式 B agent loop 离线闭环（mock 上游，不依赖真网）。"""
    import json as _json
    from glmrelay.agent.loop import (
        aggregate_builtin_response,
        handle_builtin_request,
        run_builtin_agent,
    )
    from glmrelay.bridge.mode import resolve_tool_mode, strip_builtin_suffix
    from glm2api.config import load_config  # 本函数自身构造 config（main 的局部导入不进这里）

    # AG-a 模式判定三层覆盖 + 非法值回落 + 后缀剥离
    check(resolve_tool_mode({"X-GLM2API-Tool-Mode": "builtin"}, "glm-4", "passthrough") == "builtin",
          "AG-a-1 请求头覆盖最高")
    check(resolve_tool_mode(None, "glm-4@builtin", "passthrough") == "builtin",
          "AG-a-2 模型 @builtin 后缀次之")
    check(resolve_tool_mode(None, "glm-4", "builtin") == "builtin",
          "AG-a-3 全局默认兜底")
    check(resolve_tool_mode({"x-glm2api-tool-mode": "bogus"}, "glm-4", "passthrough") == "passthrough",
          "AG-a-4 非法头值回落 passthrough")
    check(strip_builtin_suffix("glm-4-flash@builtin") == "glm-4-flash"
          and strip_builtin_suffix("glm-4-flash") == "glm-4-flash",
          "AG-a-5 @builtin 后缀剥离")

    class FakeClient:
        """mock 上游：按脚本顺序返回响应。"""

        def __init__(self, script):
            self.script = list(script)
            self.calls: list[dict] = []

        def chat_completion(self, payload):
            self.calls.append(payload)
            return self.script.pop(0), "conv-1"

    def response(message: dict) -> dict:
        return {"choices": [{"index": 0, "message": message, "finish_reason": None}]}

    from glmrelay.tools import registry as registry_mod
    from glmrelay.tools.registry import ToolSpec

    def fake_tool(name: str, output: str) -> ToolSpec:
        return ToolSpec(
            name=name, description="fake", parameters={"type": "object", "properties": {}},
            handler=lambda args, session: output, readonly=True,
        )

    registry_mod.build_registry  # 引用完整性
    config = load_config(str(tmp / ".env"))
    config.glm_builtin_tools = ["echo_tool"]
    config.glm_tool_mode = "passthrough"
    config.glm_builtin_max_rounds = 3

    # 注册一个 fake 工具：monkeypatch build_builtin_registry 的工厂来源
    import glmrelay.agent.loop as loop_mod

    def make_registry(config_arg):
        # run_builtin_agent 调用形态是 build_builtin_registry(config)：
        # mock 从 config.glm_builtin_tools 取启用名单，注册同名 fake 工具
        reg = registry_mod.ToolRegistry()
        for n in list(config_arg.glm_builtin_tools):
            reg.register(fake_tool(n, "echo: " + n))
        return reg

    orig_build = loop_mod.build_builtin_registry
    loop_mod.build_builtin_registry = make_registry
    try:
        # AG-b 非 builtin 模式不接管（透传）
        handled = handle_builtin_request({"model": "glm-4", "messages": []}, {}, FakeClient([]), config)
        check(handled is None, "AG-b 非 builtin 模式返回 None（透传不接管）")

        # AG-c 闭环：第一轮 tool_calls → 执行 → 回灌；第二轮纯文本收尾
        client = FakeClient([
            response({"role": "assistant", "content": None, "tool_calls": [
                {"id": "call_1", "type": "function",
                 "function": {"name": "echo_tool", "arguments": "{\"value\": 1}"}}
            ]}),
            response({"role": "assistant", "content": "工具结果总结"}),
        ])
        payload = {"model": "glm-4@builtin", "messages": [{"role": "user", "content": "hi"}], "tools": [{"fake": True}]}
        stream = b"".join(run_builtin_agent(dict(payload, **{"stream": True}), client, config, logging.getLogger("ag")))
        text = stream.decode("utf-8")
        check('"content": "echo_tool' in text or "echo_tool 成功" in text, "AG-c-a 进度 delta 含工具执行摘要", text[-400:])
        check("工具结果总结" in text, "AG-c-b 最终答复下发")
        check("data: [DONE]" in text, "AG-c-c [DONE] 收尾")
        check(client.calls[0].get("tools") and client.calls[0]["tools"][0]["function"]["name"] == "echo_tool",
              "AG-c-d 内置工具 schema 注入 payload.tools")
        second_round_messages = client.calls[1]["messages"]
        check(
            any(m.get("role") == "assistant" and m.get("tool_calls") for m in second_round_messages)
            and any(m.get("role") == "tool" and m.get("tool_call_id") == "call_1" for m in second_round_messages),
            "AG-c-e assistant tool_calls 与 role:tool 成对回灌（id 对齐前提）",
        )
        check(client.calls[1]["messages"][-1]["content"].startswith("echo: "), "AG-c-f 工具输出全文回灌给模型")
        # 客户端声明的 tools 被忽略；非流式聚合为完整 response
        client_stream_false = FakeClient([response({"role": "assistant", "content": "工具结果总结"})])
        handled2 = handle_builtin_request(
            {"model": "glm-4@builtin", "messages": [], "stream": False, "tools": [{"fake": True}]},
            {}, client_stream_false, config,
        )
        check(isinstance(handled2, dict) and "工具结果总结" in handled2["choices"][0]["message"]["content"],
              "AG-c-g 非流式聚合为完整 response")

        # AG-d 工具参数坏 JSON → error 回灌且循环继续
        client_bad = FakeClient([
            response({"role": "assistant", "content": None, "tool_calls": [
                {"id": "call_bad", "type": "function",
                 "function": {"name": "echo_tool", "arguments": "{broken"}}
            ]}),
            response({"role": "assistant", "content": "done"}),
        ])
        stream_bad = b"".join(run_builtin_agent(
            {"model": "glm-4", "messages": [{"role": "user", "content": "hi"}]}, client_bad, config,
            logging.getLogger("ag"),
        )).decode("utf-8")
        check("工具参数解析失败" in stream_bad and "done" in stream_bad,
              "AG-d 坏参数 error 回灌且循环继续")

        # AG-e 轮数上限：恒返回 tool_calls → max_rounds 后终止并说明
        endless = response({"role": "assistant", "content": None, "tool_calls": [
            {"id": "call_x", "type": "function", "function": {"name": "echo_tool", "arguments": "{}"}}
        ]})
        client_loop = FakeClient([endless] * 10)
        stream_loop = b"".join(run_builtin_agent(
            {"model": "glm-4", "messages": [{"role": "user", "content": "hi"}]}, client_loop, config,
            logging.getLogger("ag"),
        )).decode("utf-8")
        check("已达最大工具轮数" in stream_loop and len(client_loop.script) == 7,
              "AG-e 轮数上限终止（3 轮后不再调上游）")
    finally:
        loop_mod.build_builtin_registry = orig_build

    # AG-f 空注册表显式失败
    empty_config = load_config(str(tmp / ".env"))
    empty_config.glm_builtin_tools = []
    stream_empty = b"".join(run_builtin_agent(
        {"model": "glm-4", "messages": [{"role": "user", "content": "hi"}]}, FakeClient([]), empty_config,
        logging.getLogger("ag"),
    )).decode("utf-8")
    check("未启用任何内置工具" in stream_empty, "AG-f 空注册表显式失败不静默透传")

    # AG-g aggregate 纯聚合
    def tiny_stream():
        yield _fake_chunk_bytes("你好")
        yield _fake_chunk_bytes("世界")

    def _fake_chunk_bytes(content: str) -> bytes:
        event = {"choices": [{"index": 0, "delta": {"content": content}, "finish_reason": None}]}
        # 对齐 loop._chunk 的真实 SSE 帧格式（data: 前缀），aggregate 按该格式解析
        return ("data: " + _json.dumps(event, ensure_ascii=False) + "\n\n").encode("utf-8")

    aggregated = aggregate_builtin_response(tiny_stream())
    check(aggregated["choices"][0]["message"]["content"] == "你好世界", "AG-g 非流式聚合拼接 content")


# --------------------------------------------------------------- P3 内置工具运行时（fs/shell/todo）

def check_p3tools() -> None:
    """P3 模式 B：内置工具三模块 + registry 物理隔离 + 统一执行契约。

    不往共享 tmp 写垃圾：自建 mkdtemp 沙箱目录，finally 清理。
    覆盖：T1 文件工具（沙箱/行号/唯一替换/glob/二进制跳过/只删文件）、
    T2 shell（危险命令正则 + 真实执行 + 超时）、T3 todo（状态渲染 + 非法值）、
    T4 物理隔离（名单外不注册 + 未注册调用报错）、T5 异常转 error 结果。
    """
    from glm2api.config import load_config
    from glmrelay.tools import fs as fs_tools
    from glmrelay.tools import shell as shell_tools
    from glmrelay.tools import todo as todo_tools
    from glmrelay.tools.registry import ToolRegistry, ToolSpec, build_registry
    from glmrelay.tools.safety import check_shell_command

    root = Path(tempfile.mkdtemp(prefix="p3tools_"))
    sandbox = root / "sandbox"
    sandbox.mkdir()
    try:
        env_path = root / ".env"
        env_path.write_text("GLM_TOOL_FS_ROOT=" + str(sandbox) + "\n", encoding="utf-8")
        cfg = load_config(str(env_path))
        check(Path(cfg.glm_tool_fs_root).resolve() == sandbox.resolve(),
              "T0 GLM_TOOL_FS_ROOT 接线到 config.glm_tool_fs_root")

        def tool_handler(module, name: str):
            return module.TOOL_FACTORIES[name](cfg).handler

        read_file = tool_handler(fs_tools, "read_file")
        write_file = tool_handler(fs_tools, "write_file")
        edit_file = tool_handler(fs_tools, "edit_file")
        list_dir = tool_handler(fs_tools, "list_dir")
        grep_files = tool_handler(fs_tools, "grep_files")
        delete_file = tool_handler(fs_tools, "delete_file")
        run_command = tool_handler(shell_tools, "run_command")
        todo_write = tool_handler(todo_tools, "todo_write")

        def raises_value_error(fn, *fn_args, **fn_kwargs) -> tuple[bool, str]:
            try:
                fn(*fn_args, **fn_kwargs)
            except ValueError as exc:
                return True, str(exc)
            return False, ""

        # ---- T1 文件工具（全部路径收敛在沙箱内）
        # T1-a read_file 正常读取 + offset/limit 行号（0 起）
        msg = write_file({"path": "notes/a.txt", "content": "第一行\n第二行\n第三行"}, None)
        check("已写入" in msg, "T1-a-1 write_file 覆盖写并自动建父目录", msg)
        full = read_file({"path": "notes/a.txt"}, None)
        check(full.splitlines() == ["第一行", "第二行", "第三行"], "T1-a-2 read_file 全文按行返回", full)
        window = read_file({"path": "notes/a.txt", "offset": 1, "limit": 1}, None)
        check(window.splitlines() == ["第二行"], "T1-a-3 read_file offset/limit 行号正确（0 起）", window)

        # T1-b 越界路径拒绝（.. 逃逸 + 沙箱外绝对路径）
        (root / "outside.txt").write_text("secret", encoding="utf-8")
        hit, detail = raises_value_error(read_file, {"path": "../outside.txt"}, None)
        check(hit, "T1-b-1 read_file 拒绝 .. 逃逸路径", detail)
        hit, detail = raises_value_error(read_file, {"path": str(root / "outside.txt")}, None)
        check(hit, "T1-b-2 read_file 拒绝沙箱外绝对路径", detail)
        hit, detail = raises_value_error(read_file, {"path": "missing.txt"}, None)
        check(hit, "T1-b-3 read_file 文件不存在报 ValueError", detail)

        # T1-c write_file 写入 + list_dir 可见
        write_file({"path": "notes/b.log", "content": "log-line"}, None)
        listing = list_dir({"path": "notes"}, None)
        check("a.txt" in listing and "b.log" in listing and "[file]" in listing and "字节" in listing,
              "T1-c-1 list_dir 列出名字/类型/大小", listing)
        filtered = list_dir({"path": "notes", "pattern": "*.txt"}, None)
        check("a.txt" in filtered and "b.log" not in filtered, "T1-c-2 list_dir pattern 通配过滤", filtered)

        # T1-d edit_file 唯一匹配替换；多次出现拒绝
        write_file({"path": "edit.txt", "content": "hello world\nhello again"}, None)
        edit_msg = edit_file({"path": "edit.txt", "old_string": "world", "new_string": "GLM"}, None)
        check("替换" in edit_msg and "hello GLM" in read_file({"path": "edit.txt"}, None),
              "T1-d-1 edit_file 唯一匹配替换成功", edit_msg)
        hit, detail = raises_value_error(edit_file, {"path": "edit.txt", "old_string": "hello", "new_string": "X"}, None)
        check(hit and "2" in detail, "T1-d-2 多次出现拒绝并说明出现次数", detail)
        hit, detail = raises_value_error(edit_file, {"path": "edit.txt", "old_string": "absent", "new_string": "X"}, None)
        check(hit, "T1-d-3 出现 0 次拒绝替换", detail)

        # T1-e grep_files：命中形态 / glob 过滤 / 二进制跳过 / 大小写 / max_results
        write_file({"path": "src/main.py", "content": "import os\nTOKEN = 'abc'\n"}, None)
        write_file({"path": "src/skip.log", "content": "TOKEN = 'abc'\n"}, None)
        (sandbox / "src" / "bin.dat").write_bytes(b"TOKEN = 'abc'\x00binary")
        grep_all = grep_files({"pattern": "TOKEN"}, None)
        check("src/main.py:2: TOKEN = 'abc'" in grep_all, "T1-e-1 命中行输出形态 相对路径:行号: 内容", grep_all)
        grep_py = grep_files({"pattern": "TOKEN", "path": "src", "glob": "*.py"}, None)
        check("main.py" in grep_py and "skip.log" not in grep_py, "T1-e-2 glob 过滤生效", grep_py)
        grep_bin = grep_files({"pattern": "TOKEN", "path": "src", "glob": "*.dat"}, None)
        check("bin.dat" not in grep_bin and "无匹配" in grep_bin, "T1-e-3 二进制文件（前 1KB 含 NUL）跳过", grep_bin)
        grep_ci = grep_files({"pattern": "token", "path": "src", "glob": "*.py"}, None)
        check("main.py" in grep_ci, "T1-e-4 re.IGNORECASE 大小写不敏感", grep_ci)
        write_file({"path": "many.txt", "content": "\n".join("hit" + str(i) for i in range(10))}, None)
        grep_cap = grep_files({"pattern": "hit", "path": "many.txt", "max_results": 3}, None)
        check(grep_cap.count("many.txt:") == 3 and "截断" in grep_cap, "T1-e-5 max_results 截断并注明", grep_cap)

        # T1-f delete_file 只删文件不删目录
        write_file({"path": "doomed.txt", "content": "bye"}, None)
        del_msg = delete_file({"path": "doomed.txt"}, None)
        check("已删除" in del_msg and not (sandbox / "doomed.txt").exists(), "T1-f-1 delete_file 删文件成功", del_msg)
        hit, detail = raises_value_error(delete_file, {"path": "notes"}, None)
        check(hit, "T1-f-2 delete_file 拒绝删除目录", detail)

        # ---- T2 shell 工具
        check(check_shell_command("rm -rf /") is not None, "T2-a-1 拒绝 rm -rf /")
        check(check_shell_command("del /s /q") is not None, "T2-a-2 拒绝 del /s /q")
        check(check_shell_command("shutdown /s") is not None, "T2-a-3 拒绝 shutdown /s")
        check(check_shell_command("python --version") is None, "T2-a-4 放行 python --version")

        out = run_command({"command": "python --version"}, None)
        check("Python" in out and "退出码: 0" in out, "T2-b-1 run_command 真实执行 python --version", out)
        # 超时路径：monkeypatch 超时阈值为 0.1s，命令用平台 sleep 形态拖过阈值
        prev_timeout = cfg.glm_shell_timeout_seconds
        try:
            cfg.glm_shell_timeout_seconds = 0.1
            slow = "ping -n 3 127.0.0.1 > nul" if sys.platform == "win32" else "sleep 2"
            hit, detail = raises_value_error(run_command, {"command": slow}, None)
        finally:
            cfg.glm_shell_timeout_seconds = prev_timeout
        check(hit and "超时" in detail, "T2-b-2 超时命令被终止并报 ValueError", detail)

        # ---- T3 todo 工具
        class FakeSession:
            def __init__(self) -> None:
                self.todo_list = None

        sess = FakeSession()
        todo_out = todo_write({"todos": [
            {"content": "任务甲", "status": "pending"},
            {"content": "任务乙", "status": "in_progress"},
            {"content": "任务丙", "status": "completed"},
        ]}, sess)
        check("[ ] 任务甲" in todo_out and "[~] 任务乙" in todo_out and "[x] 任务丙" in todo_out,
              "T3-a-1 三种状态前缀渲染 [ ]/[~]/[x]", todo_out)
        check(isinstance(sess.todo_list, list) and len(sess.todo_list) == 3, "T3-a-2 状态写入 session.todo_list")
        check("共 3 项" in todo_out, "T3-a-3 计数摘要", todo_out.splitlines()[-1])
        hit, detail = raises_value_error(todo_write, {"todos": [{"content": "x", "status": "done"}]}, sess)
        check(hit, "T3-a-4 非法 status 报 ValueError", detail)

        # ---- T4 registry 物理隔离
        builders = {}
        for module in (fs_tools, shell_tools, todo_tools):
            for name, factory in module.TOOL_FACTORIES.items():
                builders[name] = (lambda f=factory, c=cfg: f(c))
        reg = build_registry(["read_file", "list_dir", "grep_files", "todo_write"], builders)
        names = reg.names()
        check(names == ["grep_files", "list_dir", "read_file", "todo_write"],
              "T4-a 只注册名单内工具（物理隔离）", str(names))
        check(not set(names) & {"write_file", "edit_file", "run_command", "delete_file"},
              "T4-b 写档/执行/删除工具默认不注册", str(names))
        miss = reg.run_tool("write_file", {}, None)
        check(not miss.ok and "工具不存在" in miss.output, "T4-c 未注册工具调用返回 error 结果", miss.output)

        # ---- T5 run_tool 执行契约：异常转 error 结果，成功原文回灌
        reg2 = ToolRegistry()

        def boom(args, session):
            raise RuntimeError("boom 内部爆炸")

        reg2.register(ToolSpec(name="boom_tool", description="t",
                               parameters={"type": "object", "properties": {}}, handler=boom))
        bad = reg2.run_tool("boom_tool", {}, None)
        check(not bad.ok and "RuntimeError" in bad.output and "boom" in bad.output,
              "T5-a handler 异常转 error 结果（含异常信息）", bad.output)
        reg2.register(ToolSpec(name="ok_tool", description="t",
                               parameters={"type": "object", "properties": {}},
                               handler=lambda args, session: "一切正常"))
        good = reg2.run_tool("ok_tool", {}, None)
        check(good.ok and good.output == "一切正常", "T5-b 成功路径 ok=True 原文回灌", good.output)
        noargs = reg2.run_tool("ok_tool", None, None)
        check(noargs.ok, "T5-c arguments=None 容错为空参数")
    finally:
        shutil.rmtree(root, ignore_errors=True)


# --------------------------------------------------------------- P2.5-2 I1 身份字段单一数据源 + 矛盾自检

def check_identity(tmp: Path) -> None:
    from glmrelay.identity import (
        IdentityProfile,
        build_profile_from_headers,
        reset_identity_warnings,
        validate_identity,
        warn_identity_conflicts,
    )

    browser_ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0"
    )

    # I1-a urllib + 浏览器 UA → F4 指纹矛盾可观测（TLS 是 Python 栈，头却自称浏览器）
    profile_a = build_profile_from_headers("urllib", "deid-a", {"User-Agent": browser_ua})
    conflicts_a = validate_identity(profile_a)
    check(
        any("F4" in c and "Python 栈" in c for c in conflicts_a),
        "I1-a urllib + 浏览器 UA → 矛盾列表含 F4 条目",
        str(conflicts_a),
    )

    # I1-b 干净配置 → 零矛盾（自检不误伤诚实身份）
    clean = IdentityProfile(
        transport="urllib",
        device_id="deid-clean-0001",
        user_agent="glm2api/0.3 (Windows NT 10.0; Win64; x64)",
        accept_language="zh-CN,zh;q=0.9",
        x_lang="zh",
        sec_ch_ua_platform='"Windows"',
    )
    check(validate_identity(clean) == [], "I1-b 干净配置（urllib+非伪装 UA+zh+真实 deid）→ 零矛盾",
          str(validate_identity(clean)))

    # I1-c 设备身份缺失必须显式暴露
    profile_c = IdentityProfile(
        transport="urllib", device_id="", user_agent="glm2api/0.3",
        accept_language="zh-CN,zh;q=0.9", x_lang="zh", sec_ch_ua_platform="",
    )
    conflicts_c = validate_identity(profile_c)
    check(
        any("device_id" in c and "为空" in c for c in conflicts_c),
        "I1-c device_id 为空 → 含设备身份条目",
        str(conflicts_c),
    )

    # I1-d CDP 传输带 UA = bridge 禁止头剔除漏了的回归信号
    profile_d = IdentityProfile(
        transport="cdp", device_id="deid-d", user_agent=browser_ua,
        accept_language="zh-CN,zh;q=0.9", x_lang="zh", sec_ch_ua_platform='"Windows"',
    )
    conflicts_d = validate_identity(profile_d)
    check(
        any("CDP" in c and "User-Agent" in c for c in conflicts_d),
        "I1-d cdp 传输 + UA 非空 → 含『CDP 不应携带伪装 UA』条目",
        str(conflicts_d),
    )

    # I1-e 头键大小写不敏感：get_browser_headers 输出是混合大小写键
    profile_e = build_profile_from_headers(
        "urllib",
        "deid-e",
        {
            "User-Agent": browser_ua,
            "accept-language": "zh-CN,zh;q=0.9",
            "X-LANG": "zh",
            "sec-ch-ua-platform": '"Windows"',
        },
    )
    check(
        profile_e.user_agent == browser_ua
        and profile_e.accept_language == "zh-CN,zh;q=0.9"
        and profile_e.x_lang == "zh"
        and profile_e.sec_ch_ua_platform == '"Windows"',
        "I1-e build_profile_from_headers 大小写不敏感取值",
        f"ua={profile_e.user_agent[:24]}… lang={profile_e.accept_language} xlang={profile_e.x_lang} plat={profile_e.sec_ch_ua_platform}",
    )

    # I1-f 同一 (transport, 矛盾文本) 第二次调用不再落日志（防每请求刷屏）
    logger = logging.getLogger("check_identity")
    logs = LogCapture()
    logger.addHandler(logs)
    try:
        warned = warn_identity_conflicts(profile_a, logger, "acct-a")
        n_first = sum(1 for m in logs.messages if "身份自检矛盾" in m)
        warn_identity_conflicts(profile_a, logger, "acct-a")
        n_second = sum(1 for m in logs.messages if "身份自检矛盾" in m)
    finally:
        logger.removeHandler(logs)
        reset_identity_warnings()
    check(
        len(warned) == 1 and n_first == 1,
        "I1-f-a 首次告警逐条输出且返回全量矛盾列表",
        f"returned={len(warned)} logged={n_first}",
    )
    check(
        n_second == n_first,
        "I1-f-b 同一 (transport, 矛盾) 二次调用不再输出",
        f"first={n_first} second={n_second}",
    )

    # I1-g 语言自洽矛盾：X-Lang=zh 但 Accept-Language 不以 zh 开头
    profile_g = IdentityProfile(
        transport="urllib", device_id="deid-g", user_agent="glm2api/0.3",
        accept_language="en-US", x_lang="zh", sec_ch_ua_platform="",
    )
    conflicts_g = validate_identity(profile_g)
    check(
        any("X-Lang=zh" in c and "en-US" in c for c in conflicts_g),
        "I1-g x_lang=zh 但 accept_language=en-US → 含语言矛盾条目",
        str(conflicts_g),
    )


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

        # SP-a 先断言扩展层钩子安装形态，随后按"底座独立形态"卸下 stats 两钩子
        # —— 统计落盘若全程在位，各测试组的 record 调用会经 tmp 的 stats 文件
        # 相互回填计数，污染 R1/GR1 等从零计数的既有断言（真实部署无此问题：
        # 回填的就是该部署自己的历史计数）。
        check(
            GLMAccessTokenManager.stats_persist_listener is not None
            and GLMAccessTokenManager.stats_restore_provider is not None,
            "SP-a stats 持久化钩子已由 glmrelay 安装",
        )
        GLMAccessTokenManager.stats_persist_listener = None
        GLMAccessTokenManager.stats_restore_provider = None

        cfg = load_config(str(tmp / ".env"))
        mgr = GLMAccessTokenManager(cfg, logging.getLogger("check_env"))
        check_d4(mgr)
        check_d1(tmp, _deid)
        check_alias(tmp, _tok1, _deid)
        check_d3(tmp)
        check_p01(tmp)
        check_p02(tmp)
        check_p03(tmp)
        check_p04(tmp)
        check_p05(tmp)
        check_p06(tmp)
        check_p07(tmp)
        check_p08(tmp)
        check_p09(tmp)
        check_p10(tmp)
        check_p11(tmp)
        check_runtime(tmp)
        check_p2(tmp)
        check_p6(tmp)
        check_streamguard()
        check_identity(tmp)
        check_statspersist(tmp, _tok1)
        check_p3agent(tmp)
        check_p3tools()
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
