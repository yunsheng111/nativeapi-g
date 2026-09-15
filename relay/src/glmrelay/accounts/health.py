"""账号健康探测（P1-b）：后台逐账号轻量探活，失效账号自动摘除。

探活动作 = 触发该账号的一次 token 获取：
- token 缓存有效（1 小时内活跃的账号）→ 零上游成本，视为健康；
- 缓存过期 → 发起真实 refresh / guest 请求，成功即续命缓存并确认健康，
  失败经 record_probe_result 累计，达阈值由底座熔断摘除（到期后 failover 半开重试）。

调度原则（呼应 D3 节奏）：账号间错峰、首轮延迟启动，避免与启动瞬时请求叠加；
GLM_HEALTH_PROBE_SECONDS=0 时完全不启动。

依赖方向：glmrelay → glm2api（读 GLMAccessTokenManager.last_instance）。
启动入口：底座 server.py 的扩展层接入区调用 ensure_health_probe()。
"""

from __future__ import annotations

import random
import threading
import time
from logging import Logger

from glm2api.config import AppConfig
from glm2api.services.glm_auth import GLMAccessTokenManager

_FIRST_ROUND_DELAY_RANGE = (5.0, 15.0)
_PER_ACCOUNT_GAP_RANGE = (0.5, 2.0)

_started = False
_start_lock = threading.Lock()


def ensure_health_probe(config: AppConfig, logger: Logger) -> bool:
    """启动后台探活线程（幂等）。返回是否实际启动。"""
    global _started
    seconds = config.glm_health_probe_seconds
    with _start_lock:
        if _started or seconds <= 0:
            return False
        _started = True
    thread = threading.Thread(
        target=_probe_loop,
        args=(config, seconds, logger),
        name="glmrelay-health-probe",
        daemon=True,
    )
    thread.start()
    logger.info("健康探测已启动 每 %ss 一轮（GLM_HEALTH_PROBE_SECONDS=%s）", seconds, seconds)
    return True


def _probe_loop(config: AppConfig, seconds: int, logger: Logger) -> None:
    time.sleep(random.uniform(*_FIRST_ROUND_DELAY_RANGE))
    while True:
        try:
            probed = probe_once(logger)
            if probed:
                logger.debug("健康探测完成 本轮账号数=%s", probed)
        except Exception as exc:  # 探活自身故障不允许拖垮服务
            logger.warning("健康探测轮次异常 error=%s", exc)
        time.sleep(seconds)


def probe_once(logger: Logger) -> int:
    """执行一轮探活，返回本轮探过的账号数。供后台线程与面板手动触发共用。"""
    manager = GLMAccessTokenManager.last_instance
    if manager is None:
        return 0
    count = manager.get_account_count()
    probed = 0
    for index in range(count):
        if not manager.is_guest_account(index):
            # 账号间错峰，避免"齐步走"式探活（D3 节奏原则）
            time.sleep(random.uniform(*_PER_ACCOUNT_GAP_RANGE))
        try:
            manager.get_access_token_for_account(index)
        except Exception as exc:
            manager.record_probe_result(index, False, f"probe: {exc}")
            continue
        manager.record_probe_result(index, True)
        probed += 1
    return probed
