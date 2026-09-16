"""账号健康探测（P1-b → P2.5 第二批 keepalive 批处理）。

探活动作 = 触发该账号的一次 token 获取：
- token 缓存仍有效（剩余 TTL 高于临期阈值）→ 零上游成本，视为健康；
- 缓存临期/无缓存 → 发起真实 refresh / guest 请求，成功即续命缓存并确认健康，
  失败经 record_probe_result 累计，达阈值由底座熔断摘除（到期后 failover 半开重试）。

P2.5 第二批 keepalive 批处理（对照 gptGrok B3「每轮限量 N 个临期账号主动续命」）：
每轮只挑缓存临期的账号做真实续命，且每轮限量 N 个 —— 避免探测轮自身在缓存
集体过期时瞬间打出一串真实刷新请求（探测风暴）。失败退避由既有摘除机制天然
承担（连续 3 轮失败 → 摘除 600s），摘除中的账号直接跳过、不再打无意义请求。

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
from glm2api.core.transport import set_request_account
from glm2api.services.glm_auth import GLMAccessTokenManager

_FIRST_ROUND_DELAY_RANGE = (5.0, 15.0)
_PER_ACCOUNT_GAP_RANGE = (0.5, 2.0)
# 临期阈值：缓存剩余低于该值视为"该续命了"（下游请求不再撞上刷新延迟）
_KEEPALIVE_TTL_THRESHOLD = 300.0

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
    logger.info(
        "健康探测已启动 每 %ss 一轮 keepalive批量=%s（GLM_HEALTH_PROBE_SECONDS=%s）",
        seconds,
        config.glm_health_keepalive_batch,
        seconds,
    )
    return True


def _probe_loop(config: AppConfig, seconds: int, logger: Logger) -> None:
    time.sleep(random.uniform(*_FIRST_ROUND_DELAY_RANGE))
    while True:
        try:
            probed = probe_once(logger, batch_limit=config.glm_health_keepalive_batch)
            if probed:
                logger.debug("健康探测完成 本轮健康账号数=%s", probed)
        except Exception as exc:  # 探活自身故障不允许拖垮服务
            logger.warning("健康探测轮次异常 error=%s", exc)
        time.sleep(seconds)


def probe_once(logger: Logger, batch_limit: int = 0) -> int:
    """执行一轮探活，返回本轮确认健康的账号数（零成本确认 + 真实续命成功）。

    batch_limit = 每轮真实续命尝试的上限（0 = 不限量，保持旧行为），按尝试计
    —— 失败也占名额，否则失败账号会让批量形同虚设；缓存仍长期有效的账号
    零成本确认健康，不占名额；熔断摘除中的账号直接跳过 —— 摘除期打它没有
    意义，到期后由 failover 半开。
    """
    manager = GLMAccessTokenManager.last_instance
    if manager is None:
        return 0
    count = manager.get_account_count()
    healthy = 0
    attempted = 0
    for index in range(count):
        # 账号提示（P2.5 第二批）：探活请求也按账号路由到专属 context
        set_request_account(index)
        try:
            if manager.is_account_breaked(index):
                continue  # 已摘除：等 failover 半开，不在探活里硬打（摘除即最强退避）
            if not manager.is_guest_account(index):
                # 账号间错峰（D3 节奏原则）；游客槽上岗时已有 apply_guest_stagger
                time.sleep(random.uniform(*_PER_ACCOUNT_GAP_RANGE))
                ttl = manager.get_token_ttl_seconds(index)
                if ttl is not None and ttl > _KEEPALIVE_TTL_THRESHOLD:
                    # 缓存仍然健康：零成本确认，不发上游请求，不占批量名额
                    manager.record_probe_result(index, True)
                    healthy += 1
                    continue
                if 0 < batch_limit <= attempted:
                    continue  # 批量名额用尽：本轮到此为止
                attempted += 1
                try:
                    # 临期/无缓存 → 强制续命。必须绕过 get 的 60s 缓存命中线，
                    # 否则 60~300s 之间的"临期"账号会被缓存命中吞掉，续命形同虚设
                    manager.refresh_account_token(index)
                except Exception as exc:
                    manager.record_probe_result(index, False, f"probe: {exc}")
                    continue
                manager.record_probe_result(index, True)
                healthy += 1
            else:
                # 游客槽：既有行为 —— 缓存命中零成本，否则真实获取（无账号可续命）
                try:
                    manager.get_access_token_for_account(index)
                except Exception as exc:
                    manager.record_probe_result(index, False, f"probe: {exc}")
                    continue
                manager.record_probe_result(index, True)
                healthy += 1
        finally:
            set_request_account(None)
    return healthy
