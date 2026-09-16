from __future__ import annotations

import hashlib
import gzip
import json
import random
import re
import threading
import time
import uuid
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from logging import Logger
from typing import Callable

from ..config import AppConfig, GUEST_REFRESH_TOKEN_MARKER
from ..core.transport import open_upstream
from ..logging_utils import debug_dump


SIGN_SECRET = "8a1317a7468aa3ad86e997d08f3f31cb"
ACCESS_TOKEN_EXPIRES_SECONDS = 3600
# 风控冷却（D3）：同类风控事件累计达到阈值即冷却，冷却期间该账号不接新请求。
# 冷却触发时把 device_id 换成新匿名值（D1 安全阀），不覆盖 accounts.json 的真实
# deid —— 服务重启后自动回归真实身份。
RISK_EVENT_THRESHOLD = 3
RISK_COOLDOWN_SECONDS = 600
# 熔断摘除（P1-b）：与风控冷却分源的通用失败熔断 —— 连续失败（无论原因）达阈值
# 即摘除一段时间，到期后由 failover 半开重试；期间一次成功即清零。
BREAKER_FAILURE_THRESHOLD = 3
BREAKER_COOLDOWN_SECONDS = 600

# P0-1 状态码分类（生态调研 A1/P0-2）：同一状态码在不同维度语义不同，先分类再处置。
# TRANSIENT（404/409/423/5xx）：资源未就绪 / 上游抖动 —— 账号无辜，不切号
# （404 切号既浪费账号又掩盖真实原因），失败仍计入通用熔断计数。
TRANSIENT_STATUS_CODES = frozenset({404, 409, 423})
# BUSY（429 + 忙碌形态）：沿用既有忙碌重试语义，不计风控。
BUSY_INNER_STATUS = 10061
BUSY_MESSAGE_MARKER = "请等待其他对话生成完毕"
# send_request 忙碌重试耗尽后的自产错误文案（语义仍是忙碌而非风控，切号找空闲身份）
BUSY_EXHAUSTED_MARKER = "长时间忙碌"
# AUTH（401）的权威失效标记：仅 body 明确说"身份失效"才计入风控（冷却 + 换 device_id）；
# 无标记的 401 只记失败走通用熔断 —— 封禁信号不得被无依据的猜测放大。
AUTH_INVALIDATION_MARKERS = (
    "登录",
    "失效",
    "过期",
    "身份",
    "认证",
    "unauthorized",
    "invalid token",
    "token invalid",
)

# P0-2 Retry-After 解析（生态调研 A5/P0-3）：上游明示"请等 N"时尊重它。
# 上游是中文站，错误文案里中英单位混用（"5 分钟" / "5 minutes"），只认英文会漏。
# retry_after=0 用 is not None 判断（`if retry_after:` 会把"立即重试"吞成"无信息"）。
RETRY_AFTER_PATTERN = re.compile(
    r"(\d+)\s*(hours?|hrs?|minutes?|mins?|seconds?|secs?|小时|分钟|分|秒钟|秒|天|d|h|m|s)",
    re.IGNORECASE,
)
RETRY_AFTER_UNIT_SECONDS = {
    "h": 3600.0, "hr": 3600.0, "hrs": 3600.0, "hour": 3600.0, "hours": 3600.0, "小时": 3600.0,
    "m": 60.0, "min": 60.0, "mins": 60.0, "minute": 60.0, "minutes": 60.0, "分钟": 60.0, "分": 60.0,
    "s": 1.0, "sec": 1.0, "secs": 1.0, "second": 1.0, "seconds": 1.0, "秒": 1.0, "秒钟": 1.0,
    "d": 86400.0, "day": 86400.0, "days": 86400.0, "天": 86400.0,
}
# 无总体重试预算可裁剪（游客重取循环无 deadline），用硬上限兜底防止退避失控
RETRY_AFTER_MAX_SECONDS = 600.0


def build_sign() -> tuple[str, str, str]:
    now = str(int(time.time() * 1000))
    digits = [int(char) for char in now]
    checksum = (sum(digits) - digits[-2]) % 10
    timestamp = now[:-2] + str(checksum) + now[-1]
    nonce = uuid.uuid4().hex
    sign = hashlib.md5(f"{timestamp}-{nonce}-{SIGN_SECRET}".encode("utf-8")).hexdigest()
    return timestamp, nonce, sign


@dataclass(slots=True)
class AccessToken:
    access_token: str
    refresh_token: str
    expires_at: float


@dataclass(slots=True)
class AccountState:
    refresh_token: str
    is_guest: bool = False
    cached_token: AccessToken | None = None
    device_id: str = ""
    request_id_counter: int = 0
    device_request_count: int = 0
    risk_event_count: int = 0
    cooldown_until: float = 0.0
    stagger_done: bool = False
    # P1-b：配额统计 + 通用失败熔断
    total_requests: int = 0
    total_failures: int = 0
    consecutive_failures: int = 0
    breaker_until: float = 0.0
    probe_failures: int = 0
    last_used_at: float = 0.0
    last_success_at: float = 0.0
    last_error: str = ""
    # P0-7 新账号宽限：进入账号池的时刻。宽限窗口内的失败不计入通用熔断
    # （网络抖动不至误摘稀缺账号）；风控信号不豁免（register_risk_event 独立路径）。
    created_at: float = field(default_factory=time.time)


class GLMAccessTokenManager:
    # 扩展点（D1）：glmrelay 在导入时安装，按 refresh_token 返回导入时抓到的
    # 真实设备标识（chatglm-deid）。底座不感知 accounts.json 的存在。
    device_id_resolver: Callable[[str], str] | None = None
    # 扩展点（B2）：glmrelay 在导入时安装，refresh_token 被上游轮换写回时收到
    # (旧 token, 新 token) 通报，用于登记 accounts.json 的别名链，保住挂在旧
    # 指纹上的真实设备身份。底座不感知 accounts.json 的存在。
    token_rotation_listener: Callable[[str, str], None] | None = None
    # 扩展点（P1-b）：glmrelay 的健康探测与管理面板从这里读取活跃实例。
    # 本服务为单实例进程，最后创建者即活跃实例。
    last_instance: "GLMAccessTokenManager | None" = None

    def __init__(self, config: AppConfig, logger: Logger) -> None:
        self.config = config
        self.logger = logger
        accounts: list[AccountState] = []
        resolved_devices = 0
        for token in config.glm_refresh_tokens:
            is_guest = token == GUEST_REFRESH_TOKEN_MARKER
            device_id = ""
            if not is_guest:
                resolver = type(self).device_id_resolver
                if resolver is not None:
                    try:
                        device_id = resolver(token) or ""
                    except Exception as exc:
                        self.logger.warning(
                            "device_id 解析失败，该账号回退稳定随机值 error=%s", exc
                        )
                        device_id = ""
            if device_id:
                resolved_devices += 1
            else:
                # 真实设备的标识终身不换；拿不到真实值时也用稳定随机值（不轮换）
                device_id = uuid.uuid4().hex
            accounts.append(
                AccountState(
                    refresh_token="" if is_guest else token,
                    is_guest=is_guest,
                    device_id=device_id,
                )
            )
        self._accounts = accounts
        self._current_index = 0
        self._lock = threading.RLock()  # RLock：因为 next_request_id 会在 _refresh_access_token（已持锁）内被调用
        self._persist_lock = threading.Lock()
        type(self).last_instance = self
        logger.info(
            "账号管理器初始化 账号数=%s 游客模式=%s 真实设备身份=%s/%s",
            len(self._accounts),
            any(a.is_guest for a in self._accounts),
            resolved_devices,
            len(self._accounts) - sum(1 for a in self._accounts if a.is_guest),
        )

    def get_browser_headers(self, app_fr: str = "browser_extension") -> dict[str, str]:
        return {
            "Accept": "application/json, text/plain, */*" if app_fr == "default" else "text/event-stream",
            "Accept-Encoding": "gzip, deflate" if app_fr == "default" else "identity",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
            "App-Name": "chatglm",
            "Cache-Control": "no-cache",
            "Content-Type": "application/json",
            "Origin": "https://chatglm.cn",
            "Pragma": "no-cache",
            "Priority": "u=1, i",
            "Sec-Ch-Ua": '"Microsoft Edge";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": self.config.glm_user_agent,
            "X-App-Fr": app_fr,
            "X-App-Platform": "pc",
            "X-App-Version": "0.0.1",
            "X-Device-Brand": "",
            "X-Device-Model": "",
            "X-Lang": "zh",
        }

    def read_json_response(self, response) -> dict[str, object]:
        try:
            raw_body = response.read()
            content_encoding = response.headers.get("Content-Encoding", "").lower()

            if content_encoding == "gzip":
                raw_body = gzip.decompress(raw_body)

            debug_dump(self.logger, self.config.debug_dump_all, "GLM 原始 JSON 响应体", raw_body)
            payload = json.loads(raw_body.decode("utf-8"))
        except gzip.BadGzipFile as exc:
            raise RuntimeError("GLM 响应 gzip 解压失败") from exc
        except UnicodeDecodeError as exc:
            raise RuntimeError("GLM 响应不是合法 UTF-8") from exc
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"GLM 响应不是合法 JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise RuntimeError(f"GLM 响应格式异常，期望 JSON 对象，实际是: {type(payload).__name__}")
        return payload

    def get_access_token(self) -> str:
        with self._lock:
            return self._get_access_token_for_index(self._current_index)

    def get_account_count(self) -> int:
        return len(self._accounts)

    def get_current_account_index(self) -> int:
        with self._lock:
            return self._current_index

    def is_guest_account(self, account_index: int) -> bool:
        with self._lock:
            return self._accounts[account_index].is_guest

    def get_device_id_for_account(self, account_index: int) -> str:
        """返回该账号当前的 device_id。"""
        with self._lock:
            if 0 <= account_index < len(self._accounts):
                dev = self._accounts[account_index].device_id
                if dev:
                    return dev
            return uuid.uuid4().hex

    def next_request_id_for_account(self, account_index: int) -> str:
        """生成 request_id。device_id 一旦确定终身不换（真实设备不会按请求数轮换）；
        device_request_count 仅作观测统计。失败/冷却时的身份更换走风控冷却分支。"""
        with self._lock:
            if 0 <= account_index < len(self._accounts):
                acc = self._accounts[account_index]
                acc.request_id_counter += 1
                acc.device_request_count += 1
                return f"{acc.device_id[:8]}-{int(time.time()*1000)}-{acc.request_id_counter}"
            return f"{uuid.uuid4().hex[:8]}-{int(time.time()*1000)}-1"

    def advance_account(self, failed_index: int, reason: str) -> int:
        with self._lock:
            if failed_index != self._current_index:
                return self._current_index
            next_index = (failed_index + 1) % len(self._accounts)
            self._current_index = next_index
            self.logger.warning(
                "账号请求失败，切换 refresh_token 账号 index=%s -> %s reason=%s",
                failed_index,
                next_index,
                reason,
            )
            return next_index

    def reset_account_cycle(self) -> None:
        with self._lock:
            self._current_index = 0

    def invalidate_account(self, account_index: int) -> None:
        with self._lock:
            self._accounts[account_index].cached_token = None

    def get_access_token_for_account(self, account_index: int) -> str:
        with self._lock:
            return self._get_access_token_for_index(account_index)

    def get_token_ttl_seconds(self, account_index: int) -> float | None:
        """access_token 缓存剩余秒数（P2.5 第二批 keepalive 批处理用）。

        None = 无缓存（下任一使用方都会发起真实刷新）；>0 = 缓存有效剩余量。
        健康探测据此挑「临期」账号主动续命，而不是全量扫。
        """
        with self._lock:
            if not (0 <= account_index < len(self._accounts)):
                return None
            cached = self._accounts[account_index].cached_token
            if cached is None:
                return None
            return cached.expires_at - time.time()

    def refresh_account_token(self, account_index: int) -> str:
        """强制刷新该账号的 access_token（P2.5 第二批 keepalive 续命入口）。

        get_access_token_for_account 的缓存命中线（剩余 >60s）比探活的临期
        阈值（300s）低 —— 介于两者之间的账号按 get 语义会命中缓存、续命不会
        真实发生；本入口绕过缓存直接刷新，供健康探测在缓存跌破阈值前续命。
        """
        with self._lock:
            account = self._accounts[account_index]
            account.cached_token = self._refresh_access_token(account_index)
            return account.cached_token.access_token

    def _get_access_token_for_index(self, account_index: int) -> str:
        account = self._accounts[account_index]
        if account.cached_token and time.time() < account.cached_token.expires_at - 60:
            self.logger.debug("使用缓存 access_token account=%s 剩余=%.0fs", account_index, account.cached_token.expires_at - time.time())
            return account.cached_token.access_token
        account.cached_token = self._refresh_access_token(account_index)
        return account.cached_token.access_token

    def _refresh_access_token(self, account_index: int) -> AccessToken:
        account = self._accounts[account_index]
        if account.is_guest or not account.refresh_token:
            return self._fetch_guest_access_token(account_index)
        timestamp, nonce, sign = build_sign()
        request = urllib.request.Request(
            self.config.refresh_url,
            data=b"{}",
            method="POST",
            headers={
                **self.get_browser_headers(),
                "Authorization": f"Bearer {account.refresh_token}",
                "X-Nonce": nonce,
                "X-Sign": sign,
                "X-Timestamp": timestamp,
            },
        )
        # 先生成 request_id（可能触发 device_id 轮换），再读取 device_id
        request.headers["X-Request-Id"] = self.next_request_id_for_account(account_index)
        request.headers["X-Device-Id"] = self.get_device_id_for_account(account_index)
        debug_dump(self.logger, self.config.debug_dump_all, f"GLM 刷新 access_token 请求头 account={account_index}", dict(request.header_items()))
        debug_dump(self.logger, self.config.debug_dump_all, f"GLM 刷新 access_token 请求体 account={account_index}", b"{}")
        with open_upstream(request, timeout=self.config.request_timeout) as response:
            payload = self.read_json_response(response)
        code = payload.get("code", payload.get("status"))
        result = payload.get("result") or {}
        access_token = result.get("access_token")
        refresh_token = result.get("refresh_token", account.refresh_token)
        if response.status != 200 or code not in {0, None} or not access_token:
            raise RuntimeError(f"刷新 GLM token 失败: {payload}")
        if refresh_token != account.refresh_token:
            old_token = account.refresh_token  # 赋新值前先取旧值：别名登记需要轮换前后的 token 对
            try:
                self._persist_refresh_token(account_index, refresh_token)
            except Exception as exc:
                self.logger.warning("写回 GLM refresh_token 失败 index=%s error=%s", account_index, exc)
            # 扩展点（B2）：把 (旧, 新) token 对通报给扩展层登记别名链；登记失败
            # 只影响重启后的身份解析，不得阻断刷新主流程。
            listener = type(self).token_rotation_listener
            if listener is not None:
                try:
                    listener(old_token, refresh_token)
                except Exception as exc:
                    self.logger.warning(
                        "token 轮换别名登记失败 index=%s error=%s", account_index, exc
                    )
            account.refresh_token = refresh_token
            self.config.glm_refresh_tokens[account_index] = refresh_token
            if account_index == 0:
                self.config.glm_refresh_token = refresh_token
            self.logger.info("GLM refresh_token 已自动刷新并写回账号存储 index=%s", account_index)
        return AccessToken(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=time.time() + ACCESS_TOKEN_EXPIRES_SECONDS - random.randint(10, 30),
        )

    def _fetch_guest_access_token(self, account_index: int) -> AccessToken:
        account = self._accounts[account_index]
        timestamp, nonce, sign = build_sign()
        request_id = self.next_request_id_for_account(account_index)
        device_id = self.get_device_id_for_account(account_index)
        request = urllib.request.Request(
            self.config.guest_refresh_url,
            data=b"",
            method="POST",
            headers={
                **self.get_browser_headers(app_fr="default"),
                "Content-Length": "0",
                "Referer": "https://chatglm.cn/",
                "X-Device-Id": device_id,
                "X-Nonce": nonce,
                "X-Request-Id": request_id,
                "X-Sign": sign,
                "X-Timestamp": timestamp,
            },
        )
        debug_dump(self.logger, self.config.debug_dump_all, f"GLM 游客 token 请求头 account={account_index}", dict(request.header_items()))
        debug_dump(self.logger, self.config.debug_dump_all, f"GLM 游客 token 请求体 account={account_index}", b"")
        with open_upstream(request, timeout=self.config.request_timeout) as response:
            payload = self.read_json_response(response)
        code = payload.get("code", payload.get("status"))
        result = payload.get("result") or {}
        access_token = result.get("access_token")
        refresh_token = result.get("refresh_token")
        if response.status != 200 or code not in {0, None} or not access_token or not refresh_token:
            raise RuntimeError(f"获取 GLM 游客 token 失败: {payload}")
        account.refresh_token = str(refresh_token)
        self.logger.info("已获取新的 GLM 游客 refresh_token index=%s", account_index)
        return AccessToken(
            access_token=str(access_token),
            refresh_token=str(refresh_token),
            expires_at=time.time() + ACCESS_TOKEN_EXPIRES_SECONDS - random.randint(10, 30),
        )

    def _persist_refresh_token(self, account_index: int, refresh_token: str) -> None:
        with self._persist_lock:
            if self._accounts[account_index].is_guest:
                return
            if self.config.token_file_path.exists() or len(self.config.glm_refresh_tokens) > 1:
                tokens = list(self.config.glm_refresh_tokens)
                tokens[account_index] = refresh_token
                content = "\n".join(tokens) + "\n"
                try:
                    self.config.token_file_path.write_text(content, encoding="utf-8")
                except OSError as exc:
                    raise RuntimeError(f"写入 token 文件失败: {self.config.token_file_path} error={exc}") from exc
                return
            self._persist_env_refresh_token(refresh_token)

    def _persist_env_refresh_token(self, refresh_token: str) -> None:
        env_path = self.config.env_file_path
        if not env_path.exists():
            self.logger.warning(".env 文件不存在，无法自动写回新的 refresh_token")
            return

        try:
            content = env_path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise RuntimeError(f".env 不是有效的 UTF-8 编码: {env_path}") from exc
        except OSError as exc:
            raise RuntimeError(f"读取 .env 失败: {env_path} error={exc}") from exc
        lines = content.splitlines()
        updated = False

        for index, line in enumerate(lines):
            if line.startswith("GLM_REFRESH_TOKEN="):
                lines[index] = f"GLM_REFRESH_TOKEN={refresh_token}"
                updated = True
                break

        if not updated:
            if lines and lines[-1].strip():
                lines.append("")
            lines.append(f"GLM_REFRESH_TOKEN={refresh_token}")

        new_content = "\n".join(lines) + "\n"
        try:
            env_path.write_text(new_content, encoding="utf-8")
        except OSError as exc:
            raise RuntimeError(f"写入 .env 失败: {env_path} error={exc}") from exc

    def classify_upstream_error(self, exc: Exception) -> str:
        """上游异常四分类（P0-1）：返回 TRANSIENT / BUSY / AUTH / RISK。

        分类先行，处置在后：TRANSIENT 不切号；BUSY 沿用忙碌重试语义；
        AUTH 仅在 body 带权威失效标记时升级为风控；RISK 计风控。
        """
        status = getattr(exc, "status_code", None)
        if status is None and isinstance(exc, urllib.error.HTTPError):
            status = exc.code
        if isinstance(status, int):
            if status == 429:
                payload = getattr(exc, "payload", None)
                message = str(payload.get("message", "")) if isinstance(payload, dict) else str(exc)
                if (
                    (isinstance(payload, dict) and payload.get("status") == BUSY_INNER_STATUS)
                    or BUSY_MESSAGE_MARKER in message
                    or BUSY_EXHAUSTED_MARKER in message
                ):
                    return "BUSY"
                return "RISK"
            if status == 401:
                return "AUTH"
            if status in (403, 405):
                return "RISK"
            # 404/409/423/5xx 及其余未知状态码：账号无辜，不切号
            return "TRANSIENT"
        # 无 HTTP 状态码：网络层错误（URLError/TimeoutError/socket.timeout/
        # ConnectionError 均为 OSError 子类）属暂态，切号无济于事。
        if isinstance(exc, OSError):
            return "TRANSIENT"
        if isinstance(exc, RuntimeError):
            # token 生命周期异常（刷新失败 / 游客获取失败）：按 AUTH 处理（切号）；
            # 是否升级风控由 is_authoritative_auth_failure 依据 body 文本判定。
            text = str(exc).lower()
            if "token" in text or "刷新" in text:
                return "AUTH"
            return "TRANSIENT"
        return "TRANSIENT"

    def is_authoritative_auth_failure(self, exc: Exception) -> bool:
        """401 是否带上游权威失效标记（P0-1）。只有 body 明确说"身份失效"
        才计风控；仅凭 HTTP 状态码本身不足以判定账号被封禁。"""
        payload = getattr(exc, "payload", None)
        if isinstance(payload, dict):
            if payload.get("code") == 401 or payload.get("status") == 401:
                return True
            text = str(payload.get("message", ""))
        elif isinstance(exc, urllib.error.HTTPError):
            # 裸 HTTPError 只有头层信息，无权威 body 语义 → 未确认
            return False
        else:
            text = str(exc)
        lowered = text.lower()
        return any(marker in text or marker in lowered for marker in AUTH_INVALIDATION_MARKERS)

    def should_switch_account(self, exc: Exception) -> bool:
        """是否切换账号（P0-1 语义：按分类决定，不再"有 status_code 就切号"）。

        TRANSIENT（404/409/423/5xx/网络）不切号 —— 资源未就绪或链路抖动与账号
        无关，切号浪费账号且掩盖真实原因；BUSY/AUTH/RISK 均切号。
        """
        return self.classify_upstream_error(exc) != "TRANSIENT"

    def classify_risk_event(self, exc: Exception) -> bool:
        """判断异常是否为风控信号（D3 语义，P0-1 收紧 401）。

        = RISK 类（403/405/真限流 429），或 AUTH 且 body 带权威失效标记。
        429 忙碌形态（10061 / "请等待其他对话生成完毕"）不算风控。
        """
        kind = self.classify_upstream_error(exc)
        if kind == "RISK":
            return True
        return kind == "AUTH" and self.is_authoritative_auth_failure(exc)

    def register_risk_event(self, account_index: int, exc: Exception) -> bool:
        """记录一次风控事件；累计达阈值进入冷却并轮换设备身份。返回是否触发冷却。"""
        with self._lock:
            if not (0 <= account_index < len(self._accounts)):
                return False
            acc = self._accounts[account_index]
            acc.risk_event_count += 1
            if acc.risk_event_count < RISK_EVENT_THRESHOLD:
                return False
            acc.risk_event_count = 0
            acc.cooldown_until = time.time() + RISK_COOLDOWN_SECONDS
            old_dev = acc.device_id[:8]
            acc.device_id = uuid.uuid4().hex
            acc.cached_token = None
            self.logger.warning(
                "account=%s 风控事件累计达阈值，进入冷却 %ss 并轮换 device_id %s → %s（accounts.json 中的真实身份不受影响，重启后回归）",
                account_index, RISK_COOLDOWN_SECONDS, old_dev, acc.device_id[:8],
            )
            return True

    def is_account_cooling_down(self, account_index: int) -> bool:
        with self._lock:
            if 0 <= account_index < len(self._accounts):
                return time.time() < self._accounts[account_index].cooldown_until
            return False

    def is_account_breaked(self, account_index: int) -> bool:
        """是否处于熔断摘除期（连续失败达阈值 / 健康探测判定失效）。"""
        with self._lock:
            if 0 <= account_index < len(self._accounts):
                return time.time() < self._accounts[account_index].breaker_until
            return False

    def is_account_available(self, account_index: int) -> bool:
        """failover 选号的统一可用性判定：不在风控冷却、也不在熔断摘除期。"""
        return not self.is_account_cooling_down(account_index) and not self.is_account_breaked(account_index)

    def record_request(self, account_index: int) -> None:
        with self._lock:
            if 0 <= account_index < len(self._accounts):
                acc = self._accounts[account_index]
                acc.total_requests += 1
                acc.last_used_at = time.time()

    def record_result(self, account_index: int, ok: bool, error: str = "") -> bool:
        """回填一次上游请求结果（成功=HTTP 建联成功）。返回是否触发熔断摘除。

        P0-7：账号进入账号池后 GLM_ACCOUNT_GRACE_SECONDS 内的失败只记录不计入
        通用熔断 —— 新导入账号立即遇网络抖动不应被误摘；风控冷却不受宽限豁免
        （封禁信号不该被宽限吞掉，见 register_risk_event 独立路径）。
        """
        with self._lock:
            if not (0 <= account_index < len(self._accounts)):
                return False
            acc = self._accounts[account_index]
            if ok:
                acc.consecutive_failures = 0
                acc.last_success_at = time.time()
                acc.last_error = ""
                return False
            acc.total_failures += 1
            acc.last_error = (error or "")[:200]
            grace = int(self.config.glm_account_grace_seconds or 0)
            if grace > 0 and time.time() - acc.created_at < grace:
                return False
            acc.consecutive_failures += 1
            if acc.consecutive_failures >= BREAKER_FAILURE_THRESHOLD and time.time() >= acc.breaker_until:
                acc.breaker_until = time.time() + BREAKER_COOLDOWN_SECONDS
                acc.consecutive_failures = 0
                self.logger.warning(
                    "account=%s 连续失败达阈值，熔断摘除 %ss（到期后半开重试）last_error=%s",
                    account_index, BREAKER_COOLDOWN_SECONDS, acc.last_error,
                )
                return True
            return False

    def record_probe_result(self, account_index: int, ok: bool, error: str = "") -> bool:
        """回填健康探测结果（P1-b）。与请求失败分源计数，达阈值同样熔断摘除。"""
        with self._lock:
            if not (0 <= account_index < len(self._accounts)):
                return False
            acc = self._accounts[account_index]
            if ok:
                acc.probe_failures = 0
                return False
            acc.probe_failures += 1
            if error:
                acc.last_error = error[:200]
            if acc.probe_failures >= BREAKER_FAILURE_THRESHOLD and time.time() >= acc.breaker_until:
                acc.breaker_until = time.time() + BREAKER_COOLDOWN_SECONDS
                acc.probe_failures = 0
                self.logger.warning(
                    "account=%s 健康探测连续失败达阈值，判定失效并熔断摘除 %ss",
                    account_index, BREAKER_COOLDOWN_SECONDS,
                )
                return True
            return False

    def get_account_stats(self) -> list[dict[str, object]]:
        """运行时配额视图（管理面板 / 健康探测共用）。"""
        with self._lock:
            now = time.time()
            rows: list[dict[str, object]] = []
            for index, acc in enumerate(self._accounts):
                ok_count = acc.total_requests - acc.total_failures
                rows.append(
                    {
                        "index": index,
                        "is_guest": acc.is_guest,
                        "device_id_head": acc.device_id[:8],
                        "total_requests": acc.total_requests,
                        "total_failures": acc.total_failures,
                        "success_rate": round(ok_count / acc.total_requests, 4) if acc.total_requests else None,
                        "consecutive_failures": acc.consecutive_failures,
                        "cooling_down": now < acc.cooldown_until,
                        "breaked": now < acc.breaker_until,
                        "last_used_at": acc.last_used_at,
                        "last_success_at": acc.last_success_at,
                        "last_error": acc.last_error,
                    }
                )
            return rows

    def parse_retry_after(self, exc: Exception) -> float | None:
        """从异常中解析上游明示的等待时长（P0-2）。返回秒数；无法解析返回 None。

        优先级：HTTP 头 Retry-After（纯秒数）> payload retry_after 字段 >
        错误文案正则（中英双语，支持"1小时30分钟"叠加）。
        """
        headers = getattr(exc, "headers", None)
        if headers is not None:
            try:
                value = headers.get("Retry-After")
            except Exception:
                value = None
            if value is not None:
                text = str(value).strip()
                try:
                    return float(text)
                except ValueError:
                    pass
        payload = getattr(exc, "payload", None)
        if isinstance(payload, dict) and payload.get("retry_after") is not None:
            try:
                return float(payload["retry_after"])
            except (TypeError, ValueError):
                pass
        if isinstance(payload, dict):
            texts = [str(payload.get("message", ""))]
        else:
            texts = []
        texts.append(str(exc))
        for text in texts:
            total = 0.0
            matched = False
            for match in RETRY_AFTER_PATTERN.finditer(text):
                unit = match.group(2).lower()
                factor = RETRY_AFTER_UNIT_SECONDS.get(unit)
                if factor is None:
                    continue
                total += float(match.group(1)) * factor
                matched = True
            if matched:
                return total
        return None

    def next_risk_backoff(self, attempt: int, retry_after: float | None = None) -> float:
        """风控类异常的同账号重试退避：min(60, 2^n) 秒 + 半程抖动（P0-2 扩展）。

        上游明示 Retry-After 时取 max(指数退避, retry_after) 并裁剪到上限；
        retry_after=0 视为"立即可重试"，不得被 falsy 判断吞掉。
        """
        base = min(60.0, 2.0 ** max(0, attempt))
        if retry_after is not None:
            if retry_after <= 0:
                return 0.0
            return min(max(base, retry_after), RETRY_AFTER_MAX_SECONDS)
        return base + random.uniform(0, base * 0.5)

    def apply_guest_stagger(self, account_index: int) -> None:
        """游客槽错峰（D3）：每个游客槽首次请求前随机延迟一次，替代瞬时全新设备群。"""
        with self._lock:
            if not (0 <= account_index < len(self._accounts)):
                return
            acc = self._accounts[account_index]
            if not acc.is_guest or acc.stagger_done:
                return
            acc.stagger_done = True
        seconds = self.config.glm_guest_stagger_seconds
        if seconds <= 0:
            return
        delay = random.uniform(0, seconds)
        self.logger.info("游客槽错峰上岗 account=%s 首次请求前延迟 %.1fs", account_index, delay)
        time.sleep(delay)
