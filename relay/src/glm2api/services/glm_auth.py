from __future__ import annotations

import hashlib
import gzip
import json
import random
import threading
import time
import uuid
import urllib.error
import urllib.request
from dataclasses import dataclass
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
# 视为风控信号的 HTTP 状态：401 签名/授权拒绝、403 封禁、405 游客通道被拒（社区实测）。
# 429 单独判断：上游"其他对话生成中"的忙碌形态不算风控。
RISK_STATUS_CODES = frozenset({401, 403, 405})
# 熔断摘除（P1-b）：与风控冷却分源的通用失败熔断 —— 连续失败（无论原因）达阈值
# 即摘除一段时间，到期后由 failover 半开重试；期间一次成功即清零。
BREAKER_FAILURE_THRESHOLD = 3
BREAKER_COOLDOWN_SECONDS = 600


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


class GLMAccessTokenManager:
    # 扩展点（D1）：glmrelay 在导入时安装，按 refresh_token 返回导入时抓到的
    # 真实设备标识（chatglm-deid）。底座不感知 accounts.json 的存在。
    device_id_resolver: Callable[[str], str] | None = None
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
            try:
                self._persist_refresh_token(account_index, refresh_token)
            except Exception as exc:
                self.logger.warning("写回 GLM refresh_token 失败 index=%s error=%s", account_index, exc)
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

    def should_switch_account(self, exc: Exception) -> bool:
        if hasattr(exc, "status_code"):
            return True
        if isinstance(exc, urllib.error.HTTPError):
            return True
        if isinstance(exc, urllib.error.URLError):
            return True
        if isinstance(exc, TimeoutError):
            return True
        if isinstance(exc, RuntimeError):
            return "token" in str(exc).lower()
        return False

    def classify_risk_event(self, exc: Exception) -> bool:
        """判断异常是否为风控信号（D3）。

        429 需要区分：payload 带 status=10061 或"请等待其他对话生成完毕"是
        上游忙碌（已有独立的重试语义），不算风控；其余 429（限流爆发）计入。
        """
        status = getattr(exc, "status_code", None)
        if status is not None:
            if status == 429:
                payload = getattr(exc, "payload", None) or {}
                message = str(payload.get("message", ""))
                if payload.get("status") == 10061 or "请等待其他对话生成完毕" in message:
                    return False
                return True
            return status in RISK_STATUS_CODES
        if isinstance(exc, urllib.error.HTTPError):
            return exc.code in RISK_STATUS_CODES or exc.code == 429
        return False

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
        """回填一次上游请求结果（成功=HTTP 建联成功）。返回是否触发熔断摘除。"""
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
            acc.consecutive_failures += 1
            acc.last_error = (error or "")[:200]
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

    def next_risk_backoff(self, attempt: int) -> float:
        """风控类异常的同账号重试退避：min(60, 2^n) 秒 + 半程抖动。"""
        base = min(60.0, 2.0 ** max(0, attempt))
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
