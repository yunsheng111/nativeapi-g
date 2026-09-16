"""账号登录导入：拉起受控浏览器，用户自己登录，程序自动抓 refresh_token。

相比「每个账号都去 F12 → Application → Local Storage 复制粘贴」，这里的流程是：

    点「导入账号」→ 弹出一个独立 profile 的浏览器 → 用户扫码/密码登录
    → 程序检测到 refresh_token 出现 → 自动去重写入 token.txt
    → 保持窗口打开，可继续登出再登入下一个账号

设计要点：
1. **独立 profile**：不复用用户日常浏览器的数据目录。这既是 Chrome/Edge 136+
   的硬性要求（默认 profile 不允许开远程调试端口），也避免污染用户登录态。
2. **device_id 一并抓取**：`chatglm-deid` 是账号绑定的设备身份，底座也在管理它。
   只导入 token 而不导入 device_id 会造成身份错配，反而更容易触发风控。
3. **诊断快照**：首次抓到 token 时把 localStorage 的键名与脱敏值落盘，
   便于日后上游改键名时快速定位。
4. **不缓存 token 列表**：每次轮询都重新读 token.txt，避免与服务端写入打架。
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from ..browser import CDPError, ManagedBrowser
from .store import (
    DEVICE_KEY_CANDIDATES,
    TOKEN_KEY_CANDIDATES,
    TokenStore,
    extract_candidates,
    looks_like_device_key,
    looks_like_token_key,
    mask_token,
    now_iso,
    pick_local_storage_value,
)

CHATGLM_HOME = "https://chatglm.cn"

# 轮询是「读一次页面 localStorage」，导航瞬间读失败属正常。
# 只有连续失败到这个次数，才判定会话已死并置为 error。
_MAX_POLL_FAILURES = 5

_DUMP_JS = """
(() => {
  const out = {};
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k === null) continue;
      const v = localStorage.getItem(k);
      out[k] = v === null ? '' : v;
    }
  } catch (e) {
    return {__error: String(e && e.message || e)};
  }
  return out;
})()
"""


def _capture_chatglm_cookies(client) -> list[dict]:
    """抓取浏览器里 chatglm.cn 域的全部 cookie（P2.5 第二批 D2）。

    用途：BrowserContext 账号隔离池创建专属 context 时灌入，让该账号的
    同源 fetch 带上自己的 cookie（cookie 与 Authorization 同源一致，消除
    身份混叠）。抓取放在登录导入时一次性完成；Storage.getCookies 无需
    enable，失败降级为无 cookie（context 干净身份仍成立）。

    落盘位置：accounts.json 的条目 extra.cookies —— 该文件本就存同级敏感
    的 refresh_token，且已在凭据 ignore 清单内。
    """
    try:
        result = client.call("Storage.getCookies", {}, timeout=8.0)
    except Exception:  # noqa: BLE001  CDPError/断连都降级为无 cookie
        return []
    cookies = result.get("cookies") if isinstance(result, dict) else None
    if not isinstance(cookies, list):
        return []
    return [c for c in cookies if isinstance(c, dict) and "chatglm" in str(c.get("domain", ""))]


@dataclass
class Capture:
    """一次成功抓取。"""

    index: int
    fingerprint: str
    token_masked: str
    device_id: str
    token_key: str
    device_key: str
    captured_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "fingerprint": self.fingerprint,
            "token_masked": self.token_masked,
            "device_id": self.device_id,
            "token_key": self.token_key,
            "device_key": self.device_key,
            "captured_at": self.captured_at,
        }


class LoginImportSession:
    """一次「登录导入」会话。线程安全，可被管理面板轮询。"""

    def __init__(
        self,
        store: TokenStore,
        profile_dir: Path,
        port: int = 9333,
        preferred: str | None = None,
        headless: bool = False,
        snapshot_dir: Path | None = None,
        poll_interval: float = 1.5,
        settle_seconds: float = 2.0,
    ) -> None:
        self.store = store
        self.profile_dir = Path(profile_dir)
        self.port = port
        self.preferred = preferred
        self.headless = headless
        self.snapshot_dir = Path(snapshot_dir) if snapshot_dir else None
        self.poll_interval = poll_interval
        # P0-9 settle 稳定窗口：抓到候选后继续观察 N 秒，值变化取最新，
        # 稳定一窗才入库（防半截凭据）；0 = 关闭（抓到即入库的旧行为）。
        self.settle_seconds = settle_seconds

        self.session_id = uuid.uuid4().hex[:12]
        self.state = "created"
        self.message = "尚未启动"
        self.browser_name = ""
        self.last_error = ""
        self.poll_count = 0
        self.fail_count = 0
        self.captures: list[Capture] = []

        self._managed: ManagedBrowser | None = None
        self._client = None
        self._proc = None
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._thread: threading.Thread | None = None
        self._snapshot_done = False

    # ---------------------------------------------------------------- 生命周期

    def start(self) -> dict:
        with self._lock:
            if self.state in ("starting", "waiting_login"):
                return self.status()

        try:
            managed = ManagedBrowser(
                user_data_dir=str(self.profile_dir),
                port=self.port,
                preferred=self.preferred,
                headless=self.headless,
                start_url=CHATGLM_HOME,
            )
            with self._lock:
                self._managed = managed
                self.browser_name = str(managed.browser)
                self.state = "starting"
                self.message = f"正在启动 {managed.browser.name}…"

            proc, client = managed.start(page_url_contains="chatglm.cn")
            with self._lock:
                self._proc = proc
                self._client = client
                self.state = "waiting_login"
                self.message = "浏览器已打开，请在窗口中登录智谱清言（扫码或账号密码均可）"
        except Exception as exc:  # noqa: BLE001
            with self._lock:
                self.state = "error"
                self.last_error = f"{type(exc).__name__}: {exc}"
                self.message = f"启动失败：{self.last_error}"
            self._cleanup_browser()
            return self.status()

        thread = threading.Thread(target=self._loop, name=f"login-import-{self.session_id}", daemon=True)
        self._thread = thread
        thread.start()
        return self.status()

    def _loop(self) -> None:
        failures = 0
        while not self._stop.is_set():
            try:
                self.poll_once()
                if failures:
                    failures = 0
                    with self._lock:
                        self.fail_count = 0
            except CDPError as exc:
                # 页面切换 / 导航中会短暂不可求值，属正常，不终止；
                # 但连续失败说明浏览器真的没了，必须让面板看到 error。
                failures += 1
                with self._lock:
                    self.last_error = str(exc)
                    self.fail_count = failures
                    if failures >= _MAX_POLL_FAILURES:
                        self.state = "error"
                        self.message = (
                            f"连续 {failures} 次读取失败，浏览器可能已关闭：{self.last_error}"
                        )
                if failures >= _MAX_POLL_FAILURES:
                    break
            except Exception as exc:  # noqa: BLE001
                with self._lock:
                    self.last_error = f"{type(exc).__name__}: {exc}"
                    self.state = "error"
                    self.message = f"轮询异常：{self.last_error}"
                break
            self._stop.wait(self.poll_interval)

        with self._lock:
            if self.state not in ("error", "stopped"):
                self.state = "stopped"
                self.message = "导入会话已结束"

    def stop(self) -> dict:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=max(3.0, self.poll_interval * 3))
        self._cleanup_browser()
        with self._lock:
            if self.state != "error":
                self.state = "stopped"
                self.message = "导入会话已结束，浏览器已关闭"
        return self.status()

    def _cleanup_browser(self) -> None:
        client = self._client
        if client is not None:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass
            self._client = None
        managed = self._managed
        if managed is not None:
            try:
                managed.stop()
            except Exception:  # noqa: BLE001
                pass
            self._managed = None
        self._proc = None

    # ------------------------------------------------------------------- 抓取

    def _read_local_storage(self) -> dict[str, str]:
        """读取当前页 localStorage；优先页面脚本，失败退回 DOMStorage 域。"""
        client = self._client
        if client is None:
            raise CDPError("浏览器会话不存在")

        items: dict[str, str] = {}
        try:
            raw = client.evaluate(_DUMP_JS)
            if isinstance(raw, dict) and "__error" not in raw:
                items = {str(k): str(v) for k, v in raw.items()}
        except CDPError:
            items = {}

        if not items:
            state = client.page_state() or {}
            origin = str(state.get("origin") or "")
            if origin and origin != "null":
                try:
                    items = client.dom_storage_items(origin)
                except CDPError:
                    items = {}
        return items

    def poll_once(self) -> list[dict]:
        """轮询一次，返回本次新导入的账号。"""
        with self._lock:
            client = self._client
            state = self.state
        if client is None or state not in ("starting", "waiting_login"):
            return []

        items = self._read_local_storage()
        self.poll_count += 1
        if not items:
            return []

        page_url = ""
        try:
            page_url = str((client.page_state() or {}).get("href") or "")
        except CDPError:
            page_url = ""

        token, token_key = pick_local_storage_value(
            items, TOKEN_KEY_CANDIDATES, matcher=looks_like_token_key
        )
        if not token:
            return []

        # P0-9 settle 稳定窗口（对照 turb-register 的 settle 思路）：抓到候选后
        # 继续观察，值变化则采用最新值并继续观察，稳定一窗后才入库 —— 防止把
        # 登录过程中尚未写完的半截凭据入库。变化链有兜底上限（5 窗），
        # 到点时已有候选 → 用当前候选照常入库，不空手而归。
        device_id, device_key = pick_local_storage_value(
            items, DEVICE_KEY_CANDIDATES, matcher=looks_like_device_key
        )
        if self.settle_seconds > 0:
            chain_deadline = time.monotonic() + max(self.settle_seconds * 5, 1.0)
            while time.monotonic() < chain_deadline:
                time.sleep(self.settle_seconds)
                re_items = self._read_local_storage()
                re_token, re_key = pick_local_storage_value(
                    re_items, TOKEN_KEY_CANDIDATES, matcher=looks_like_token_key
                )
                if not re_token or re_token == token:
                    break
                token, token_key = re_token, re_key
                device_id, device_key = pick_local_storage_value(
                    re_items, DEVICE_KEY_CANDIDATES, matcher=looks_like_device_key
                )

        if not self._snapshot_done:
            self._write_snapshot(items, page_url, token_key, device_key)

        # P2.5 第二批 D2：登录态 cookie 一并抓取，供 BrowserContext 池灌入
        cookies: list[dict] = []
        with self._lock:
            client = self._client
        if client is not None:
            cookies = _capture_chatglm_cookies(client)

        if self.store.has_token(token):
            with self._lock:
                if "已登录账号已导入" not in self.message and not self.captures:
                    self.message = "检测到已登录账号，但它已在 token.txt 中；可登出后换下一个账号"
            return []

        added = self.store.add_token(token)
        if not added:
            return []

        entry = self.store.record(
            token,
            device_id=device_id,
            source="browser-login",
            label=f"登录导入 {now_iso()}",
            extra={
                "token_key": token_key,
                "device_key": device_key,
                "page_url": page_url,
                "cookies": cookies,
            },
        )
        tokens = self.store.load_tokens()
        cap = Capture(
            index=len(tokens) - 1,
            fingerprint=entry.fingerprint,
            token_masked=mask_token(token),
            device_id=device_id,
            token_key=token_key,
            device_key=device_key,
        )
        with self._lock:
            self.captures.append(cap)
            self.message = (
                f"已导入第 {len(self.captures)} 个账号（{cap.token_masked}）。"
                "可继续登出并登录下一个账号，或点「结束导入」"
            )
        return [cap.to_dict()]

    def _write_snapshot(
        self, items: dict[str, str], page_url: str, token_key: str, device_key: str
    ) -> None:
        """落盘一次 localStorage 结构快照，仅供诊断键名用（值已脱敏）。"""
        self._snapshot_done = True
        if self.snapshot_dir is None:
            return
        try:
            self.snapshot_dir.mkdir(parents=True, exist_ok=True)
            sensitive = ("token", "cookie", "session", "secret", "auth", "key", "deid", "deid")
            view = {}
            for key, value in items.items():
                low = key.lower()
                if any(word in low for word in sensitive):
                    view[key] = f"<{mask_token(value)} len={len(value)}>"
                else:
                    view[key] = value if len(value) <= 120 else value[:120] + "…"
            payload = {
                "captured_at": now_iso(),
                "page_url": page_url,
                "token_key_hit": token_key,
                "device_key_hit": device_key,
                "key_count": len(items),
                "keys": sorted(items.keys()),
                "values": view,
            }
            path = self.snapshot_dir / f"localstorage-snapshot-{self.session_id}.json"
            path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------- 状态

    def status(self) -> dict:
        with self._lock:
            alive = self._proc is not None and self._proc.poll() is None
            return {
                "session_id": self.session_id,
                "state": self.state,
                "message": self.message,
                "browser": self.browser_name,
                "debug_port": self.port,
                "profile_dir": str(self.profile_dir),
                "poll_count": self.poll_count,
                "fail_count": self.fail_count,
                "browser_alive": alive,
                "last_error": self.last_error,
                "captured_count": len(self.captures),
                "captured": [c.to_dict() for c in self.captures],
                "restart_required": len(self.captures) > 0,
                "note": (
                    "token.txt 已更新，但服务在启动时读取账号列表 —— "
                    "需重启中转服务新账号才会生效"
                ),
            }


# ------------------------------------------------------------------ 粘贴导入


def import_from_text(store: TokenStore, text: str) -> dict:
    """从粘贴的文本里提取 token / device_id 并入库。

    兜底路径：当浏览器自动化不便使用（远程桌面、无 GUI、只想贴一条）时用。
    能识别裸 token、DevTools 键值对、JSON 片段、.env 风格赋值。
    """
    found = extract_candidates(text)
    tokens: list[str] = found["tokens"]
    devices: list[str] = found["devices"]

    added: list[dict] = []
    skipped: list[dict] = []
    for idx, token in enumerate(tokens):
        if store.has_token(token):
            skipped.append({"token_masked": mask_token(token), "reason": "已存在于 token.txt"})
            continue
        if not store.add_token(token):
            skipped.append({"token_masked": mask_token(token), "reason": "写入失败或重复"})
            continue
        # 单个 token 配单个 device_id；多 token 时按顺序配对，多余的不猜
        device_id = devices[idx] if idx < len(devices) else ""
        entry = store.record(
            token,
            device_id=device_id,
            source="paste",
            label=f"粘贴导入 {now_iso()}",
            extra={"raw_length": len(text)},
        )
        added.append(
            {
                "index": len(store.load_tokens()) - 1,
                "fingerprint": entry.fingerprint,
                "token_masked": mask_token(token),
                "device_id": device_id,
            }
        )

    return {
        "added": added,
        "skipped": skipped,
        "device_id_found": len(devices),
        "stats": store.stats(),
        "restart_required": bool(added),
    }


__all__ = [
    "CHATGLM_HOME",
    "Capture",
    "LoginImportSession",
    "import_from_text",
]
