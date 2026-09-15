"""管理面板扩展端点（账号导入 / 账号池）。

设计：底座 server.py 里只插一行调用，其余全在这里，保证同步上游时冲突面最小。

复用底座的鉴权与响应工具（`_check_admin` / `_read_admin_body` /
`_write_admin_json` / `_api_ok` / `_api_err`）。这些都是下划线私有名，跨模块
引用的确不够干净，但比复制一份鉴权逻辑安全得多 —— 鉴权一旦有两份实现，
迟早会漏一处。
"""

from __future__ import annotations

import threading
from http import HTTPStatus

from glm2api.admin import (
    _api_err,
    _api_ok,
    _check_admin,
    _read_admin_body,
    _write_admin_json,
)
from glm2api.config import AppConfig

from .accounts import LoginImportSession, TokenStore, import_from_text

# 导入会话使用的调试端口。与用户日常浏览器的 9222 错开，避免互相抢占。
LOGIN_DEBUG_PORT = 9333
PREFIX = "/admin/api/accounts"


def _store_for(config: AppConfig) -> TokenStore:
    """token.txt 与旁挂元数据都放在 .env 同级的项目目录里。"""
    return TokenStore(token_file=config.token_file_path)


def _project_dir(config: AppConfig):
    return config.env_file_path.parent


class _SessionManager:
    """同一时刻只允许一个导入会话（同时开多个受控浏览器没有意义，还会抢端口）。"""

    _lock = threading.RLock()
    _session: LoginImportSession | None = None

    @classmethod
    def start(cls, config: AppConfig, preferred: str | None, headless: bool) -> LoginImportSession:
        with cls._lock:
            if cls._session is not None:
                state = cls._session.status()["state"]
                if state in ("starting", "waiting_login"):
                    return cls._session
            project = _project_dir(config)
            session = LoginImportSession(
                store=_store_for(config),
                profile_dir=project / ".glmrelay" / "login-profile",
                port=LOGIN_DEBUG_PORT,
                preferred=preferred,
                headless=headless,
                snapshot_dir=project / "artifacts" / "localstorage-snapshots",
            )
            cls._session = session
        session.start()
        return session

    @classmethod
    def current(cls) -> LoginImportSession | None:
        with cls._lock:
            return cls._session

    @classmethod
    def stop(cls) -> LoginImportSession | None:
        with cls._lock:
            session = cls._session
        if session is not None:
            session.stop()
        return session


def handle_admin_ext(handler, method: str, path: str, config: AppConfig) -> bool:
    """扩展管理端点分发。返回 True 表示请求已处理，调用方应直接 return。"""
    if not path.startswith(PREFIX):
        return False

    if not _check_admin(handler):
        _write_admin_json(handler, _api_err("Unauthorized"), HTTPStatus.UNAUTHORIZED)
        return True

    store = _store_for(config)

    # ── GET /admin/api/accounts ──────────────────────────────────────────
    if method == "GET" and path == PREFIX:
        session = _SessionManager.current()
        payload = {
            "accounts": store.list_accounts(),
            "stats": store.stats(),
            "session": session.status() if session else None,
        }
        _write_admin_json(handler, _api_ok(payload))
        return True

    # ── POST /admin/api/accounts/import/start ────────────────────────────
    if method == "POST" and path == f"{PREFIX}/import/start":
        body = _read_admin_body(handler)
        preferred = str(body.get("browser") or "").strip().lower() or None
        if preferred not in (None, "edge", "chrome"):
            _write_admin_json(handler, _api_err("browser 只能是 edge 或 chrome"), HTTPStatus.BAD_REQUEST)
            return True
        headless = bool(body.get("headless", False))
        try:
            session = _SessionManager.start(config, preferred, headless)
        except Exception as exc:  # noqa: BLE001
            _write_admin_json(
                handler, _api_err(f"启动导入会话失败: {type(exc).__name__}: {exc}"), HTTPStatus.INTERNAL_SERVER_ERROR
            )
            return True
        _write_admin_json(handler, _api_ok({"session": session.status()}))
        return True

    # ── GET /admin/api/accounts/import/status ────────────────────────────
    if method == "GET" and path == f"{PREFIX}/import/status":
        session = _SessionManager.current()
        _write_admin_json(
            handler,
            _api_ok(
                {
                    "session": session.status() if session else None,
                    "accounts": store.list_accounts(),
                    "stats": store.stats(),
                }
            ),
        )
        return True

    # ── POST /admin/api/accounts/import/stop ─────────────────────────────
    if method == "POST" and path == f"{PREFIX}/import/stop":
        session = _SessionManager.stop()
        _write_admin_json(
            handler,
            _api_ok(
                {
                    "session": session.status() if session else None,
                    "accounts": store.list_accounts(),
                    "stats": store.stats(),
                }
            ),
        )
        return True

    # ── POST /admin/api/accounts/paste ───────────────────────────────────
    if method == "POST" and path == f"{PREFIX}/paste":
        body = _read_admin_body(handler)
        text = str(body.get("text") or "")
        if not text.strip():
            _write_admin_json(handler, _api_err("粘贴内容为空"), HTTPStatus.BAD_REQUEST)
            return True
        result = import_from_text(store, text)
        result["accounts"] = store.list_accounts()
        _write_admin_json(handler, _api_ok(result))
        return True

    # ── POST /admin/api/accounts/delete ──────────────────────────────────
    if method == "POST" and path == f"{PREFIX}/delete":
        body = _read_admin_body(handler)
        fp = str(body.get("fingerprint") or "").strip()
        if not fp:
            _write_admin_json(handler, _api_err("缺少 fingerprint"), HTTPStatus.BAD_REQUEST)
            return True
        removed = store.remove_by_fingerprint(fp)
        if not removed:
            _write_admin_json(handler, _api_err("未找到该账号"), HTTPStatus.NOT_FOUND)
            return True
        _write_admin_json(handler, _api_ok({"removed": fp, "accounts": store.list_accounts(), "stats": store.stats()}))
        return True

    # ── POST /admin/api/accounts/update ──────────────────────────────────
    if method == "POST" and path == f"{PREFIX}/update":
        body = _read_admin_body(handler)
        fp = str(body.get("fingerprint") or "").strip()
        if not fp:
            _write_admin_json(handler, _api_err("缺少 fingerprint"), HTTPStatus.BAD_REQUEST)
            return True
        fields = {}
        for key in ("label", "note", "device_id"):
            if key in body:
                fields[key] = str(body[key])
        if not fields:
            _write_admin_json(handler, _api_err("没有可更新的字段"), HTTPStatus.BAD_REQUEST)
            return True
        if not store.update_meta_by_fingerprint(fp, **fields):
            _write_admin_json(handler, _api_err("未找到该账号"), HTTPStatus.NOT_FOUND)
            return True
        _write_admin_json(handler, _api_ok({"accounts": store.list_accounts()}))
        return True

    return False


__all__ = ["LOGIN_DEBUG_PORT", "PREFIX", "handle_admin_ext"]
