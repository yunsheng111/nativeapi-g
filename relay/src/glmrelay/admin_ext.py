"""管理面板扩展端点（账号导入 / 账号池）。

设计：底座 server.py 里只插一行调用，其余全在这里，保证同步上游时冲突面最小。

复用底座的鉴权与响应工具（`_check_admin` / `_read_admin_body` /
`_write_admin_json` / `_api_ok` / `_api_err`）。这些都是下划线私有名，跨模块
引用的确不够干净，但比复制一份鉴权逻辑安全得多 —— 鉴权一旦有两份实现，
迟早会漏一处。
"""

from __future__ import annotations

import logging
import threading
from http import HTTPStatus

from glm2api.admin import (
    ApiKeyStore,
    _api_err,
    _api_ok,
    _check_admin,
    _persist_api_keys,
    _read_admin_body,
    _write_admin_json,
    normalize_key_mode,
)
from glm2api.config import AppConfig
from glm2api.services.glm_auth import GLMAccessTokenManager

from .accounts import LoginImportSession, TokenStore, import_from_text

# 导入会话使用的调试端口。与用户日常浏览器的 9222 错开，避免互相抢占。
LOGIN_DEBUG_PORT = 9333
PREFIX = "/admin/api/accounts"
TOOLS_PREFIX = "/admin/api/tools"


def _runtime_account_stats() -> list[dict]:
    """运行时配额视图（P1-b）。auth 未创建（服务启动前）时返回空列表。"""
    manager = GLMAccessTokenManager.last_instance
    return manager.get_account_stats() if manager is not None else []


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
    # ── P5-b 工具策略：/admin/api/tools 前缀（鉴权与账号池同一道门）─────
    if path.startswith(TOOLS_PREFIX):
        if not _check_admin(handler):
            _write_admin_json(handler, _api_err("Unauthorized"), HTTPStatus.UNAUTHORIZED)
            return True
        if method == "GET" and path == TOOLS_PREFIX:
            _write_admin_json(handler, _api_ok(_tools_snapshot(handler, config)))
            return True
        if method == "POST" and path == f"{TOOLS_PREFIX}/key-mode":
            return _handle_key_mode(handler)
        return False  # 未匹配的 tools 子路径交还底座走 404

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
            "runtime": _runtime_account_stats(),
        }
        _write_admin_json(handler, _api_ok(payload))
        return True

    # ── POST /admin/api/accounts/probe ───────────────────────────────────
    if method == "POST" and path == f"{PREFIX}/probe":
        from .accounts.health import probe_once

        logger = logging.getLogger("glmrelay.admin")
        probed = probe_once(logger)
        _write_admin_json(handler, _api_ok({"probed": probed, "runtime": _runtime_account_stats()}))
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


def _tools_snapshot(handler, config: AppConfig) -> dict:
    """GET /admin/api/tools 的策略快照。

    工厂表按物理隔离原则延迟 import（只在 GET 分支的调用路径上加载，不占
    import 期）；MCP 只读运行态（绝不在这里 ensure_server 拉起子进程，快照
    不应有副作用）；技能扫描直接复用 tools.skills 的发现函数，保证面板与
    skills_list 工具看到的是同一份解析结果。
    """
    from .tools import mcp as _mcp
    from .tools import skills as _skills
    from .tools.browser import TOOL_FACTORIES as _BROWSER_FACTORIES
    from .tools.fs import TOOL_FACTORIES as _FS_FACTORIES
    from .tools.shell import TOOL_FACTORIES as _SHELL_FACTORIES
    from .tools.skills import TOOL_FACTORIES as _SKILL_FACTORIES
    from .tools.todo import TOOL_FACTORIES as _TODO_FACTORIES

    # ── 内置工具：五个静态工厂表合并（MCP 动态工具单独走 mcp 节）──────
    merged: dict = {}
    for table in (_FS_FACTORIES, _SHELL_FACTORIES, _TODO_FACTORIES, _BROWSER_FACTORIES, _SKILL_FACTORIES):
        merged.update(table)
    enabled_names = {str(name).strip() for name in config.glm_builtin_tools if str(name).strip()}
    builtin_tools = []
    for name in sorted(merged):
        # 工厂只构造 ToolSpec（handler 是未执行的闭包），无副作用
        spec = merged[name](config)
        builtin_tools.append({
            "name": name,
            "description": spec.description[:100],
            "readonly": bool(spec.readonly),
            "enabled": name in enabled_names,
        })

    # ── MCP：配置清单 + manager 运行态（_states 里已连接的才有存活信息）──
    servers_cfg = [s for s in (config.glm_mcp_servers or []) if isinstance(s, dict)]
    states: dict = {}
    if servers_cfg:
        states = getattr(_mcp.get_mcp_manager(), "_states", None) or {}
    mcp_servers = []
    for entry in servers_cfg:
        sname = str(entry.get("name") or "").strip()
        command_line = " ".join(
            [str(entry.get("command") or "")] + [str(a) for a in (entry.get("args") or [])]
        ).strip()
        state = states.get(sname)
        alive = None
        tool_count = 0
        if state is not None:
            alive = not (bool(state.dead) or state.proc.poll() is not None)
            tool_count = len(state.tools or [])
        mcp_servers.append({"name": sname, "command": command_line[:80], "alive": alive, "tool_count": tool_count})

    # 已注册的 mcp 工具名：按 build_mcp_factories 的同一套命名/glob/去重规则
    # 从已连接服务器的 tools/list 缓存推导，避免第二份注册逻辑
    registered_tools: list = []
    if servers_cfg and states:
        patterns = _mcp._parse_patterns(getattr(config, "glm_mcp_tools", None))
        used: set = set()
        for entry in servers_cfg:
            sname = str(entry.get("name") or "").strip()
            state = states.get(sname)
            for tool in (state.tools if state is not None else None) or []:
                if not isinstance(tool, dict):
                    continue
                tname = str(tool.get("name") or "").strip()
                if not tname:
                    continue
                base = _mcp._registered_name(sname, tname)
                if not _mcp._match_any(base, patterns):
                    continue
                final = _mcp._dedupe_name(base, used)
                used.add(final)
                registered_tools.append(final)
        registered_tools.sort()

    # ── 技能：复用工具模块的扫描（候选目录含固定目录，先到先得语义一致）──
    skill_entries, skill_dirs = _skills._discover_skills(config)
    skills_payload = {
        "dirs": [str(d) for d in skill_dirs],
        "found": [
            {"name": e.name, "description": (e.description or "")[:80]}
            for e in skill_entries
        ],
    }

    settings = {
        "builtin_max_rounds": config.glm_builtin_max_rounds,
        "shell_timeout_seconds": config.glm_shell_timeout_seconds,
        "tool_fs_root": config.glm_tool_fs_root,
        "mcp_tools_glob": config.glm_mcp_tools,
        "skills_dirs": list(config.glm_skills_dirs),
        "browser_headless": bool(config.glm_tool_browser_headless),
        "browser_allow_private": bool(config.glm_tool_browser_allow_private),
    }

    return {
        "global_mode": config.glm_tool_mode,
        "builtin_tools": builtin_tools,
        "settings": settings,
        "mcp": {"configured": bool(servers_cfg), "servers": mcp_servers, "tools": registered_tools},
        "skills": skills_payload,
        "api_keys": handler._admin_api_key_store.list_all(),
    }


def _handle_key_mode(handler) -> bool:
    """POST /admin/api/tools/key-mode：改单个 API Key 的工具模式绑定。"""
    body = _read_admin_body(handler)
    name = str(body.get("name") or "").strip()
    if not name:
        _write_admin_json(handler, _api_err("缺少 name"), HTTPStatus.BAD_REQUEST)
        return True
    store: ApiKeyStore = handler._admin_api_key_store
    if store.get(name) is None:
        _write_admin_json(handler, _api_err(f"API Key '{name}' 不存在"), HTTPStatus.NOT_FOUND)
        return True
    # 非法值由 normalize_key_mode 回落「跟随全局」，与 P5-a 的宽容语义一致
    tool_mode = normalize_key_mode(body.get("tool_mode"))
    store.update(name, tool_mode=tool_mode)
    _persist_api_keys(handler)
    updated = store.get(name)
    _write_admin_json(handler, _api_ok(updated.to_dict(mask=True) if updated else {}, "已更新"))
    return True


__all__ = ["LOGIN_DEBUG_PORT", "PREFIX", "TOOLS_PREFIX", "handle_admin_ext"]
