"""设备身份注册表：把 accounts.json 里的真实 chatglm-deid 接进底座 glm_auth。

底座 GLMAccessTokenManager 通过类级钩子 device_id_resolver 调到这里的
resolve_device_id。依赖方向是 glmrelay → glm2api（扩展层感知底座，反向不成立），
底座只看到一个 ``(token) -> str`` 的函数。

为什么按指纹索引：token.txt 里的 token 会被上游轮换重写，accounts.json 用
sha256 前 16 位指纹做键，与底座的 token 值解耦（见 store.fingerprint）。
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

from glm2api.config import GUEST_REFRESH_TOKEN_MARKER, parse_dotenv

from .store import TokenStore, fingerprint

_lock = threading.Lock()
_cache: dict[str, str] = {}
_cache_mtime: float | None = None


def _token_file() -> Path:
    """与底座 load_config 同构的 token 文件定位。

    顺序：进程环境变量 > cwd/.env 里的 GLM_TOKEN_FILE > 缺省 cwd/token.txt。
    相对路径一律相对 cwd —— 底座 load_config() 无参调用时 env 文件就是 cwd/.env，
    两者天然一致。
    """
    raw = os.environ.get("GLM_TOKEN_FILE")
    if not raw:
        try:
            raw = parse_dotenv(Path.cwd() / ".env").get("GLM_TOKEN_FILE", "")
        except Exception:
            raw = ""
    path = Path(raw or "token.txt")
    return path if path.is_absolute() else Path.cwd() / path


def _load_device_map() -> dict[str, str]:
    """指纹 -> 真实设备标识。accounts.json 的 mtime 变化即重载（登录导入后无需重启）。"""
    global _cache, _cache_mtime
    meta_file = _token_file().with_name("accounts.json")
    try:
        mtime: float | None = meta_file.stat().st_mtime
    except OSError:
        mtime = None
    with _lock:
        if mtime is None:
            _cache = {}
        elif mtime != _cache_mtime:
            meta = TokenStore(_token_file()).load_meta()
            _cache = {fp: m.device_id for fp, m in meta.items() if m.device_id}
        _cache_mtime = mtime
        return _cache


def resolve_device_id(token: str) -> str:
    """底座钩子入口：按 token 指纹返回导入时抓到的真实 chatglm-deid。

    无记录、游客标记 token、元数据文件缺失时一律返回空串 —— 由底座回退
    稳定随机值。解析失败向上抛异常，由底座统一记日志并回退。
    """
    if not token or token.strip() == GUEST_REFRESH_TOKEN_MARKER:
        return ""
    return _load_device_map().get(fingerprint(token), "")
