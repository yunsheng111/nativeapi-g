"""账号存储层：token.txt（底座格式）+ accounts.json（旁挂元数据）。

为什么分两个文件：
    底座 `config.load_refresh_tokens()` 会跳过空行与 `#` 注释行，看起来支持注释，
    但 `glm_auth._persist_refresh_token()` 轮换 token 时是
    `"\\n".join(tokens) + "\\n"` **整文件重写** —— 它用的是已解析过的裸 token 列表，
    注释会被静默冲掉。因此 token.txt 必须保持「一行一个裸 token」，任何元数据
    （device_id、备注、导入时间、配额统计）都只能放旁挂的 accounts.json。

落盘一律走「临时文件 + os.replace」保证原子性，避免服务正在读时读到半截文件。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

# 登录后刷新令牌可能落在这些键上（按优先级）
TOKEN_KEY_CANDIDATES: tuple[str, ...] = (
    "chatglm_refresh_token",
    "refresh_token",
    "refreshToken",
    "chatglm_token",
)

# 设备标识：chatglm.cn 未登录时也有 `chatglm-deid`，它对应底座的 device_id 概念。
# 导入时一并抓取，避免账号与其设备身份错配反而更容易触发风控。
DEVICE_KEY_CANDIDATES: tuple[str, ...] = (
    "chatglm-deid",
    "chatglm_deid",
    "device_id",
    "deviceId",
)

_TOKEN_SHAPE = re.compile(r"^[A-Za-z0-9_\-\.]{20,4096}$")

# key / value 扫描。要点（都是实测踩出来的）：
#   - 键名两侧可能有引号：{"chatglm_refresh_token":"xxx"}
#   - 分隔符不一定是 : 或 =，DevTools 复制出来的是制表符
#   - 值的长度下限放到 4，因为 device_id 可能很短（如 8 位）；
#     长度下限按键类型再分别过滤，不能一刀切
_KEY_VALUE = re.compile(
    r"""(?:^|[\s,{;\[])          # 前置分隔：行首/空白/逗号/花括号/分号/方括号
        "?(?P<key>[A-Za-z0-9_\-\.]{4,64})"?
        \s*
        (?:[:=]|\t+|\s{2,})      # 分隔：冒号、等号、制表符、或多空格
        \s*
        "?(?P<val>[A-Za-z0-9_\-\.]{4,4096})"?
    """,
    re.VERBOSE,
)

_TOKEN_KEY_EXACT = {k.lower() for k in TOKEN_KEY_CANDIDATES}
_DEVICE_KEY_EXACT = {k.lower() for k in DEVICE_KEY_CANDIDATES}

# token 值太短几乎必然是误匹配（比如时间戳、布尔值）
_TOKEN_MIN_LEN = 16
_DEVICE_MIN_LEN = 4


def looks_like_token_key(key: str) -> bool:
    """键名是否是 refresh token。除精确名单外做模糊匹配。

    必须模糊匹配的原因：用户可能从 `.env` 里复制 `GLM_REFRESH_TOKEN=xxx`，
    或上游改键名成 `xx_refresh_token`，精确名单会全部漏掉。
    """
    low = key.lower()
    if low in _TOKEN_KEY_EXACT:
        return True
    return ("refresh" in low and "token" in low) or low.endswith("refreshtoken")


def looks_like_device_key(key: str) -> bool:
    low = key.lower()
    if low in _DEVICE_KEY_EXACT:
        return True
    return "deid" in low or low in ("deviceid", "device-id") or low.endswith("_device_id")


def extract_candidates(text: str) -> dict[str, list[str]]:
    """从任意粘贴文本里抽取 refresh_token / device_id 候选。

    支持用户从各种地方复制的内容：
    - 裸 token 本身
    - DevTools Application 面板的键值对（键值之间是制表符）
    - JSON / JS 对象片段（`"refresh_token": "xxx"`）
    - `.env` 风格的 `GLM_REFRESH_TOKEN=xxx`
    - localStorage dump / cURL 回显
    """
    tokens: list[str] = []
    devices: list[str] = []
    if not text:
        return {"tokens": [], "devices": []}

    for match in _KEY_VALUE.finditer(text):
        key = match.group("key")
        val = match.group("val")
        if len(val) < _DEVICE_MIN_LEN:
            continue
        if looks_like_token_key(key) and len(val) >= _TOKEN_MIN_LEN:
            tokens.append(val)
        elif looks_like_device_key(key):
            devices.append(val)

    # 退路一：整段文本本身就是一串 token
    stripped = text.strip()
    if not tokens and "\n" not in stripped and _TOKEN_SHAPE.match(stripped):
        tokens.append(stripped)

    # 退路二：逐行找像 token 的行（跳过明显的键名行）
    if not tokens:
        for line in stripped.splitlines():
            line = line.strip().strip('",')
            if not line or ":" in line or "=" in line or "\t" in line:
                continue
            if _TOKEN_SHAPE.match(line):
                tokens.append(line)

    def dedupe(items: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for item in items:
            if item not in seen:
                seen.add(item)
                out.append(item)
        return out

    return {"tokens": dedupe(tokens), "devices": dedupe(devices)}


def pick_local_storage_value(
    items: dict[str, str],
    candidates: tuple[str, ...],
    matcher: "Callable[[str], bool] | None" = None,
) -> tuple[str, str]:
    """从 localStorage 字典里挑出目标键。返回 (值, 命中的键名)。

    先精确匹配候选键（大小写不敏感）；命中不到且给了 matcher 时，再退化到
    模糊匹配 —— matcher 必须是类型相关的谓词（token 用 looks_like_token_key），
    否则会把 device_id 当成 token 抓走。
    """
    if not items:
        return "", ""
    lowered = {k.lower(): (k, v) for k, v in items.items()}

    for cand in candidates:
        hit = lowered.get(cand.lower())
        if hit and hit[1]:
            return hit[1], hit[0]

    if matcher is not None:
        for key, value in items.items():
            if value and matcher(key):
                return value, key
    return "", ""


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")


def mask_token(token: str, head: int = 6, tail: int = 4) -> str:
    if not token:
        return ""
    if len(token) <= head + tail:
        return "*" * len(token)
    return f"{token[:head]}{'*' * 8}{token[-tail:]}"


def fingerprint(token: str) -> str:
    """稳定的短指纹。用于旁挂元数据的键 —— token 本身会轮换，不能直接当键。"""
    return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()[:16]


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-", suffix=".swap")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


@dataclass
class AccountMeta:
    """旁挂元数据。按 token 指纹索引。"""

    fingerprint: str
    label: str = ""
    device_id: str = ""
    source: str = ""
    imported_at: str = ""
    last_seen_at: str = ""
    note: str = ""
    extra: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict) -> "AccountMeta":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        kwargs = {k: v for k, v in data.items() if k in known}
        kwargs.setdefault("fingerprint", "")
        return cls(**kwargs)


class TokenStore:
    """token.txt 的读写（底座兼容格式）+ 元数据旁挂。"""

    def __init__(self, token_file: Path, meta_file: Path | None = None) -> None:
        self.token_file = Path(token_file)
        self.meta_file = Path(meta_file) if meta_file else self.token_file.with_name("accounts.json")

    # ------------------------------------------------------------ token.txt

    def load_tokens(self) -> list[str]:
        """复刻底座解析规则：跳空行、跳 # 注释。"""
        if not self.token_file.exists():
            return []
        try:
            raw = self.token_file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return []
        tokens: list[str] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            tokens.append(line)
        return tokens

    def has_token(self, token: str) -> bool:
        needle = token.strip()
        return any(existing.strip() == needle for existing in self.load_tokens())

    def add_token(self, token: str) -> bool:
        """追加一个 token。已存在则返回 False，不重复写入。"""
        token = token.strip()
        if not token:
            return False
        tokens = self.load_tokens()
        if any(existing.strip() == token for existing in tokens):
            return False
        tokens.append(token)
        _atomic_write(self.token_file, "\n".join(tokens) + "\n")
        return True

    def remove_token(self, token: str) -> bool:
        needle = token.strip()
        tokens = self.load_tokens()
        remaining = [t for t in tokens if t.strip() != needle]
        if len(remaining) == len(tokens):
            return False
        _atomic_write(self.token_file, ("\n".join(remaining) + "\n") if remaining else "")
        return True

    def find_token_by_fingerprint(self, fp: str) -> str:
        """按指纹反查 token。指纹是 sha256 前缀，只能遍历比对。"""
        for token in self.load_tokens():
            if fingerprint(token) == fp:
                return token
        return ""

    def remove_by_fingerprint(self, fp: str) -> bool:
        token = self.find_token_by_fingerprint(fp)
        if not token:
            return False
        removed = self.remove_token(token)
        if removed:
            meta = self.load_meta()
            if meta.pop(fp, None) is not None:
                self.save_meta(meta)
        return removed

    def update_meta_by_fingerprint(self, fp: str, **fields: object) -> bool:
        meta = self.load_meta()
        entry = meta.get(fp)
        if entry is None:
            return False
        for name, value in fields.items():
            if hasattr(entry, name):
                setattr(entry, name, value)
            else:
                entry.extra[name] = value
        self.save_meta(meta)
        return True

    def replace_all(self, tokens: list[str]) -> None:
        cleaned = [t.strip() for t in tokens if t.strip()]
        _atomic_write(self.token_file, ("\n".join(cleaned) + "\n") if cleaned else "")

    # ---------------------------------------------------------- accounts.json

    def load_meta(self) -> dict[str, AccountMeta]:
        if not self.meta_file.exists():
            return {}
        try:
            data = json.loads(self.meta_file.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return {}
        records = data.get("accounts", data) if isinstance(data, dict) else {}
        out: dict[str, AccountMeta] = {}
        if isinstance(records, dict):
            for key, value in records.items():
                if isinstance(value, dict):
                    out[str(key)] = AccountMeta.from_dict(value)
        return out

    def save_meta(self, meta: dict[str, AccountMeta]) -> None:
        payload = {
            "version": 1,
            "updated_at": now_iso(),
            "accounts": {k: asdict(v) for k, v in meta.items()},
        }
        _atomic_write(self.meta_file, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")

    def record(self, token: str, **fields: object) -> AccountMeta:
        """写入/更新一条元数据。"""
        meta = self.load_meta()
        key = fingerprint(token)
        entry = meta.get(key) or AccountMeta(fingerprint=key, imported_at=now_iso())
        if not entry.imported_at:
            entry.imported_at = now_iso()
        entry.last_seen_at = now_iso()
        for name, value in fields.items():
            if value in (None, ""):
                continue
            if hasattr(entry, name):
                setattr(entry, name, value)
            else:
                entry.extra[name] = value
        meta[key] = entry
        self.save_meta(meta)
        return entry

    # ------------------------------------------------------------- 组合视图

    def list_accounts(self) -> list[dict]:
        """给管理面板用的脱敏视图。"""
        tokens = self.load_tokens()
        meta = self.load_meta()
        rows: list[dict] = []
        for index, token in enumerate(tokens):
            key = fingerprint(token)
            entry = meta.get(key)
            rows.append(
                {
                    "index": index,
                    "fingerprint": key,
                    "token_masked": mask_token(token),
                    "token_length": len(token),
                    "label": (entry.label if entry else "") or f"账号 #{index + 1}",
                    "device_id": (entry.device_id if entry else ""),
                    "source": (entry.source if entry else "manual"),
                    "imported_at": (entry.imported_at if entry else ""),
                    "last_seen_at": (entry.last_seen_at if entry else ""),
                    "note": (entry.note if entry else ""),
                }
            )
        return rows

    def stats(self) -> dict:
        tokens = self.load_tokens()
        rows = self.list_accounts()
        return {
            "token_file": str(self.token_file),
            "meta_file": str(self.meta_file),
            "token_count": len(tokens),
            "with_device_id": sum(1 for r in rows if r["device_id"]),
            "imported": sum(1 for r in rows if r["source"] == "browser-login"),
            "pasted": sum(1 for r in rows if r["source"] == "paste"),
        }
