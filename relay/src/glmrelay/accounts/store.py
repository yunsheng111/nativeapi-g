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
import threading
from dataclasses import asdict, dataclass, field, replace
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
    # 别名链指针（B2）：本指纹的 token 被上游轮换成新 token 后，指向新 token 的
    # 指纹。链方向永远是 旧 → 新，resolve_device_id 据此做防环回溯。
    rotated_to: str = ""
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
        # 运行统计旁挂（P2-5）：与 accounts.json 同级的独立文件 —— 统计是每请求
        # 更新的运行时数据，不与身份元数据混写（身份文件只在导入/轮换时变）。
        self.stats_file = self.token_file.with_name("accounts_stats.json")
        self._stats_lock = threading.Lock()

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

    def rotate_token_alias(self, old_token: str, new_token: str) -> "AccountMeta | None":
        """token 轮换别名登记（CAS 幂等）：把旧指纹条目整体继承给新指纹。

        为什么需要：底座轮换 refresh_token 时是整文件重写 token.txt，accounts.json
        的设备身份条目仍挂在旧 token 指纹上 —— 不登记别名的话，首次自动轮换后
        resolve_device_id 就查不到新 token，真实 chatglm-deid 解析断链，重启后
        回退稳定随机值。本方法形成单向别名链（旧.rotated_to = 新指纹）：

            fp_old --rotated_to--> fp_new1 --rotated_to--> fp_new2 ...

        链上每个新条目都完整继承旧条目（device_id / label / imported_at / extra
        等），只有 fingerprint 换新、last_seen_at 刷新、rotated_to 清空（新条目
        是链尾）；旧条目保留原 device_id 并追加 rotated_to 指针。一次 save_meta
        同时落盘新旧两条，原子性由 _atomic_write 保证。

        返回值：
            AccountMeta  新指纹条目（本次继承生成，或 CAS 命中已存在的）；
            None         旧指纹无条目，无从继承 —— 调用方应自行 record 全新条目。

        幂等性：新旧同指纹（没真轮换）直接返回现有条目不写盘；新指纹条目已
        存在视为重复登记，直接返回它，不产生新条目。
        """
        old_token = (old_token or "").strip()
        new_token = (new_token or "").strip()
        if not old_token or not new_token:
            return None
        old_fp = fingerprint(old_token)
        new_fp = fingerprint(new_token)
        meta = self.load_meta()
        if old_fp == new_fp:
            # 没有真轮换（上游回显了同一个 token），无事可做
            return meta.get(new_fp)
        # CAS：新条目已存在 → 之前登记过，幂等返回，不重写盘
        existing_new = meta.get(new_fp)
        if existing_new is not None:
            return existing_new
        old_entry = meta.get(old_fp)
        if old_entry is None:
            return None
        # 复制旧条目全部字段（replace 浅拷贝，extra 必须单独特拷防两条目共享可变字典）
        new_entry = replace(
            old_entry,
            fingerprint=new_fp,
            rotated_to="",
            last_seen_at=now_iso(),
            extra=dict(old_entry.extra),
        )
        old_entry.rotated_to = new_fp
        meta[new_fp] = new_entry
        meta[old_fp] = old_entry
        self.save_meta(meta)
        return new_entry

    # ---------------------------------------------------------- accounts_stats.json

    def load_stats(self) -> dict[str, dict]:
        """读运行统计旁挂：token 指纹 -> 统计快照 dict。文件缺失/损坏返回空。"""
        if not self.stats_file.exists():
            return {}
        try:
            data = json.loads(self.stats_file.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return {}
        records = data.get("stats", data) if isinstance(data, dict) else {}
        if not isinstance(records, dict):
            return {}
        return {str(key): dict(value) for key, value in records.items() if isinstance(value, dict)}

    def save_stats(self, stats: dict[str, dict]) -> None:
        payload = {"version": 1, "updated_at": now_iso(), "stats": stats}
        _atomic_write(self.stats_file, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")

    def _stats_key(self, account_index: int) -> str | None:
        """统计键：token 行存在用指纹（与账号内容绑定）；行数不足（游客槽 /
        env 单账号）回退槽位键 —— 游客身份每进程随机，但「槽位统计」视角
        仍连续。行序后续扩容后 idx 键的旧数据可能失配，统计非身份关键数据，
        可接受；负数 index 无意义返回 None。
        """
        tokens = self.load_tokens()
        if 0 <= account_index < len(tokens):
            return fingerprint(tokens[account_index])
        if account_index >= 0:
            return f"idx-{account_index}"
        return None

    def record_stats_for_index(self, account_index: int, snapshot: dict) -> None:
        """底座 stats_persist_listener 入口（P2-5）：index 翻译成统计键后落盘。

        锁内读改写防并发丢更新。
        """
        with self._stats_lock:
            key = self._stats_key(account_index)
            if key is None:
                return
            stats = self.load_stats()
            stats[key] = dict(snapshot)
            self.save_stats(stats)

    def stats_for_index(self, account_index: int) -> dict:
        """底座 stats_restore_provider 入口：按 index 回填落盘快照。"""
        with self._stats_lock:
            key = self._stats_key(account_index)
            if key is None:
                return {}
            return self.load_stats().get(key, {})

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
