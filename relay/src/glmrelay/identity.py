"""身份字段单一数据源 + 矛盾自检（F4 挂账项的观测性收口）。

本项目同时存在 urllib 与 CDP 两条上游传输。urllib 路径的 TLS/HTTP2 是
Python 栈，请求头却自称具体浏览器版本（UA=Edge 143）—— 这是已知指纹
矛盾（F4）。本模块把一次上游请求的身份字段收拢为 IdentityProfile 单一
数据源，并对已知矛盾点做离线自检：枚举矛盾 → 打 warning 日志，让矛盾
可观测、可回归（tools/check_riskctrl.py 的 I1 断言组守住这些文案与语义
不腐化）。

红线：只做自检与告警，绝不加伪装意图。不做指纹随机化、不做 GeoIP、
不自动"修正成更像真人"——减少伪装是 Agent 决策层的事，且在本项目里
是被明确否决的方向（少伪装 = 少被识别，见 browser/cdp_fetch.py 的
禁止头剔除设计：浏览器自动发真实值）。本模块唯一的产品是把矛盾说出口，
修正与否、如何修正由人拍板。
"""

from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass


@dataclass(frozen=True)
class IdentityProfile:
    """一次上游请求对外呈现的身份快照（只收自检需要的字段）。

    frozen：身份字段在请求生命周期内不该被改写，改写即制造新矛盾。
    """

    transport: str  # "urllib" / "cdp"
    device_id: str
    user_agent: str
    accept_language: str
    x_lang: str
    sec_ch_ua_platform: str


# F4 的判定基准：UA 自称这三家之一的具体版本号，即与 Python TLS 栈构成矛盾。
# Safari/Firefox 等不在挂账范围（F4 只针对当前实际发出的 Edge/Chrome 伪装值）。
_BROWSER_UA_RE = re.compile(r"(?:Edge|Edg|Chrome)/\d+", re.IGNORECASE)


def _header(headers: dict[str, str], name: str) -> str:
    """大小写不敏感取头。头集合来自 get_browser_headers（混合大小写键），缺省为空串。"""
    lowered = name.lower()
    for key, value in headers.items():
        if str(key).lower() == lowered:
            return str(value)
    return ""


def build_profile_from_headers(transport: str, device_id: str, headers: dict[str, str]) -> IdentityProfile:
    """从 get_browser_headers() 的输出构造身份快照。

    transport 与 device_id 由调用方传入（传输层与账号层各自持有，
    不在头集合里），其余四个字段从头里取。
    """
    return IdentityProfile(
        transport=transport,
        device_id=device_id,
        user_agent=_header(headers, "User-Agent"),
        accept_language=_header(headers, "Accept-Language"),
        x_lang=_header(headers, "X-Lang"),
        sec_ch_ua_platform=_header(headers, "Sec-Ch-Ua-Platform"),
    )


def validate_identity(profile: IdentityProfile) -> list[str]:
    """枚举已知矛盾点，返回中文矛盾描述列表；干净配置返回空列表。

    这是纯函数：不改状态、不做修正、不给修复建议之外的副作用。
    """
    conflicts: list[str] = []
    transport = (profile.transport or "").strip().lower()
    user_agent = profile.user_agent or ""

    # F4：urllib 传输的 TLS/HTTP2 是 Python 栈，UA 却自称具体浏览器版本
    if transport == "urllib" and _BROWSER_UA_RE.search(user_agent):
        conflicts.append(
            f"urllib 传输的 TLS/HTTP2 为 Python 栈，User-Agent 却自称具体浏览器版本（F4）： UA={user_agent}"
        )

    if not (profile.device_id or "").strip():
        conflicts.append("设备身份 device_id 为空")

    # 语言自洽：X-Lang 声明中文，Accept-Language 却不含 zh
    if (profile.x_lang or "").strip().lower() == "zh" and not (profile.accept_language or "").lower().startswith("zh"):
        conflicts.append(f"语言矛盾： X-Lang=zh 但 Accept-Language={profile.accept_language}")

    # 平台自洽：client hint 声明 Windows，UA 里却没有对应的 Windows NT 标记
    if "windows" in (profile.sec_ch_ua_platform or "").lower() and "windows nt" not in user_agent.lower():
        conflicts.append("平台矛盾： Sec-Ch-Ua-Platform=Windows 但 UA 无 Windows NT")

    # CDP 传输由真实浏览器发头，任何自带 UA 都说明 bridge 的禁止头剔除漏了
    # （见 cdp_fetch._FORBIDDEN_HEADER_KEYS）—— 这条是给 bridge 回归的信号
    if transport == "cdp" and (profile.user_agent or "").strip():
        conflicts.append("CDP 传输不应携带伪装 User-Agent（浏览器自动发真值，禁止头剔除应已移除）")

    return conflicts


# 同一 (transport, 矛盾文本) 只告警一次：上游请求是每账号高频路径，
# 重复告警只会刷屏、掩盖新矛盾。set + Lock 保证并发下恰好一条。
_warn_lock = threading.Lock()
_warned: set[tuple[str, str]] = set()


def warn_identity_conflicts(profile: IdentityProfile, logger: logging.Logger, account_tag: str = "") -> list[str]:
    """自检并逐条告警，返回完整矛盾列表（去重只影响日志，不影响返回值）。

    返回值始终是当次 validate_identity 的全量结果，供调用方直接计数或断言；
    是否落日志由 (transport, 矛盾文本) 去重集决定。
    """
    conflicts = validate_identity(profile)
    with _warn_lock:
        fresh = [c for c in conflicts if (profile.transport, c) not in _warned]
        _warned.update((profile.transport, c) for c in fresh)
    for conflict in fresh:
        logger.warning("身份自检矛盾 account=%s: %s", account_tag, conflict)
    return conflicts


def reset_identity_warnings() -> None:
    """清空告警去重集（测试用；生产运行期不调用）。"""
    with _warn_lock:
        _warned.clear()
