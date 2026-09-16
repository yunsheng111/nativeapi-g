"""上游 HTTP 传输 seam（P2）。

所有对上游的请求（token 刷新 / 对话流 / 图片流 / 会话删除 / 文件上传 / 图片下载）
必须经 open_upstream 发出。默认实现是底座原有 urllib 栈，行为与历史版本一致；
P2.5 的 CDP 同源 fetch 传输通过 set_upstream_transport 注入，做到「换传输不换协议」。

seam 同时是唯一的上游 SSRF 防线：目标必须 http/https，且解析后的 IP 不得是
环回 / 链路本地（含云元数据 169.254.169.254）/ 未指定地址；私网地址默认同样
阻断（自建内网上游可经 GLM_TRANSPORT_BLOCK_PRIVATE=false 放宽）。
若只换对话流不统一入口，同一 device_id 会同时暴露 Python 与 Chrome 两种
TLS 指纹，比纯 urllib 更可疑（技术选型融合方案 10.8.1）。
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import urllib.request
from typing import Callable
from urllib.parse import urlsplit

_open: Callable[..., object] = urllib.request.urlopen
_DEFAULT_OPEN: Callable[..., object] = _open
_block_private: bool = True

# 请求级传输提示（P2.5）：每请求一线程，由 server 层解析 X-GLM2API-Transport
# 头与模型后缀后设置，routed opener 读取；优先级高于全局 GLM_TRANSPORT。
_hint = threading.local()

# RFC 2544 benchmark 段（198.18.0.0/15）：TUN 代理的 fake-IP 模式用它承载到公网的
# 连接，不指向任何真实内网服务 —— 从私网阻断中例外，否则代理环境下正常请求被打死。
_FAKEIP_NETWORKS = tuple(ipaddress.ip_network(n) for n in ("198.18.0.0/15",))


def _validate_target(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError(f"上游传输只允许 http/https 协议: {parts.scheme!r}")
    host = parts.hostname
    if not host:
        raise ValueError(f"上游目标缺少主机名: {url!r}")
    try:
        infos = socket.getaddrinfo(
            host,
            parts.port or (443 if parts.scheme == "https" else 80),
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror:
        return  # 解析失败交由真实请求抛出自然的网络错误
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified:
            raise ValueError(f"上游目标解析到禁止地址: {host} -> {ip}")
        if _block_private and ip.is_private and not any(ip in net for net in _FAKEIP_NETWORKS):
            raise ValueError(
                f"上游目标解析到私网地址（如确需访问内网上游，设置 GLM_TRANSPORT_BLOCK_PRIVATE=false）: {host} -> {ip}"
            )


def open_upstream(request: urllib.request.Request, timeout: float | None = None):
    _validate_target(str(request.full_url) if isinstance(request, urllib.request.Request) else str(request))
    return _open(request, timeout=timeout)


def set_upstream_transport(opener: Callable[..., object] | None) -> None:
    """替换上游传输实现（P2.5 注入点）。传 None 恢复默认 urllib 传输。"""
    global _open
    _open = opener if opener is not None else _DEFAULT_OPEN


def set_upstream_policy(block_private: bool | None = None) -> None:
    """调整目标校验策略（默认阻断私网）。"""
    global _block_private
    if block_private is not None:
        _block_private = block_private


def set_request_transport(name: str | None) -> None:
    """设置当前线程的传输提示（"cdp" / "urllib" / None=清除）。"""
    _hint.name = name


def current_request_transport() -> str | None:
    name = getattr(_hint, "name", None)
    return name if name in ("cdp", "urllib") else None
