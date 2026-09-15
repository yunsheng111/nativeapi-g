"""最小 WebSocket 客户端 —— 只实现 CDP 所需子集。

标准库没有 WebSocket，而 CDP 的 Runtime.evaluate / DOMStorage 只能走 WebSocket。
这里手写握手与帧编解码，避免为「读一个 refresh_token」引入第三方依赖。

支持范围（够 CDP 用，不做通用实现）：
- 客户端握手，含 Sec-WebSocket-Accept 校验
- 文本帧收发（客户端发送强制掩码，符合 RFC 6455）
- 7 / 16 / 64 位三种载荷长度
- 分片续帧（continuation）
- ping / pong / close 控制帧

明确不支持：扩展协商（permessage-deflate）、非阻塞 IO、多路复用。
"""

from __future__ import annotations

import base64
import hashlib
import os
import socket
import struct
from urllib.parse import urlparse

_OP_CONT = 0x0
_OP_TEXT = 0x1
_OP_BIN = 0x2
_OP_CLOSE = 0x8
_OP_PING = 0x9
_OP_PONG = 0xA

_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# 单条消息上限，防止被异常数据撑爆内存（CDP 消息远小于此）
_MAX_MESSAGE_BYTES = 64 * 1024 * 1024


class WebSocketError(RuntimeError):
    """WebSocket 层错误。"""


class WebSocket:
    """极简 WebSocket 客户端（同步阻塞）。"""

    def __init__(self, url: str, timeout: float = 30.0) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "ws":
            raise WebSocketError(f"只支持 ws:// 协议，收到 {parsed.scheme!r}")
        self._host = parsed.hostname or "127.0.0.1"
        self._port = parsed.port or 80
        resource = parsed.path or "/"
        if parsed.query:
            resource += "?" + parsed.query
        self._resource = resource
        self._timeout = timeout
        self._sock: socket.socket | None = None
        self._buffer = bytearray()
        self._closed = False

    # ------------------------------------------------------------------ 连接

    def connect(self) -> None:
        sock = socket.create_connection((self._host, self._port), timeout=self._timeout)
        sock.settimeout(self._timeout)
        self._sock = sock

        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET {self._resource} HTTP/1.1\r\n"
            f"Host: {self._host}:{self._port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        sock.sendall(request.encode("ascii"))

        header = self._read_http_header()
        status_line = header.split("\r\n", 1)[0]
        if " 101 " not in status_line and not status_line.endswith(" 101"):
            raise WebSocketError(f"WebSocket 握手失败: {status_line}")

        expected = base64.b64encode(
            hashlib.sha1((key + _WS_GUID).encode("ascii")).digest()
        ).decode("ascii")
        for line in header.split("\r\n")[1:]:
            if line.lower().startswith("sec-websocket-accept:"):
                got = line.split(":", 1)[1].strip()
                if got != expected:
                    raise WebSocketError("Sec-WebSocket-Accept 校验失败，可能不是标准 WebSocket 服务")
                break

    def _read_http_header(self) -> str:
        assert self._sock is not None
        raw = bytearray()
        while not raw.endswith(b"\r\n\r\n"):
            chunk = self._sock.recv(1)
            if not chunk:
                raise WebSocketError("握手期间连接被关闭")
            raw += chunk
            if len(raw) > 64 * 1024:
                raise WebSocketError("握手响应头异常过大")
        return raw.decode("latin-1")

    # ------------------------------------------------------------------ 收发

    def send_text(self, text: str) -> None:
        self._send_frame(_OP_TEXT, text.encode("utf-8"))

    def recv_text(self) -> str | None:
        """读取一条完整文本消息。返回 None 表示对端已关闭。"""
        fragments = bytearray()
        while True:
            fin, opcode, payload = self._read_frame()

            if opcode == _OP_PING:
                self._send_frame(_OP_PONG, payload)
                continue
            if opcode == _OP_PONG:
                continue
            if opcode == _OP_CLOSE:
                self._send_frame(_OP_CLOSE, payload[:2] if len(payload) >= 2 else b"")
                self._closed = True
                return None
            if opcode in (_OP_TEXT, _OP_BIN, _OP_CONT):
                fragments.extend(payload)
                if len(fragments) > _MAX_MESSAGE_BYTES:
                    raise WebSocketError("消息超过上限，疑似协议错乱")
            else:
                raise WebSocketError(f"未知 opcode: {opcode}")

            if fin:
                # CDP 只会发文本；二进制帧按 UTF-8 解码同样可读
                return fragments.decode("utf-8", "replace")

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        if self._sock is None:
            raise WebSocketError("尚未连接")
        header = bytearray()
        header.append(0x80 | opcode)  # FIN=1

        length = len(payload)
        if length < 126:
            header.append(0x80 | length)  # 0x80 = 已掩码
        elif length <= 0xFFFF:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", length))

        mask = os.urandom(4)
        header.extend(mask)
        masked = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
        self._sock.sendall(bytes(header) + masked)

    def _read_frame(self) -> tuple[bool, int, bytes]:
        head = self._recv_exact(2)
        b0, b1 = head[0], head[1]
        fin = bool(b0 & 0x80)
        opcode = b0 & 0x0F
        masked = bool(b1 & 0x80)
        length = b1 & 0x7F

        if length == 126:
            length = struct.unpack("!H", self._recv_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._recv_exact(8))[0]

        mask = self._recv_exact(4) if masked else None
        payload = self._recv_exact(length) if length else b""
        if mask:
            payload = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
        return fin, opcode, payload

    def _recv_exact(self, n: int) -> bytes:
        assert self._sock is not None
        while len(self._buffer) < n:
            chunk = self._sock.recv(max(4096, n - len(self._buffer)))
            if not chunk:
                raise WebSocketError("连接已被对端关闭")
            self._buffer.extend(chunk)
        data = bytes(self._buffer[:n])
        del self._buffer[:n]
        return data

    # ------------------------------------------------------------------ 关闭

    def close(self) -> None:
        if self._sock is None:
            return
        if not self._closed:
            try:
                self._send_frame(_OP_CLOSE, struct.pack("!H", 1000))
            except Exception:  # noqa: BLE001
                pass
        try:
            self._sock.close()
        except Exception:  # noqa: BLE001
            pass
        finally:
            self._sock = None
            self._closed = True

    def __enter__(self) -> "WebSocket":
        self.connect()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
