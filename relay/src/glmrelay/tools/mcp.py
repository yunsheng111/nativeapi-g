"""MCP（Model Context Protocol）stdio 客户端工具（P4 模式 B 扩展）。

把用户在配置里显式列出的 MCP 服务器（JSON-RPC 2.0 over stdio，换行分隔
JSON，无 Content-Length 帧）接入内置工具运行时：每个 MCP 工具注册成
``mcp__{server}__{tool}`` 形态的 ToolSpec，handler 经模块级单例 MCPManager
转发给对应服务器子进程。

启用语义（与内置工具物理隔离原则的差异，属有意放宽）：
  - **配置即启用** —— 用户显式列出 MCP 服务器本身就是显式选择信任该服务器
    提供的全部工具，因此 MCP 工具不要求再进 GLM_BUILTIN_TOOLS 名单；
  - ``GLM_MCP_TOOLS`` glob 白名单（默认 "*"，支持 ``mcp__fs__*`` 形态）用于
    在已信任的服务器内进一步收窄暴露面，被过滤的工具完全不注册；
  - 某台服务器启动/握手失败只影响它自己的工具（warning 日志记录原因），
    不抛给 registry 构建，也不影响其他服务器。

进程与并发模型：
  - 每台服务器一个子进程 + 两个 daemon 线程（stdout 按行读进 queue 供按 id
    匹配响应；stderr 攒最近若干行用于错误报告）；Windows 下 CREATE_NO_WINDOW
    不弹新控制台；
  - 同一服务器的请求串行化（每服务器一把锁）：stdio 是单通道，并发请求的
    响应 id 会交叉，串行最稳；交叉到达的旧响应按 id 暂存，等对应请求取走。

生命周期取舍：服务器进程死亡（poll 非 None / 写管道断裂 / stdout EOF）后
标记 dead，后续调用直接报「MCP 服务器 {name} 已退出」，**不自动重启** ——
进程内做重启策略（退避/上限）容易把故障服务器变成重启风暴；服务重启即
恢复全部连接，重启节奏交给运维。``GLM_MCP_START_TIMEOUT_SECONDS`` 覆盖
启动+握手+tools/list 的整体预算，``GLM_MCP_TIMEOUT_SECONDS`` 控制单次工具
调用，超时与一切失败一律 raise ValueError，不伪装成成功。
"""

from __future__ import annotations

import atexit
import fnmatch
import itertools
import json
import logging
import os
import queue
import re
import subprocess
import threading
import time
from collections import OrderedDict, deque
from typing import Callable

from .registry import ToolSpec

_logger = logging.getLogger("glmrelay.tools.mcp")

# 与 config.py 的默认值保持一致（config 侧属性缺失/非法时以此兜底）
DEFAULT_TOOLS_PATTERN = "*"
DEFAULT_CALL_TIMEOUT_SECONDS = 30.0
DEFAULT_START_TIMEOUT_SECONDS = 15.0

_PROTOCOL_VERSION = "2024-11-05"
_CLIENT_INFO = {"name": "glm2api", "version": "1.0"}

# 交叉暂存响应的上限：超时放弃后迟到的响应最多积这么多，防内存缓慢增长
_PENDING_MAX = 32
# stderr 只攒最近若干行：够错误报告用即可，不无限积攒
_STDERR_TAIL_LINES = 10
# 错误报告里带出的 stderr 行数与单行长度上限
_STDERR_REPORT_LINES = 5
_STDERR_LINE_MAX_CHARS = 200


# ------------------------------------------------------------------ 连接

class _ServerConnection:
    """一台 MCP 服务器子进程的连接：读写泵线程 + 按 id 匹配的请求。

    request/notify 要求调用方已持有 ``self.lock``（同一服务器的请求串行化
    由上层负责），本类内部不做可重入加锁。
    """

    def __init__(self, name: str, proc: subprocess.Popen) -> None:
        self.name = name
        self.proc = proc
        self.lock = threading.Lock()
        self.queue: queue.Queue = queue.Queue()
        self.stderr_tail: deque = deque(maxlen=_STDERR_TAIL_LINES)
        self.dead = False
        self.tools: list | None = None  # tools/list 缓存（进程生命周期内不重拉）
        self._id_counter = itertools.count(1)
        self._pending: OrderedDict = OrderedDict()  # 交叉到达的响应暂存（id -> message）

    # ------------------------------------------------------------- 泵线程

    def start_pump_threads(self) -> None:
        threading.Thread(target=self._pump_stdout, name="mcp-stdout-" + self.name, daemon=True).start()
        threading.Thread(target=self._pump_stderr, name="mcp-stderr-" + self.name, daemon=True).start()

    def _pump_stdout(self) -> None:
        try:
            for raw in iter(self.proc.stdout.readline, b""):
                line = raw.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    message = json.loads(line)
                except json.JSONDecodeError:
                    continue  # 服务器混进 stdout 的非 JSON 行（横幅/日志）：丢弃
                if isinstance(message, dict):
                    self.queue.put(message)
        except (OSError, ValueError):
            pass  # 管道随进程退出被关闭：由 EOF 哨兵唤醒等待方
        finally:
            self.queue.put(None)

    def _pump_stderr(self) -> None:
        try:
            for raw in iter(self.proc.stderr.readline, b""):
                text = raw.decode("utf-8", errors="replace").strip()
                if text:
                    self.stderr_tail.append(text)
        except (OSError, ValueError):
            pass

    # ------------------------------------------------------------- 协议

    def notify(self, method: str, params: dict | None) -> None:
        """发通知（无 id，服务器不应回应答）。要求已持有 self.lock。"""
        payload = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        self._write(payload)

    def request(self, method: str, params: dict | None, timeout: float) -> dict:
        """发请求并阻塞等匹配 id 的响应。要求已持有 self.lock。

        notifications 与服务器主动发起的请求（sampling 等）直接丢弃；
        其他 id 的响应暂存进 _pending 供后续请求取走 —— 超时放弃后迟到的
        响应不会卡死或污染后续请求。
        """
        if self.dead or self.proc.poll() is not None:
            self.dead = True
            raise ValueError(self.dead_message())
        req_id = next(self._id_counter)
        payload = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            payload["params"] = params
        self._write(payload)
        deadline = time.monotonic() + max(float(timeout), 0.05)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError(
                    "MCP 服务器 {0} 请求超时({1}s): {2}".format(self.name, timeout, method)
                )
            try:
                message = self.queue.get(timeout=remaining)
            except queue.Empty:
                raise ValueError(
                    "MCP 服务器 {0} 请求超时({1}s): {2}".format(self.name, timeout, method)
                ) from None
            if message is None:  # stdout EOF 哨兵：进程已退出
                self.dead = True
                raise ValueError(self.dead_message())
            if "method" in message:
                continue  # 服务器发来的通知/请求：P4 不支持双向请求，丢弃
            mid = message.get("id")
            if mid is None:
                continue  # 无 id 的畸形消息：丢弃
            if mid == req_id:
                error = message.get("error")
                if isinstance(error, dict):
                    raise ValueError(
                        "MCP 服务器 {0} 返回错误: {1}".format(self.name, error.get("message") or error)
                    )
                return message
            self._pending[mid] = message
            while len(self._pending) > _PENDING_MAX:
                self._pending.popitem(last=False)

    def _write(self, payload: dict) -> None:
        data = json.dumps(payload, ensure_ascii=False) + "\n"
        try:
            self.proc.stdin.write(data.encode("utf-8"))
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError, ValueError) as exc:
            # ValueError: 写已关闭的管道；BrokenPipeError/OSError: 进程已死
            self.dead = True
            raise ValueError(self.dead_message()) from exc

    # ------------------------------------------------------------- 状态

    def dead_message(self) -> str:
        text = "MCP 服务器 {0} 已退出".format(self.name)
        tail = self.stderr_tail_text()
        if tail:
            text += "\n最近 stderr:\n" + tail
        return text

    def stderr_tail_text(self) -> str:
        lines = [line[:_STDERR_LINE_MAX_CHARS] for line in list(self.stderr_tail)[-_STDERR_REPORT_LINES:]]
        return "\n".join(lines)

    def terminate(self) -> None:
        """进程清理：先关 stdin 让服务器优雅退出，再 terminate/kill 兜底。"""
        self.dead = True
        proc = self.proc
        try:
            if proc.stdin is not None:
                proc.stdin.close()
        except OSError:
            pass
        if proc.poll() is None:
            try:
                proc.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                pass
        if proc.poll() is None:
            try:
                proc.terminate()
            except OSError:
                pass
            try:
                proc.wait(timeout=1.5)
            except subprocess.TimeoutExpired:
                pass
        if proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass
            try:
                proc.wait(timeout=1.5)
            except subprocess.TimeoutExpired:
                pass
        for stream in (proc.stdout, proc.stderr):
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass


def _connect(name: str, command: str, args: list, env: dict | None) -> _ServerConnection:
    """拉起一台 MCP 服务器子进程并启动读写泵线程。"""
    merged_env = None
    if env:
        # 继承本进程环境再叠加用户配置：MCP 服务器普遍依赖 PATH/SystemRoot 等系统变量
        merged_env = os.environ.copy()
        merged_env.update({str(k): str(v) for k, v in env.items()})
    popen_kwargs: dict = {}
    if os.name == "nt":
        # Windows 下不弹新控制台（服务运行在后台会话时尤其必要）
        popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.Popen(
            [command] + [str(a) for a in (args or [])],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=merged_env,
            **popen_kwargs,
        )
    except OSError as exc:
        raise ValueError("无法启动 MCP 服务器 {0}: {1}".format(name, exc)) from exc
    connection = _ServerConnection(name, proc)
    connection.start_pump_threads()
    return connection


def _result_text(server_name: str, result: dict) -> str:
    """tools/call 结果解析：content 数组里 type=="text" 的 text 用换行拼接。

    isError==True 视为工具失败，把错误文本作为异常信息抛出 —— 失败不伪装。
    """
    parts: list[str] = []
    content = result.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(str(item.get("text", "")))
    if result.get("isError"):
        message = "\n".join(part for part in parts if part)
        raise ValueError(
            message or "MCP 服务器 {0} 报告工具失败（未提供错误文本）".format(server_name)
        )
    if not parts:
        return "(MCP 工具无文本输出)"
    return "\n".join(parts)


# ------------------------------------------------------------------ 管理器

class MCPManager:
    """全部 MCP 服务器连接的持有者（模块级单例，atexit 统一清理）。

    连接表与失败表由 _lock 保护；单台服务器内部的请求串行由连接自身的
    lock 承担。ensure_server 把「连接+握手+tools/list」整体放在 _lock 内
    串行完成 —— 构建期的一次性成本，换取无重复拉起竞态的最简实现。
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._states: dict[str, _ServerConnection] = {}
        self._failed: dict[str, str] = {}
        self._closed = False

    def ensure_server(self, name: str, command: str, args: list, env: dict | None,
                      start_timeout: float) -> list:
        """懒启动：连接 + 握手 + tools/list，工具清单缓存（进程内不重拉）。

        失败（含本进程内的历史失败）raise ValueError，由调用方决定跳过；
        本方法不重试 —— 服务重启即恢复，重启策略交给运维。
        """
        with self._lock:
            if self._closed:
                raise ValueError("MCPManager 已关闭，无法再连接服务器: {0}".format(name))
            state = self._states.get(name)
            if state is not None:
                return state.tools or []
            if name in self._failed:
                raise ValueError(
                    "MCP 服务器 {0} 启动失败（本进程内不再重试）: {1}".format(name, self._failed[name])
                )
            state = None
            try:
                state = _connect(name, command, args, env)
                with state.lock:
                    deadline = time.monotonic() + max(float(start_timeout), 0.1)
                    state.request(
                        "initialize",
                        {
                            "protocolVersion": _PROTOCOL_VERSION,
                            "capabilities": {},
                            "clientInfo": _CLIENT_INFO,
                        },
                        max(deadline - time.monotonic(), 0.1),
                    )
                    # initialized 是通知（无 id）：发完即视为握手完成
                    state.notify("notifications/initialized", {})
                    listing = state.request("tools/list", {}, max(deadline - time.monotonic(), 0.1))
                result = listing.get("result")
                tools = result.get("tools") if isinstance(result, dict) else None
                if tools is None:
                    tools = []
                if not isinstance(tools, list):
                    raise ValueError("tools/list 返回了非数组 tools 字段")
                state.tools = tools
            except Exception as exc:
                if state is not None:
                    state.terminate()  # 半启动的进程不留孤儿
                self._failed[name] = str(exc)
                raise ValueError("MCP 服务器 {0} 启动/握手失败: {1}".format(name, exc)) from exc
            self._states[name] = state
            _logger.info("MCP 服务器已连接 name=%s tools=%d", name, len(tools))
            return tools

    def call_tool(self, server_name: str, tool_name: str, arguments: dict,
                  timeout: float = DEFAULT_CALL_TIMEOUT_SECONDS) -> str:
        """转发 tools/call 并把结果解析为纯文本；一切失败 raise ValueError。"""
        with self._lock:
            if self._closed:
                raise ValueError("MCPManager 已关闭")
            state = self._states.get(server_name)
        if state is None:
            raise ValueError("MCP 服务器未连接: {0}".format(server_name))
        with state.lock:
            message = state.request(
                "tools/call",
                {"name": tool_name, "arguments": dict(arguments or {})},
                timeout,
            )
        result = message.get("result")
        if not isinstance(result, dict):
            raise ValueError("MCP 服务器 {0} 对 tools/call 未返回 result".format(server_name))
        return _result_text(server_name, result)

    def shutdown(self) -> None:
        """atexit 钩子：terminate 全部子进程（短超时后 kill），幂等可重入。"""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            states = list(self._states.values())
            self._states.clear()
        for state in states:
            try:
                state.terminate()
            except Exception:  # noqa: BLE001  退出清理不抛错，避免干扰解释器收尾
                _logger.debug("MCP 服务器清理异常 name=%s", state.name, exc_info=True)


_MANAGER: MCPManager | None = None
_MANAGER_LOCK = threading.Lock()


def get_mcp_manager() -> MCPManager:
    """模块级单例：进程内所有 MCP 连接集中在一个 manager，atexit 统一清理。"""
    global _MANAGER
    with _MANAGER_LOCK:
        if _MANAGER is None:
            manager = MCPManager()
            atexit.register(manager.shutdown)
            _MANAGER = manager
        return _MANAGER


# ------------------------------------------------------------------ 命名与过滤

def _clean_name(raw: str) -> str:
    """注册名片段清洗：只保留字母数字下划线连字符，其余替换为下划线。"""
    return re.sub(r"[^a-zA-Z0-9_-]", "_", str(raw))


def _registered_name(server_name: str, tool_name: str) -> str:
    return "mcp__{0}__{1}".format(_clean_name(server_name), _clean_name(tool_name))


def _dedupe_name(base: str, used: set) -> str:
    """跨服务器清洗后重名时加序号后缀，保证 registry 注册名唯一。"""
    if base not in used:
        return base
    index = 2
    while "{0}_{1}".format(base, index) in used:
        index += 1
    return "{0}_{1}".format(base, index)


def _parse_patterns(raw) -> list:
    """GLM_MCP_TOOLS 解析：空白/逗号分隔的多个 glob，空值回落 "*"。"""
    text = DEFAULT_TOOLS_PATTERN if raw is None else str(raw).strip()
    if not text:
        text = DEFAULT_TOOLS_PATTERN
    patterns = [p for p in re.split(r"[,\s]+", text) if p]
    return patterns or [DEFAULT_TOOLS_PATTERN]


def _match_any(name: str, patterns: list) -> bool:
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)


def _setting_float(config, attr: str, default: float) -> float:
    raw = getattr(config, attr, None)
    if raw is None:
        return default
    try:
        return float(raw)
    except (TypeError, ValueError):
        _logger.warning("配置 %s 不是数字(%r)，回落默认 %s", attr, raw, default)
        return default


# ------------------------------------------------------------------ 工厂构建

def _make_factory(manager: MCPManager, server_name: str, tool_name: str, spec_name: str,
                  description: str, parameters: dict, fallback_timeout: float) -> Callable[[object], ToolSpec]:
    def factory(config=None) -> ToolSpec:
        timeout = fallback_timeout
        if config is not None:
            raw = getattr(config, "glm_mcp_timeout_seconds", None)
            if raw is not None:
                try:
                    timeout = float(raw)
                except (TypeError, ValueError):
                    pass

        def handler(args: dict, session: object) -> str:
            return manager.call_tool(server_name, tool_name, args, timeout)

        return ToolSpec(
            name=spec_name,
            description="[MCP:{0}] {1}".format(server_name, description),
            parameters=parameters,
            handler=handler,
            readonly=False,  # MCP 工具副作用未知：一律按可写对待
        )

    return factory


def build_mcp_factories(config) -> dict:
    """按配置启动 MCP 服务器并生成工具工厂表：注册名 -> (config) -> ToolSpec。

    - 服务器在构建期懒启动并缓存 tools/list；启动/握手失败的服务器打
      warning 后整体跳过（不抛给 registry 构建，也不影响其他服务器）；
    - GLM_MCP_TOOLS glob 过滤在此完成，被过滤的工具完全不注册（物理隔离）。
    """
    servers = getattr(config, "glm_mcp_servers", None) or []
    if not servers:
        return {}  # 未配置 MCP：零开销，不创建 manager
    patterns = _parse_patterns(getattr(config, "glm_mcp_tools", None))
    start_timeout = _setting_float(config, "glm_mcp_start_timeout_seconds", DEFAULT_START_TIMEOUT_SECONDS)
    call_timeout = _setting_float(config, "glm_mcp_timeout_seconds", DEFAULT_CALL_TIMEOUT_SECONDS)
    manager = get_mcp_manager()
    factories: dict = {}
    used_names: set = set()
    for entry in servers:
        if not isinstance(entry, dict):
            _logger.warning("glm_mcp_servers 含非 dict 项（已跳过）: %r", entry)
            continue
        server_name = str(entry.get("name") or "").strip()
        command = str(entry.get("command") or "").strip()
        if not server_name or not command:
            _logger.warning("MCP 服务器项缺少 name/command（已跳过）: %r", entry)
            continue
        args = entry.get("args") or []
        if not isinstance(args, list):
            args = [args]
        env = entry.get("env") or None
        try:
            tools = manager.ensure_server(server_name, command, args, env, start_timeout)
        except Exception as exc:  # noqa: BLE001  单服务器失败不阻断整体构建
            _logger.warning(
                "MCP 服务器不可用 name=%s error=%s（该服务器工具全部不注册）", server_name, exc
            )
            continue
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            tool_name = str(tool.get("name") or "").strip()
            if not tool_name:
                continue
            base_name = _registered_name(server_name, tool_name)
            if not _match_any(base_name, patterns):
                continue  # 白名单外：直接不出现
            spec_name = _dedupe_name(base_name, used_names)
            used_names.add(spec_name)
            description = str(tool.get("description") or "").strip() or "(服务器未提供描述)"
            parameters = tool.get("inputSchema")
            if not isinstance(parameters, dict):
                # MCP 的 inputSchema 本身就是 JSON Schema：直接透传，缺失时给空对象 schema
                parameters = {"type": "object", "properties": {}}
            factories[spec_name] = _make_factory(
                manager, server_name, tool_name, spec_name, description, parameters, call_timeout
            )
            _logger.info("注册 MCP 工具 name=%s server=%s tool=%s", spec_name, server_name, tool_name)
    return factories


__all__ = ["MCPManager", "build_mcp_factories", "get_mcp_manager"]
