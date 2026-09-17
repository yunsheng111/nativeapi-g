"""内置 Shell 工具（P3 模式 B）：run_command，三道安全阀强制在执行路径上。

对照架构设计六章「安全阀不可绕」：
  1. 危险命令正则：check_shell_command 命中即拒绝（宁枉勿纵，防误触最后一道网）；
  2. 超时：超过 config.glm_shell_timeout_seconds 强制终止（默认 30s，可配置）；
  3. 输出上限：stdout+stderr 拼接后超 1MB 截断并注明。

run_command 默认不在启用名单内（物理隔离）—— 真正的边界是 registry 不注册它，
正则清单只是兜底。cwd 固定在沙箱根：命令的工作面与文件工具一致，模型无需
自己拼 cd。
"""

from __future__ import annotations

import subprocess
from typing import Callable

from .registry import ToolSpec
from .safety import EXEC_OUTPUT_LIMIT_BYTES, check_shell_command, truncate_output


def _handle_run_command(config):
    def handler(args: dict, session: object) -> str:
        command = str(args.get("command", "") or "")
        reason = check_shell_command(command)
        if reason:
            raise ValueError(reason)
        timeout = float(config.glm_shell_timeout_seconds)
        try:
            proc = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                timeout=timeout,
                cwd=config.glm_tool_fs_root,
            )
        except subprocess.TimeoutExpired:
            # 超时不是静默杀掉：显式报给模型，让它决定换路或缩短命令
            raise ValueError("命令超时 {0}s 已终止".format(timeout))
        stdout = proc.stdout.decode("utf-8", errors="replace") if proc.stdout else ""
        stderr = proc.stderr.decode("utf-8", errors="replace") if proc.stderr else ""
        segments: list[str] = []
        if stdout:
            segments.append(stdout)
        if stderr:
            segments.append("[stderr]\n" + stderr)
        combined = "\n".join(segments) if segments else "(无输出)"
        text, _truncated = truncate_output(combined, EXEC_OUTPUT_LIMIT_BYTES)
        return text + "\n\n[退出码: {0}]".format(proc.returncode)

    return handler


def _factory_run_command(config) -> ToolSpec:
    return ToolSpec(
        name="run_command",
        description=(
            "在沙箱根目录执行一条 Shell 命令并返回 stdout/stderr 与退出码"
            "（stderr 以 [stderr] 段标注，输出超过 1MB 截断）。"
            "三道安全阀：危险命令特征（递归删除/关机/格式化等）命中即拒绝；"
            "超过配置超时（默认 30s）强制终止并报错。"
            "参数：command（必填，完整命令行字符串）。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "要执行的命令行（由系统 shell 解释）"},
            },
            "required": ["command"],
        },
        handler=_handle_run_command(config),
        readonly=False,
    )


TOOL_FACTORIES: dict[str, Callable[[object], ToolSpec]] = {
    "run_command": _factory_run_command,
}
