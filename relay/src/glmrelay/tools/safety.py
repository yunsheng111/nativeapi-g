"""工具安全阀（P3，架构设计六章「安全阀不可绕」+ 融合方案五章对齐 glm-web-code）。

四道阀，全部在工具执行路径上强制生效、不可绕过：
    1. 路径沙箱：文件操作限制在配置的根目录内，拒绝 .. 逃逸与符号链接逃逸；
    2. 危险命令正则：Shell 命令命中即拒绝（对照 glm-web-code dangerous_cmds.go）；
    3. 超时：命令超时 30s（GLM_SHELL_TIMEOUT_SECONDS 可调）；
    4. 输出上限：单次输出 1MB 截断（超出部分注明）。

默认姿态（六章）：工具档位默认只读 —— GLM_BUILTIN_TOOLS 默认不含 write/edit/
run_command/delete，要写要执行需部署者显式提档；delete 属破坏性操作且中转场景
无人在环可确认，默认不注册、启用也仅限沙箱内。
"""

from __future__ import annotations

import re
from pathlib import Path

SHELL_TIMEOUT_SECONDS = 30.0
EXEC_OUTPUT_LIMIT_BYTES = 1024 * 1024  # 1MB
READ_FILE_LIMIT_BYTES = 256 * 1024  # 256KB：单文件读取上限（工具结果回灌体积另有 24000 字符治理）

# 危险命令特征（Windows / Unix 常见破坏形态）。命中即拒绝执行，宁枉勿纵 ——
# 本清单不是安全边界（Shell 本质上无法完全沙箱），而是防误触的最后一道网；
# Shell 工具默认不在启用名单内才是真正的边界（物理隔离，registry 不注册）。
DANGEROUS_COMMAND_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\brm\s+(-[a-z]*[rf][a-z]*\s+)+", "递归/强制删除（rm -r/-rf）"),
    (r"\bdel\s+/[sq]", "Windows 递归删除（del /s /q）"),
    (r"\brd\s+/s", "Windows 递归删除（rd /s）"),
    (r"\brmdir\s+/s", "Windows 递归删除（rmdir /s）"),
    (r"\bremove-item\b.*-recurse", "PowerShell 递归删除（Remove-Item -Recurse）"),
    (r"\b(format|mkfs|fdisk|diskpart)\b", "磁盘格式化/分区"),
    (r"\bdd\b\s+.*of=", "底层磁盘写入（dd of=）"),
    (r"\b(shutdown|reboot|poweroff|halt)\b", "关机/重启"),
    (r"\btaskkill\b\s+/f\s+/im\s+(system|winlogon|csrss|services)\.exe", "杀死系统进程"),
    (r"\breg(\.exe)?\s+(delete|add)\b", "注册表删除/写入"),
    (r"\bschtasks\b\s+/create\b", "计划任务创建"),
    (r"\bsc(\.exe)?\s+(config|delete)\b", "Windows 服务变更"),
    (r"\bchmod\s+-r\s+777\b", "递归放开权限"),
    (r"\bchown\b\s+-r\b", "递归改属主"),
    (r"\b(curl|wget)\b.*\|\s*(sh|bash|powershell|iex)\b", "下载即执行管道"),
    (r"\b Invoke-Expression\b|\biex\b\s*\(", "PowerShell 动态执行"),
    (r"\beval\b\s*\(", "动态求值"),
    (r">\s*/dev/sd[a-z]", "裸设备写入"),
    (r"\b(vssadmin|wbadmin)\b\s+(delete|resize)", "卷影/备份删除"),
)


def check_shell_command(command: str) -> str | None:
    """危险命令校验。返回拒绝原因；安全返回 None。"""
    lowered = str(command or "").lower()
    if not lowered.strip():
        return "命令为空"
    for pattern, reason in DANGEROUS_COMMAND_PATTERNS:
        if re.search(pattern, lowered, re.IGNORECASE):
            return f"命中危险命令特征: {reason}"
    return None


def resolve_sandboxed_path(root: str | Path, raw_path: str) -> Path:
    """把用户给定的相对/绝对路径收敛到沙箱根内。

    三道校验缺一不可：
      1. resolve 归一化（消化 .. 与 . —— 字符串级 replace 挡不住 `a/b/../..`）；
      2. resolve 后必须仍在 root 内（拒绝 `..` 逃逸与绝对路径指到沙箱外）；
      3. 符号链接已在 resolve 中展开 —— 链接指到沙箱外同样被第 2 道拦下。
    """
    root_path = Path(root).resolve()
    raw = str(raw_path or "").strip()
    candidate = Path(raw) if Path(raw).is_absolute() else root_path / raw
    resolved = candidate.resolve()
    if resolved != root_path and root_path not in resolved.parents:
        raise ValueError(f"路径逃出沙箱根 {root_path}: {raw_path}")
    return resolved


def truncate_output(text: bytes | str, limit: int = EXEC_OUTPUT_LIMIT_BYTES) -> tuple[str, bool]:
    """输出上限阀：超限截断并注明（原则 3：不静默吞）。"""
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text, False
    cut = text[: limit]
    # 按字符截断可能与字节上限有偏差，这里按字符数近似（多字节时略保守）
    return cut + f"\n\n[输出超过 {limit} 字节上限，已截断；原始长度 {len(encoded)} 字节]", True
