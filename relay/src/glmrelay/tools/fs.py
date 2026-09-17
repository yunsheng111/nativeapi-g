"""内置文件工具（P3 模式 B）：read/write/edit/list/grep/delete，全部操作收敛在路径沙箱内。

设计约束（架构设计六章「安全阀不可绕」）：
  - 所有 handler 收到的 path 一律先过 resolve_sandboxed_path 收敛到沙箱根内，
    ``..`` 逃逸 / 绝对路径越界 / 符号链接逃逸都在这一步被拒绝；
  - 失败不伪装成功：文件不存在、非唯一匹配等业务失败一律 raise ValueError，
    由 registry 统一转成 error 结果回灌给模型（模型可据此重试或换路）；
  - delete_file 属破坏性操作，默认不在启用名单（物理隔离，见 config.DEFAULT_BUILTIN_TOOLS）。

工厂形态：每个工具一个 ``_factory_xxx(config) -> ToolSpec``，由 TOOL_FACTORIES 暴露；
config 在构建 registry 时才绑定 —— 未启用工具不构造，沙箱根/限额随部署配置生效。
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Callable

from .registry import ToolSpec
from .safety import READ_FILE_LIMIT_BYTES, resolve_sandboxed_path

# grep 单行命中内容的回灌上限：防止超长行（minified js 等）撑爆工具结果体积
GREP_LINE_MAX_CHARS = 200
# grep 跳过超过该大小的文件：大文件逐行扫描既慢又容易顶到回灌上限
GREP_FILE_MAX_BYTES = 1024 * 1024


def _display_path(config, path: Path) -> str:
    """给模型看的活动路径：优先显示相对沙箱根的 posix 形态（跨平台一致、更短）。"""
    try:
        return path.relative_to(Path(config.glm_tool_fs_root).resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _parse_int_arg(value: object, name: str, default: int | None = None) -> int:
    """把模型传来的整数参数（JSON 里可能是字符串形态）安全转成 int。"""
    if value is None or (isinstance(value, str) and not value.strip()):
        if default is None:
            raise ValueError("缺少整数参数: {0}".format(name))
        return default
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError("参数 {0} 必须是整数: {1!r}".format(name, value)) from exc


# --------------------------------------------------------------- read_file

def _handle_read_file(config):
    def handler(args: dict, session: object) -> str:
        path = resolve_sandboxed_path(config.glm_tool_fs_root, args.get("path", ""))
        if not path.exists():
            raise ValueError("文件不存在: {0}".format(path))
        if path.is_dir():
            raise ValueError("目标是目录，read_file 仅支持文本文件（列目录请用 list_dir）: {0}".format(path))
        # 只多读 1 字节用于判定截断：不把整个大文件读进内存
        with open(path, "rb") as fh:
            data = fh.read(READ_FILE_LIMIT_BYTES + 1)
        byte_truncated = len(data) > READ_FILE_LIMIT_BYTES
        if byte_truncated:
            data = data[:READ_FILE_LIMIT_BYTES]
        lines = data.decode("utf-8", errors="replace").splitlines()
        total = len(lines)
        offset = _parse_int_arg(args.get("offset"), "offset", default=0)
        if offset < 0:
            raise ValueError("offset 不能为负数: {0}".format(offset))
        limit_raw = args.get("limit")
        limit = None
        if limit_raw is not None and str(limit_raw).strip() != "":
            limit = _parse_int_arg(limit_raw, "limit")
            if limit < 0:
                raise ValueError("limit 不能为负数: {0}".format(limit))
        window = lines[offset:] if offset else lines
        if limit is not None:
            window = window[:limit]
        if not window:
            return "(无内容: 文件为空或 offset={0} 超出总行数 {1})".format(offset, total)
        body = "\n".join(window)
        if byte_truncated:
            body += "\n\n[文件超过 {0} 字节读取上限，已截断]".format(READ_FILE_LIMIT_BYTES)
        return body

    return handler


def _factory_read_file(config) -> ToolSpec:
    return ToolSpec(
        name="read_file",
        description=(
            "读取沙箱内的文本文件，按行返回全文或指定行窗口。"
            "参数：path（必填，文件路径，相对沙箱根或沙箱内绝对路径）；"
            "offset（可选，起始行号，从 0 开始，默认 0）；"
            "limit（可选，最多返回的行数，默认全部）。"
            "文件超过 256KB 读取上限时在上限处截断并注明。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "要读取的文件路径（必须在沙箱内）"},
                "offset": {"type": "integer", "description": "起始行号（0 起），默认 0"},
                "limit": {"type": "integer", "description": "最多返回的行数，默认全部"},
            },
            "required": ["path"],
        },
        handler=_handle_read_file(config),
        readonly=True,
    )


# --------------------------------------------------------------- write_file

def _handle_write_file(config):
    def handler(args: dict, session: object) -> str:
        path = resolve_sandboxed_path(config.glm_tool_fs_root, args.get("path", ""))
        if path.is_dir():
            raise ValueError("目标是目录，不能作为文件写入: {0}".format(path))
        content = args.get("content")
        if content is None:
            content = ""
        data = str(content).encode("utf-8")
        # 覆盖写语义：父目录不存在则自动创建（仍在沙箱收敛路径之下）
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return "已写入 {0} 字节: {1}".format(len(data), _display_path(config, path))

    return handler


def _factory_write_file(config) -> ToolSpec:
    return ToolSpec(
        name="write_file",
        description=(
            "覆盖写入文本文件（父目录不存在时自动创建）。"
            "参数：path（必填，文件路径，沙箱内）；content（必填，完整文件内容，UTF-8 文本）。"
            "注意：会整体覆盖原文件内容；局部修改请改用 edit_file。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "要写入的文件路径（必须在沙箱内）"},
                "content": {"type": "string", "description": "完整文件内容（整体覆盖）"},
            },
            "required": ["path", "content"],
        },
        handler=_handle_write_file(config),
        readonly=False,
    )


# --------------------------------------------------------------- edit_file

def _handle_edit_file(config):
    def handler(args: dict, session: object) -> str:
        path = resolve_sandboxed_path(config.glm_tool_fs_root, args.get("path", ""))
        if not path.exists() or path.is_dir():
            raise ValueError("文件不存在或不是普通文件: {0}".format(path))
        old_string = args.get("old_string")
        new_string = args.get("new_string")
        if not isinstance(old_string, str) or old_string == "":
            raise ValueError("old_string 必须是非空字符串")
        if not isinstance(new_string, str):
            raise ValueError("new_string 必须是字符串")
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("文件不是有效的 UTF-8 文本，拒绝编辑: {0}".format(path)) from exc
        count = text.count(old_string)
        if count == 0:
            raise ValueError("old_string 在文件中出现 0 次，未做任何修改（请核对原文）")
        if count > 1:
            raise ValueError(
                "old_string 在文件中出现 {0} 次，不是唯一匹配，拒绝替换（请扩大上下文使其唯一）".format(count)
            )
        path.write_text(text.replace(old_string, new_string, 1), encoding="utf-8")
        return "已替换 1 处: {0}".format(_display_path(config, path))

    return handler


def _factory_edit_file(config) -> ToolSpec:
    return ToolSpec(
        name="edit_file",
        description=(
            "对文本文件做精确替换：old_string 必须在文件中恰好出现一次，替换为 new_string。"
            "出现 0 次或多次都会报错拒绝，不做任何修改。"
            "参数：path（必填）；old_string（必填，要被替换的原文片段）；new_string（必填，替换后的内容）。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "要编辑的文件路径（必须在沙箱内）"},
                "old_string": {"type": "string", "description": "要被替换的原文片段（必须全文唯一）"},
                "new_string": {"type": "string", "description": "替换后的内容"},
            },
            "required": ["path", "old_string", "new_string"],
        },
        handler=_handle_edit_file(config),
        readonly=False,
    )


# --------------------------------------------------------------- list_dir

def _handle_list_dir(config):
    def handler(args: dict, session: object) -> str:
        path = resolve_sandboxed_path(config.glm_tool_fs_root, args.get("path") or ".")
        if not path.exists():
            raise ValueError("目录不存在: {0}".format(path))
        if not path.is_dir():
            raise ValueError("不是目录: {0}".format(path))
        pattern_raw = args.get("pattern")
        pattern = str(pattern_raw).strip() if pattern_raw not in (None, "") else None
        # 目录在前、文件在后，组内按名字排序：输出稳定，模型容易对照
        entries = sorted(path.iterdir(), key=lambda item: (not item.is_dir(), item.name.lower()))
        lines: list[str] = []
        for entry in entries:
            if pattern and not fnmatch.fnmatch(entry.name, pattern):
                continue
            if entry.is_dir():
                lines.append("[dir]  {0}/".format(entry.name))
            elif entry.is_file():
                try:
                    size = entry.stat().st_size
                except OSError:
                    # stat 失败（竞态删除/权限）：不因单个条目中断整个列目录
                    lines.append("[file] {0} (大小未知)".format(entry.name))
                    continue
                lines.append("[file] {0} ({1} 字节)".format(entry.name, size))
            else:
                lines.append("[other] {0}".format(entry.name))
        if not lines:
            if pattern:
                return "(pattern {0} 无匹配条目)".format(pattern)
            return "(空目录: {0})".format(_display_path(config, path))
        return "\n".join(lines)

    return handler


def _factory_list_dir(config) -> ToolSpec:
    return ToolSpec(
        name="list_dir",
        description=(
            "列出沙箱内目录的一层内容（名字/类型/大小，目录在前）。"
            "参数：path（可选，目录路径，默认沙箱根）；"
            "pattern（可选，fnmatch 通配符，对文件名过滤，如 *.py）。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "要列出的目录路径，默认 .（沙箱根）"},
                "pattern": {"type": "string", "description": "文件名 fnmatch 通配过滤，如 *.py，可选"},
            },
            "required": [],
        },
        handler=_handle_list_dir(config),
        readonly=True,
    )


# --------------------------------------------------------------- grep_files

def _handle_grep_files(config):
    def handler(args: dict, session: object) -> str:
        raw_pattern = args.get("pattern")
        if not isinstance(raw_pattern, str) or not raw_pattern.strip():
            raise ValueError("缺少搜索正则 pattern")
        try:
            regex = re.compile(raw_pattern, re.IGNORECASE)
        except re.error as exc:
            raise ValueError("无效正则表达式: {0} ({1})".format(raw_pattern, exc)) from exc
        base = resolve_sandboxed_path(config.glm_tool_fs_root, args.get("path") or ".")
        if not base.exists():
            raise ValueError("搜索路径不存在: {0}".format(base))
        glob_raw = args.get("glob")
        glob_pattern = str(glob_raw).strip() if glob_raw not in (None, "") else "*"
        max_results = _parse_int_arg(args.get("max_results"), "max_results", default=50)
        if max_results < 1:
            raise ValueError("max_results 必须 >= 1: {0}".format(max_results))

        if base.is_file():
            files: list[Path] = [base]
        else:
            files = sorted(p for p in base.rglob(glob_pattern) if p.is_file())

        hits: list[str] = []
        truncated = False
        for file_path in files:
            try:
                if file_path.stat().st_size > GREP_FILE_MAX_BYTES:
                    continue  # 超大文件跳过：体积治理优先于穷尽搜索
                data = file_path.read_bytes()
            except OSError:
                continue  # 单文件 IO 失败（权限/竞态）不阻断整体搜索
            if b"\x00" in data[:1024]:
                continue  # 前 1KB 含 NUL 判定为二进制，逐行搜索无意义
            text = data.decode("utf-8", errors="replace")
            display = file_path.name if file_path == base else file_path.relative_to(base).as_posix()
            for line_no, line in enumerate(text.splitlines(), start=1):
                if regex.search(line):
                    hits.append("{0}:{1}: {2}".format(display, line_no, line[:GREP_LINE_MAX_CHARS]))
                    if len(hits) >= max_results:
                        truncated = True
                        break
            if truncated:
                break
        if not hits:
            return "(无匹配: pattern={0} glob={1})".format(raw_pattern, glob_pattern)
        result = "\n".join(hits)
        if truncated:
            result += "\n[已达到 max_results={0}，结果已截断]".format(max_results)
        return result

    return handler


def _factory_grep_files(config) -> ToolSpec:
    return ToolSpec(
        name="grep_files",
        description=(
            "在沙箱内递归搜索文本：按文件名 glob 过滤后逐行正则匹配（忽略大小写），"
            "输出『相对路径:行号: 行内容』，单行内容截断到 200 字符。"
            "自动跳过二进制文件与超过 1MB 的文件；命中数达到 max_results 即停止并注明。"
            "参数：pattern（必填，正则表达式）；path（可选，搜索根，默认 .）；"
            "glob（可选，文件名通配，默认 *）；max_results（可选，最多输出行数，默认 50）。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "正则表达式（忽略大小写）"},
                "path": {"type": "string", "description": "搜索根目录或单个文件，默认 .（沙箱根）"},
                "glob": {"type": "string", "description": "文件名通配过滤，如 *.py，默认 *"},
                "max_results": {"type": "integer", "description": "最多输出的命中行数，默认 50"},
            },
            "required": ["pattern"],
        },
        handler=_handle_grep_files(config),
        readonly=True,
    )


# --------------------------------------------------------------- delete_file

def _handle_delete_file(config):
    def handler(args: dict, session: object) -> str:
        path = resolve_sandboxed_path(config.glm_tool_fs_root, args.get("path", ""))
        if not path.exists():
            raise ValueError("文件不存在: {0}".format(path))
        if path.is_dir():
            raise ValueError("delete_file 仅支持删除单个文件，不支持目录: {0}".format(path))
        path.unlink()
        return "已删除文件: {0}".format(_display_path(config, path))

    return handler


def _factory_delete_file(config) -> ToolSpec:
    return ToolSpec(
        name="delete_file",
        description=(
            "删除沙箱内的单个文件（不支持目录，破坏性操作请谨慎使用）。"
            "参数：path（必填，要删除的文件路径，沙箱内）。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "要删除的文件路径（必须在沙箱内）"},
            },
            "required": ["path"],
        },
        handler=_handle_delete_file(config),
        readonly=False,
    )


# --------------------------------------------------------------- 工厂表

TOOL_FACTORIES: dict[str, Callable[[object], ToolSpec]] = {
    "read_file": _factory_read_file,
    "write_file": _factory_write_file,
    "edit_file": _factory_edit_file,
    "list_dir": _factory_list_dir,
    "grep_files": _factory_grep_files,
    "delete_file": _factory_delete_file,
}
