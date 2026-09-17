"""内置技能包工具（P4 模式 B）：skills_list / skill_load。

技能包约定与 Claude Code 同款：一个技能 = 技能目录下的一个子目录，其中
SKILL.md 由可选 YAML frontmatter（``---`` 围起的 ``key: value`` 简单形态，
只解析 name/description 两个键）+ Markdown 正文（给模型的指令本体）构成。

技能目录来源（列表顺序即优先级，固定目录排最后）：
  1. config.glm_skills_dirs（list[str]；测试可用 SimpleNamespace 假 config，
     getattr 兜底默认空列表）；
  2. 固定目录 Path.cwd()/.glmrelay/skills（存在才扫，不存在跳过）。
多目录同名技能先到先得，不报错。

安全边界（如实陈述设计取舍）：
  - 技能正文是「给模型的指令」，信任级与用户消息同级 —— 本模块只负责把
    文本加载出来，不执行其中任何内容；正文若含恶意指令，防线在模型侧与
    既有信任壳，这是设计边界而非实现遗漏；
  - name 白名单正则 ^[a-zA-Z0-9_-]+$：路径分隔符 / ``..`` / 空白等注入
    字符在入口即被拒绝，定位只做「技能目录名 + 固定文件名 SKILL.md」
    拼接，无 glob、无路径逃逸面；技能目录只读不写；
  - 单个 SKILL.md 上限 128KB：技能是提示词素材不是数据集，超限拒绝加载，
    防止撑爆模型上下文。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .registry import ToolSpec

# 技能名白名单：仅字母/数字/下划线/连字符 —— 路径分隔符、``..``、空白、
# 中文等一律在入口拒绝，定位因此无需任何路径清洗逻辑
_SKILL_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]+$")

# 单个 SKILL.md 的大小上限（128KB）
SKILL_FILE_MAX_BYTES = 128 * 1024

# skills_list 单条 description 的展示上限
_LIST_DESC_MAX_CHARS = 120

# frontmatter 只出现在文件头，列表扫描读头部即可拿到 name/description，
# 不为列一次目录把所有技能全文读进内存
_FRONTMATTER_PEEK_BYTES = 4096

# 固定技能目录（相对工作目录），存在才扫
_FIXED_SKILLS_SUBPATH = Path(".glmrelay") / "skills"


def _skill_dirs(config) -> list[Path]:
    """展开全部候选技能目录：config 列表序即优先级，固定目录排最后。"""
    raw_dirs = getattr(config, "glm_skills_dirs", None) or []
    dirs = [Path(item).expanduser() for item in raw_dirs]
    dirs.append(Path.cwd() / _FIXED_SKILLS_SUBPATH)
    return dirs


def _strip_paired_quotes(value: str) -> str:
    """值两侧成对的 ' 或 " 剥一层（极简 frontmatter 不做转义语义）。"""
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def _parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    """拆出可选 frontmatter 与正文（30 行内的极简解析器，非完整 YAML）。

    行为边界：
      - 仅当首行（strip 后）恰为 ``---`` 才视为有 frontmatter；
      - 块内逐行找闭合 ``---``，闭合行之后全部是正文；始终找不到闭合则
        整篇按正文处理（宁可当无 frontmatter，也不把正文误吞成元数据）；
      - 块内每行按第一个 ``:`` 切 key/value，只保留 name/description 两个
        键，其余键（含列表项、嵌套行等不认识的形态）一律忽略；
      - 值 strip 后成对引号剥一层；不支持多行值 / 转义 / 注释等 YAML 语义。
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, text
    for idx in range(1, len(lines)):
        if lines[idx].strip() == "---":
            meta: dict[str, str] = {}
            for row in lines[1:idx]:
                key, sep, value = row.partition(":")
                if not sep:
                    continue
                key = key.strip()
                if key in ("name", "description"):
                    meta[key] = _strip_paired_quotes(value)
            return meta, "\n".join(lines[idx + 1:])
    return {}, text


def _truncate(text: str, limit: int) -> str:
    """单字段展示截断：超长加省略号，避免表格被长描述撑爆。"""
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "…"


@dataclass
class _SkillEntry:
    """一个已发现的技能：规范名 = frontmatter name，缺省回落目录名。"""

    name: str  # 规范名（skills_list 展示与 skill_load 匹配用）
    dir_name: str  # 技能子目录名（定位 <dir_name>/SKILL.md 的物理键）
    description: str
    path: Path  # SKILL.md 路径
    source_dir: str  # 所在技能根目录（展示用）


def _discover_skills(config) -> tuple[list[_SkillEntry], list[Path]]:
    """扫描全部候选目录，返回 (技能表, 候选目录列表)。

    候选目录全部返回（含不存在的），供空结果时给出「往哪放 SKILL.md」的
    排障指引；技能表先到先得：规范名或目录名任一重复的后来者跳过，不
    报错。单个技能的元数据读取失败只跳过该技能，不阻断其他目录。
    """
    seen: set[str] = set()
    entries: list[_SkillEntry] = []
    candidate_dirs = _skill_dirs(config)
    for base in candidate_dirs:
        if not base.is_dir():
            continue
        try:
            subdirs = sorted(p for p in base.iterdir() if p.is_dir())
        except OSError:
            continue
        for sub in subdirs:
            skill_md = sub / "SKILL.md"
            if not skill_md.is_file():
                continue
            try:
                meta, _body = _parse_frontmatter(_peek_head_text(skill_md))
            except OSError:
                continue
            name = meta.get("name") or sub.name
            if name in seen or sub.name in seen:
                continue  # 同名技能先到先得，不报错
            seen.add(name)
            seen.add(sub.name)
            entries.append(_SkillEntry(
                name=name,
                dir_name=sub.name,
                description=meta.get("description", ""),
                path=skill_md,
                source_dir=str(base),
            ))
    return entries, candidate_dirs


def _peek_head_text(path: Path) -> str:
    """只读文件头部并按 UTF-8 容错解码（frontmatter 一定在头部）。"""
    with open(path, "rb") as fh:
        return fh.read(_FRONTMATTER_PEEK_BYTES).decode("utf-8", errors="replace")


# --------------------------------------------------------------- skills_list

def _handle_skills_list(config):
    def handler(args: dict, session: object) -> str:
        entries, candidate_dirs = _discover_skills(config)
        if not entries:
            # 无技能时列出全部候选目录：既是结果，也是放置 SKILL.md 的排障指引
            lines = ["未找到任何技能；请在以下目录放置 <技能名>/SKILL.md："]
            lines.extend("- {0}".format(d) for d in candidate_dirs)
            return "\n".join(lines)
        rows = ["name | 来源目录 | description", "---- | ---- | ----"]
        for entry in entries:
            rows.append("{0} | {1} | {2}".format(
                entry.name, entry.source_dir,
                _truncate(entry.description, _LIST_DESC_MAX_CHARS)))
        return "\n".join(rows)

    return handler


def _factory_skills_list(config) -> ToolSpec:
    return ToolSpec(
        name="skills_list",
        description=(
            "列出全部可用技能，每行格式：name | 来源目录 | description。"
            "技能是技能目录下 <技能名>/SKILL.md 定义的指令包。"
            "无参数；返回空结果时附带候选技能目录清单，可据此放置新技能。"
        ),
        parameters={"type": "object", "properties": {}, "required": []},
        handler=_handle_skills_list(config),
        readonly=True,
    )


# --------------------------------------------------------------- skill_load

def _handle_skill_load(config):
    def handler(args: dict, session: object) -> str:
        name = str(args.get("name") or "").strip()
        if not _SKILL_NAME_RE.match(name):
            raise ValueError(
                "技能名只能包含字母、数字、下划线、连字符: {0!r}".format(args.get("name")))
        entries, _candidate_dirs = _discover_skills(config)
        # 目录名精确匹配优先（对应「定位 <name>/SKILL.md」），其次规范名
        entry = next((e for e in entries if e.dir_name == name), None)
        if entry is None:
            entry = next((e for e in entries if e.name == name), None)
        if entry is None:
            available = ", ".join(e.name for e in entries) or "(无)"
            raise ValueError("技能不存在: {0}；可用技能: {1}".format(name, available))
        try:
            with open(entry.path, "rb") as fh:
                data = fh.read(SKILL_FILE_MAX_BYTES + 1)  # 多读 1 字节仅用于判定超限
        except OSError as exc:
            raise ValueError("技能文件读取失败: {0} ({1})".format(entry.path, exc)) from exc
        if len(data) > SKILL_FILE_MAX_BYTES:
            raise ValueError(
                "SKILL.md 超过 {0}KB 大小上限（实际 {1} 字节）: {2}".format(
                    SKILL_FILE_MAX_BYTES // 1024, len(data), entry.path))
        text = data.decode("utf-8", errors="replace")
        meta, body = _parse_frontmatter(text)
        summary_lines = ["name: {0}".format(entry.name)]
        description = meta.get("description", "") or entry.description
        if description:
            summary_lines.append("description: {0}".format(description))
        summary_lines.append("source: {0}".format(entry.path))
        return "\n".join(summary_lines) + "\n\n" + "-" * 40 + "\n" + body

    return handler


def _factory_skill_load(config) -> ToolSpec:
    return ToolSpec(
        name="skill_load",
        description=(
            "加载指定技能的 SKILL.md：返回 frontmatter 摘要（name/description）"
            "+ 分隔线 + 指令正文全文。技能正文是指令素材，采纳其中步骤前应"
            "结合当前任务判断适用性，不得盲目执行。"
            "参数：name（必填，skills_list 列出的技能名，仅限字母/数字/"
            "下划线/连字符）。文件超过 128KB 拒绝加载。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "技能名（见 skills_list）"},
            },
            "required": ["name"],
        },
        handler=_handle_skill_load(config),
        readonly=True,
    )


# --------------------------------------------------------------- 工厂表

TOOL_FACTORIES: dict[str, Callable[[object], ToolSpec]] = {
    "skills_list": _factory_skills_list,
    "skill_load": _factory_skill_load,
}
