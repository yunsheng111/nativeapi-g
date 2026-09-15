from __future__ import annotations

import json
import logging
import re
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from .tool_protocol import BLOCKED_NATIVE_TOOL_NAMES

_logger = logging.getLogger("glm2api.tool_parser")

CODE_FENCE_PATTERN = re.compile(r"```[\s\S]*?```")
TOOL_RESULT_PATTERN = re.compile(
    r"<(?:(?:\|DSML\|)|ml_)?tool_result\b[\s\S]*?</(?:(?:\|DSML\|)|ml_)?tool_result>",
    re.IGNORECASE,
)
START_TAG_PATTERN = re.compile(
    r"<(?P<tag>\|DSML\|tool_calls|tool_calls|ml_tool_calls|ml_tool_call)\b[^>]*>",
    re.IGNORECASE,
)
DSML_TAG_PATTERN = re.compile(r"</?\|DSML\|(?P<name>tool_calls|invoke|parameter|tool_result)\b", re.IGNORECASE)
DSML_OPEN_TAG_PATTERN = re.compile(
    r"<\|dsml\|(?P<name>tool_calls|toolcalls|invoke|parameter|tool_result|toolresult)\b(?P<attrs>[^<>]*?)>",
    re.IGNORECASE,
)
DSML_CLOSE_TAG_PATTERN = re.compile(
    r"</\|dsml\|(?P<name>tool_calls|toolcalls|invoke|parameter|tool_result|toolresult)\s*\|?\s*>",
    re.IGNORECASE,
)
DSML_COMPACT_CLOSE_TAG_PATTERN = re.compile(
    r"(?:</\|dsml|<\|/dsml)(?P<name>toolcalls|invoke|parameter|toolresult)\s*\|\s*>",
    re.IGNORECASE,
)
DSML_DOUBLE_PIPE_CLOSE_TAG_PATTERN = re.compile(
    r"<\|\|dsml\|(?P<name>tool_calls|toolcalls|invoke|parameter|tool_result|toolresult)\s*\|?\s*>",
    re.IGNORECASE,
)
DSML_TOOL_CALLS_CLOSE_PATTERN = re.compile(
    r"(?:</\|dsml\|tool_calls\s*>|</\|dsml\|tool_calls\s*\|\s*>|</\|dsmltool_?calls\s*\|\s*>|<\|/dsmltool_?calls\s*\|\s*>)",
    re.IGNORECASE,
)
DSML_TOOL_CALLS_TRAILING_CLOSE_PATTERN = re.compile(
    r"(?:</\|dsml\|tool_calls\s*>|</\|dsml\|tool_calls\s*\|\s*>|</\|dsmltool_?calls\s*\|\s*>|<\|/dsmltool_?calls\s*\|\s*>|</\|dsml\|tool_calls\s*$|</\|dsmltool_?calls\s*\|?\s*$|<\|/dsmltool_?calls\s*\|?\s*$)",
    re.IGNORECASE,
)
PARAM_NAME_TAG_PATTERN = re.compile(r"<param_name>\s*(.*?)\s*</param_name>", re.IGNORECASE | re.DOTALL)
PARAM_VALUE_TAG_PATTERN = re.compile(r"<param_value>\s*(.*?)\s*</param_value>", re.IGNORECASE | re.DOTALL)
TAG_NAME_HINTS = [
    "<|",
    "</|",
    "<DStool_calls",
    "</DStool_calls",
    "<|DSML|",
    "</|DSML|",
    "<|DSML|tool_calls",
    "</|DSML|tool_calls",
    "<|DSML|invoke",
    "</|DSML|invoke",
    "<|DSML|parameter",
    "</|DSML|parameter",
    "<|DSML|tool_result",
    "</|DSML|tool_result",
    "<m",
    "</m",
    "<ml_",
    "</ml_",
    "<ml_tool_calls",
    "</ml_tool_calls",
    "<ml_tool_call",
    "</ml_tool_call",
    "<ml_tool_name",
    "</ml_tool_name",
    "<ml_parameters",
    "</ml_parameters",
    "<ml_tool_result",
    "</ml_tool_result",
    "<tool_calls",
    "</tool_calls",
    "<invoke",
    "</invoke",
    "<parameter",
    "</parameter",
]


def _local_name(tag: str) -> str:
    if "}" in tag:
        tag = tag.split("}", 1)[1]
    if ":" in tag:
        tag = tag.split(":", 1)[1]
    return tag.lower()


def _canonical_dsml_name(name: str) -> str:
    normalized = name.lower().replace("_", "")
    if normalized == "toolcalls":
        return "tool_calls"
    if normalized == "toolresult":
        return "tool_result"
    return normalized


# ── 畸形标记抢救层（P2 用例 #6：模型把搅碎的 DSML 写进正文）──
# 规则直接由 12.6 失败样本两族推导，必须保持窄匹配，只在确凿的协议畸形上
# 触发，避免误改普通正文；命中即打日志（失败不可伪装成成功）。
BROKEN_TOOL_CALLS_OPEN_PATTERN = re.compile(r"<\|?DS(?:ML)?tool_calls\s*\|?>", re.IGNORECASE)
BROKEN_TOOL_CALLS_CLOSE_PATTERN = re.compile(r"</\|?DS(?:ML)?tool_calls\s*\|?>", re.IGNORECASE)
CORRUPTED_INVOKE_LINE_PATTERN = re.compile(r"^[ \t]*<\|DSML\|invoke\b[^\n]*(?:\n|$)", re.IGNORECASE | re.MULTILINE)


def _extract_name_values(line: str) -> list[str]:
    # 逐个定位 name=" 再手动取到下一个引号：混串里的中间 name= 不会被
    # 前一个匹配的值吞掉，族 B 样本（city>name="get_weather）因此可提取。
    # 引号未闭合（族 A 的 "> 被搅没）时取到行尾，仍可凭管道痕迹判噪。
    values: list[str] = []
    for match in re.finditer(r'name\s*=\s*"', line, re.IGNORECASE):
        start = match.end()
        end = line.find('"', start)
        if end == -1:
            tail = line[start:].rstrip()
            if tail.endswith(">"):
                tail = tail[:-1]
            values.append(tail)
        else:
            values.append(line[start:end])
    return values


def _fix_corrupted_invoke_line(line_body: str) -> str | None:
    """返回 None 表示行无需改动；返回字符串为替换文本（空串 = 删除该行）。"""
    values = _extract_name_values(line_body)
    if not values:
        return None
    if len(values) >= 2:
        # 族 B：属性区搅出多个 name=，最后一个才是模型要写的工具名；
        # 尾值仍不干净时无法恢复，按噪声行删除。
        tail = values[-1]
        if tail and not any(ch in tail for ch in '"<>|\n'):
            return f'<|DSML|invoke name="{tail}">'
        return ""
    if "|" in values[0]:
        # 族 A：name 值混入管道痕迹的噪声 invoke（合法工具名不含 |），
        # 删除后块内完好的 invoke 才能通过 XML 解析存活。
        return ""
    return None


def _repair_corrupted_markup(text: str) -> str:
    if "<|DSML|invoke" not in text and not BROKEN_TOOL_CALLS_OPEN_PATTERN.search(text):
        return text
    repaired = BROKEN_TOOL_CALLS_OPEN_PATTERN.sub("<|DSML|tool_calls>", text)
    repaired = BROKEN_TOOL_CALLS_CLOSE_PATTERN.sub("</|DSML|tool_calls>", repaired)

    changed = False

    def fix_line(match: re.Match[str]) -> str:
        nonlocal changed
        line = match.group(0)
        fixed = _fix_corrupted_invoke_line(line.rstrip("\n"))
        if fixed is None:
            return line
        changed = True
        if not fixed:
            return ""  # 噪声行连换行一起删除
        return fixed + ("\n" if line.endswith("\n") else "")

    repaired = CORRUPTED_INVOKE_LINE_PATTERN.sub(fix_line, repaired)
    if changed:
        _logger.warning("检测到搅碎的 DSML 标记，已按失败样本族规则抢救归一化")
    return repaired


def _repair_malformed_dsml(block: str) -> str:
    if "<|" not in block and "]]|>" not in block:
        return block

    repaired = block.replace("]]|>", "]]>")
    if "<![CDATA[" in repaired:
        repaired = re.sub(
            r"(?<!\])\]>(?=</\|dsml\|parameter\b|</\|DSML\|parameter\b|</parameter\b|</\|dsmlparameter\|)",
            "]]>",
            repaired,
            flags=re.IGNORECASE,
        )

    def replace_open(match: re.Match[str]) -> str:
        name = _canonical_dsml_name(match.group("name"))
        attrs = match.group("attrs").rstrip("|").rstrip()
        return f"<|DSML|{name}{attrs}>"

    def replace_close(match: re.Match[str]) -> str:
        return f"</|DSML|{_canonical_dsml_name(match.group('name'))}>"

    repaired = DSML_OPEN_TAG_PATTERN.sub(replace_open, repaired)
    repaired = DSML_CLOSE_TAG_PATTERN.sub(replace_close, repaired)
    repaired = DSML_COMPACT_CLOSE_TAG_PATTERN.sub(replace_close, repaired)
    repaired = DSML_DOUBLE_PIPE_CLOSE_TAG_PATTERN.sub(replace_close, repaired)
    repaired = re.sub(
        r"(?:</\|dsml\|tool_calls|</\|dsmltool_?calls|<\|/dsmltool_?calls)\s*\|?\s*$",
        "</|DSML|tool_calls>",
        repaired,
        flags=re.IGNORECASE,
    )
    return repaired


def _normalize_dsml_to_xml(block: str) -> str:
    repaired = _repair_malformed_dsml(block)
    return DSML_TAG_PATTERN.sub(lambda match: match.group(0).replace("|DSML|", ""), repaired)


def _is_allowed_tool_name(tool_name: str, allowed_tool_names: set[str] | None) -> bool:
    # 客户端显式声明的工具优先（P2 改造 7.3）：即使名字与上游原生工具撞名
    # （如 web_search 是很多客户端的默认名），只要客户端真的声明了它，就放行 ——
    # 客户端自己执行工具，中转无权单方面撕毁 tools 契约。
    if allowed_tool_names is not None and tool_name in allowed_tool_names:
        return True
    if tool_name in BLOCKED_NATIVE_TOOL_NAMES:
        return False  # 模型自行发明的上游原生工具名：物理上拿不到，一律拒绝
    return allowed_tool_names is None or tool_name in allowed_tool_names


def _balanced_text(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _leaf_text(element: ET.Element) -> str:
    return _balanced_text("".join(element.itertext()))


def _coerce_leaf_value(text: str) -> object:
    stripped = text.strip()
    if stripped == "":
        return ""
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            if stripped.startswith("[") and not stripped.endswith("]"):
                try:
                    return json.loads(stripped + "]")
                except json.JSONDecodeError:
                    pass
            return stripped
    if stripped in {"true", "false"}:
        return stripped == "true"
    if stripped == "null":
        return None
    if re.fullmatch(r"-?\d+", stripped):
        try:
            return int(stripped)
        except ValueError:
            return stripped
    if re.fullmatch(r"-?\d+\.\d+", stripped):
        try:
            return float(stripped)
        except ValueError:
            return stripped
    return stripped


def _append_value(mapping: dict[str, object], key: str, value: object) -> None:
    if key not in mapping:
        mapping[key] = value
        return
    existing = mapping[key]
    if isinstance(existing, list):
        existing.append(value)
        return
    mapping[key] = [existing, value]


def _xml_value_to_object(element: ET.Element) -> object:
    children = [child for child in list(element) if isinstance(child.tag, str)]
    if not children:
        return _coerce_leaf_value(_leaf_text(element))

    repeated_item_only = all(_local_name(child.tag) == "item" for child in children)
    if repeated_item_only:
        return [_xml_value_to_object(child) for child in children]

    result: dict[str, object] = {}
    for child in children:
        key = child.attrib.get("name", "").strip() or _local_name(child.tag)
        _append_value(result, key, _xml_value_to_object(child))
    return result


def _extract_tool_name(element: ET.Element) -> str:
    if _local_name(element.tag) == "invoke":
        return element.attrib.get("name", "").strip()
    for tag_name in ("ml_tool_name", "tool_name"):
        tool_name_element = element.find(tag_name)
        if tool_name_element is not None:
            return _leaf_text(tool_name_element)
    return ""


def _extract_arguments(element: ET.Element) -> dict[str, object] | None:
    if _local_name(element.tag) == "invoke":
        parameters: dict[str, object] = {}
        parameter_children = [
            child
            for child in list(element)
            if isinstance(child.tag, str) and _local_name(child.tag) == "parameter"
        ]
        for child in parameter_children:
            key = child.attrib.get("name", "").strip()
            if key:
                _append_value(parameters, key, _xml_value_to_object(child))
        return parameters

    for tag_name in ("ml_parameters", "parameters"):
        parameters_element = element.find(tag_name)
        if parameters_element is not None:
            parsed = _xml_value_to_object(parameters_element)
            if isinstance(parsed, dict):
                return parsed
            return {"value": parsed}
    return None


def _build_tool_call(name: str, arguments: dict[str, object], index: int) -> dict[str, object]:
    return {
        "id": f"call_{uuid.uuid4().hex[:24]}",
        "type": "function",
        "index": index,
        "function": {
            "name": name,
            "arguments": json.dumps(arguments, ensure_ascii=False, separators=(",", ":")),
        },
    }


def _parse_tool_call_element(
    element: ET.Element,
    allowed_tool_names: set[str] | None,
    index: int,
) -> dict[str, object] | None:
    if _local_name(element.tag) not in {"invoke", "tool_call", "ml_tool_call"}:
        return None

    tool_name = _extract_tool_name(element)
    if not tool_name:
        return None
    if not _is_allowed_tool_name(tool_name, allowed_tool_names):
        return None

    arguments = _extract_arguments(element)
    if arguments is None:
        return None

    return _build_tool_call(tool_name, arguments, index)


def _extract_malformed_tool_call_from_root(
    root: ET.Element,
    allowed_tool_names: set[str] | None,
    index: int,
) -> dict[str, object] | None:
    root_name = _local_name(root.tag)
    if root_name not in {"tool_calls", "ml_tool_calls"}:
        return None

    tool_name = _extract_tool_name(root)
    if not tool_name:
        return None
    if not _is_allowed_tool_name(tool_name, allowed_tool_names):
        return None

    for tag_name in ("ml_parameters", "parameters"):
        parameters_element = root.find(tag_name)
        if parameters_element is not None:
            parsed = _xml_value_to_object(parameters_element)
            arguments = parsed if isinstance(parsed, dict) else {"value": parsed}
            return _build_tool_call(tool_name, arguments, index)

    names = [match.group(1).strip() for match in PARAM_NAME_TAG_PATTERN.finditer(ET.tostring(root, encoding="unicode"))]
    values = [match.group(1).strip() for match in PARAM_VALUE_TAG_PATTERN.finditer(ET.tostring(root, encoding="unicode"))]
    if names and values and len(names) == len(values):
        arguments = {
            key: _coerce_leaf_value(value)
            for key, value in zip(names, values, strict=False)
            if key
        }
        return _build_tool_call(tool_name, arguments, index)
    if names and not values:
        return None

    direct_pairs: dict[str, object] = {}
    children = [child for child in list(root) if isinstance(child.tag, str)]
    for child in children:
        key = _local_name(child.tag)
        if key in {"tool_name", "ml_tool_name", "tool_call", "ml_tool_call"}:
            continue
        if key in {"param_name", "param_value"}:
            continue
        direct_pairs[key] = _xml_value_to_object(child)
    if direct_pairs:
        return _build_tool_call(tool_name, direct_pairs, index)
    return None


# DSML 块解析上限（对齐 glm-web-code 的 1MB 输出安全阀），超限拒绝解析。
_MAX_DSML_XML_BLOCK = 1_048_576


def _parse_xml_block(
    block: str,
    allowed_tool_names: set[str] | None,
    start_index: int,
) -> tuple[list[dict[str, object]], tuple[int, int] | None]:
    # ET 解析器接受内部 DTD 实体展开，而模型输出是半可信输入：
    # 检测到实体声明或超长块一律按解析失败拒绝，不做剔除后继续。
    if len(block) > _MAX_DSML_XML_BLOCK:
        _logger.warning("DSML 块超过 %d 字节，拒绝解析 len=%d", _MAX_DSML_XML_BLOCK, len(block))
        return [], None
    normalized = _normalize_dsml_to_xml(block)
    if "<!DOCTYPE" in normalized or "<!ENTITY" in normalized:
        _logger.warning("DSML 块含 DOCTYPE/ENTITY 实体声明，拒绝解析 len=%d", len(normalized))
        return [], None
    try:
        root = ET.fromstring(normalized)
    except ET.ParseError as exc:
        normalized = _normalize_dsml_to_xml(block)
        _logger.debug(
            "DSML XML 解析失败, 可能丢失工具调用. original_len=%s normalized_len=%s error=%s",
            len(block), len(normalized), exc,
        )
        return [], None

    root_name = _local_name(root.tag)
    if root_name in {"tool_calls", "ml_tool_calls"}:
        candidates = [
            child
            for child in list(root)
            if isinstance(child.tag, str) and _local_name(child.tag) in {"invoke", "tool_call", "ml_tool_call"}
        ]
    elif root_name in {"tool_call", "ml_tool_call"}:
        candidates = [root]
    else:
        return [], None

    tool_calls: list[dict[str, object]] = []
    for candidate in candidates:
        parsed = _parse_tool_call_element(candidate, allowed_tool_names, len(tool_calls))
        if parsed is not None:
            tool_calls.append(parsed)

    if not tool_calls:
        malformed = _extract_malformed_tool_call_from_root(root, allowed_tool_names, 0)
        if malformed is not None:
            tool_calls.append(malformed)

    if not tool_calls:
        return [], None
    return tool_calls, (start_index, start_index + len(block))


def _mask_code_fences(text: str) -> str:
    masked = list(text)
    for match in CODE_FENCE_PATTERN.finditer(text):
        for index in range(match.start(), match.end()):
            masked[index] = " "
    return "".join(masked)


def _find_matching_block(
    masked_text: str,
    start_match: re.Match[str],
    *,
    allow_trailing_close: bool = False,
) -> tuple[int, int] | None:
    tag_name = start_match.group("tag").lower()
    if tag_name == "|dsml|tool_calls":
        closing_pattern = DSML_TOOL_CALLS_TRAILING_CLOSE_PATTERN if allow_trailing_close else DSML_TOOL_CALLS_CLOSE_PATTERN
    else:
        closing_pattern = re.compile(rf"</{re.escape(tag_name)}\s*>", re.IGNORECASE)
    closing_match = closing_pattern.search(masked_text, start_match.end())
    if closing_match is None:
        return None
    return start_match.start(), closing_match.end()


def _extract_tool_blocks(
    text: str,
    allowed_tool_names: set[str] | None,
    *,
    allow_trailing_close: bool = False,
) -> tuple[list[tuple[int, int]], list[dict[str, object]]]:
    text = _repair_corrupted_markup(text)
    masked_text = _mask_code_fences(text)
    spans: list[tuple[int, int]] = []
    tool_calls: list[dict[str, object]] = []
    cursor = 0

    while cursor < len(masked_text):
        match = START_TAG_PATTERN.search(masked_text, cursor)
        if match is None:
            break
        span = _find_matching_block(masked_text, match, allow_trailing_close=allow_trailing_close)
        if span is None:
            break

        start, end = span
        block_calls, parsed_span = _parse_xml_block(text[start:end], allowed_tool_names, start)
        if parsed_span is not None and block_calls:
            for offset, tool_call in enumerate(block_calls, start=len(tool_calls)):
                tool_call["index"] = offset
            spans.append(parsed_span)
            tool_calls.extend(block_calls)
            cursor = end
            continue
        if match.group("tag").lower() in {"|dsml|tool_calls", "tool_calls", "ml_tool_calls", "ml_tool_call"}:
            _logger.debug(
                "检测到工具调用块但解析失败, 块已从可见文本移除但未产出 tool_calls. tag=%s block_len=%s",
                match.group("tag"), end - start,
            )
            spans.append((start, end))
            cursor = end
            continue

        cursor = match.end()

    return spans, tool_calls


def _remove_spans(text: str, spans: list[tuple[int, int]], *, trim_outer_whitespace: bool = True) -> str:
    if not spans:
        cleaned = TOOL_RESULT_PATTERN.sub("", text)
        cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
        return cleaned.strip() if trim_outer_whitespace else cleaned

    parts: list[str] = []
    cursor = 0
    for start, end in spans:
        if start < cursor:
            continue
        parts.append(text[cursor:start])
        cursor = end
    parts.append(text[cursor:])
    cleaned = "".join(parts)
    cleaned = TOOL_RESULT_PATTERN.sub("", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip() if trim_outer_whitespace else cleaned


def _find_unmatched_fence_start(text: str) -> int | None:
    last_open = None
    cursor = 0
    while True:
        index = text.find("```", cursor)
        if index == -1:
            break
        if last_open is None:
            last_open = index
        else:
            last_open = None
        cursor = index + 3
    return last_open


def _find_incomplete_block_start(text: str, *, allow_trailing_close: bool = False) -> int | None:
    masked_text = _mask_code_fences(text)
    cursor = 0
    while cursor < len(masked_text):
        match = START_TAG_PATTERN.search(masked_text, cursor)
        if match is None:
            break
        span = _find_matching_block(masked_text, match, allow_trailing_close=allow_trailing_close)
        if span is None:
            return match.start()
        cursor = span[1]
    return None


def _find_partial_tag_start(text: str) -> int | None:
    lowered_text = text.lower()
    pipe_tag_start = lowered_text.rfind("<|")
    if pipe_tag_start != -1 and ">" not in lowered_text[pipe_tag_start:]:
        return pipe_tag_start
    for hint in TAG_NAME_HINTS:
        lowered_hint = hint.lower()
        max_overlap = min(len(hint), len(text))
        for size in range(max_overlap, 0, -1):
            if lowered_text.endswith(lowered_hint[:size]):
                return len(text) - size
    return None


def _looks_like_tool_markup_fragment(text: str) -> bool:
    stripped = text.strip()
    lowered = stripped.lower()
    if not stripped:
        return False
    if lowered.startswith("<|dsml|") or lowered.startswith("</|dsml|") or lowered.startswith("<|/dsml"):
        return True
    if lowered.startswith("<dst") or lowered.startswith("</dst"):
        return True
    if stripped.startswith("<ml_") or stripped.startswith("</ml_"):
        return True
    if stripped.startswith("<tool_") or stripped.startswith("</tool_"):
        return True
    if stripped.startswith("<invoke") or stripped.startswith("</invoke"):
        return True
    if stripped.startswith("<parameter") or stripped.startswith("</parameter"):
        return True
    if stripped.startswith("<m") and any(token in stripped for token in ("ml_", "tool_", "tool_calls", "tool_result")):
        return True
    return False


def _split_stream_text(
    text: str,
    allowed_tool_names: set[str] | None,
    final: bool,
) -> tuple[str, str, list[dict[str, object]]]:
    text = _repair_corrupted_markup(text)
    hold_from_candidates = [
        index
        for index in (_find_unmatched_fence_start(text), _find_incomplete_block_start(text, allow_trailing_close=final))
        if index is not None
    ]

    if not final:
        partial_start = _find_partial_tag_start(text)
        if partial_start is not None:
            hold_from_candidates.append(partial_start)

    if final:
        safe_end = min(hold_from_candidates) if hold_from_candidates else len(text)
    elif hold_from_candidates:
        safe_end = min(hold_from_candidates)
    else:
        safe_end = len(text)

    processable = text[:safe_end]
    remainder = text[safe_end:]
    spans, tool_calls = _extract_tool_blocks(processable, allowed_tool_names, allow_trailing_close=final)
    visible = _remove_spans(processable, spans, trim_outer_whitespace=final)
    return visible, remainder, tool_calls


def parse_tool_calls_from_text(text: str, allowed_tool_names: set[str] | None = None) -> tuple[str, list[dict[str, object]]]:
    if not text:
        return "", []
    # 抢救层必须在定位块之前作用：spans 以归一化后的文本为基准，
    # _remove_spans 也必须作用在同一份文本上，否则偏移错位导致标记残留。
    text = _repair_corrupted_markup(text)
    spans, tool_calls = _extract_tool_blocks(text, allowed_tool_names, allow_trailing_close=True)
    return _remove_spans(text, spans), tool_calls


@dataclass
class StreamingToolParser:
    pending_text: str = ""
    tool_calls: list[dict[str, object]] = field(default_factory=list)
    allowed_tool_names: set[str] | None = None

    def consume(self, chunk: str) -> str:
        if not chunk:
            return ""
        self.pending_text += chunk
        visible, remainder, parsed_calls = _split_stream_text(
            self.pending_text,
            allowed_tool_names=self.allowed_tool_names,
            final=False,
        )
        self.pending_text = remainder
        self.tool_calls.extend(parsed_calls)
        return visible

    def flush(self) -> tuple[str, list[dict[str, object]]]:
        visible, remainder, parsed_calls = _split_stream_text(
            self.pending_text,
            allowed_tool_names=self.allowed_tool_names,
            final=True,
        )
        self.pending_text = ""
        self.tool_calls.extend(parsed_calls)
        tail = "" if _looks_like_tool_markup_fragment(remainder) else remainder
        return (visible + tail).strip(), self.tool_calls
