"""内置 Todo 工具（P3 模式 B）：会话内任务清单，只改会话内存状态。

readonly=True 的理由：不动任何文件、不发任何请求，唯一副作用是把清单写进
AgentSession.todo_list（会话对象随请求结束丢弃）—— 对部署环境是只读的。
每次调用全量覆盖清单（模型负责传完整列表），返回渲染后的清单文本与计数
摘要，模型据此在下一轮决定推进哪一项。
"""

from __future__ import annotations

from typing import Callable

from .registry import ToolSpec

VALID_STATUSES: tuple[str, ...] = ("pending", "in_progress", "completed")
# 渲染前缀：[ ] 待办 / [~] 进行中 / [x] 已完成（与会话内 todo 展示习惯一致）
STATUS_MARKS = {"pending": "[ ]", "in_progress": "[~]", "completed": "[x]"}


def _handle_todo_write(config):
    def handler(args: dict, session: object) -> str:
        todos = args.get("todos")
        if not isinstance(todos, list):
            raise ValueError("todos 必须是数组，元素形态 {content: str, status: pending|in_progress|completed}")
        normalized: list[dict] = []
        for index, item in enumerate(todos):
            if not isinstance(item, dict):
                raise ValueError("todos[{0}] 必须是对象".format(index))
            content = item.get("content")
            status = item.get("status")
            if not isinstance(content, str) or not content.strip():
                raise ValueError("todos[{0}].content 必须是非空字符串".format(index))
            if status not in VALID_STATUSES:
                raise ValueError(
                    "todos[{0}].status 非法: {1!r}（合法值: pending/in_progress/completed）".format(index, status)
                )
            normalized.append({"content": content.strip(), "status": status})
        # 会话对象由 agent loop 提供，直接挂属性（AgentSession.todo_list 的既定形态）
        session.todo_list = normalized
        lines = ["{0} {1}".format(STATUS_MARKS[item["status"]], item["content"]) for item in normalized]
        if not lines:
            lines.append("(清单为空)")
        counts = {status: 0 for status in VALID_STATUSES}
        for item in normalized:
            counts[item["status"]] += 1
        summary = "共 {0} 项：pending {1}、in_progress {2}、completed {3}".format(
            len(normalized), counts["pending"], counts["in_progress"], counts["completed"]
        )
        return "\n".join(lines) + "\n\n" + summary

    return handler


def _factory_todo_write(config) -> ToolSpec:
    return ToolSpec(
        name="todo_write",
        description=(
            "写入/更新当前会话的任务清单（每次全量覆盖），返回渲染后的清单与计数摘要。"
            "参数：todos（必填，数组，每项为 {content, status} 对象，"
            "status 取值 pending/in_progress/completed；传空数组表示清空清单）。"
            "状态仅保存在会话内存中，不落盘。"
        ),
        parameters={
            "type": "object",
            "properties": {
                "todos": {
                    "type": "array",
                    "description": "完整任务清单（全量覆盖）",
                    "items": {
                        "type": "object",
                        "properties": {
                            "content": {"type": "string", "description": "任务内容"},
                            "status": {
                                "type": "string",
                                "enum": ["pending", "in_progress", "completed"],
                                "description": "任务状态",
                            },
                        },
                        "required": ["content", "status"],
                    },
                },
            },
            "required": ["todos"],
        },
        handler=_handle_todo_write(config),
        readonly=True,
    )


TOOL_FACTORIES: dict[str, Callable[[object], ToolSpec]] = {
    "todo_write": _factory_todo_write,
}
