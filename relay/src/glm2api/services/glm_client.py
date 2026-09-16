from __future__ import annotations

import base64
import codecs
import gzip
import http.client
import json
import socket
import mimetypes
import random
import re
import threading
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from email.generator import _make_boundary # type: ignore
from io import BufferedReader, BytesIO
from logging import Logger
from typing import Callable

from ..config import AppConfig
from ..core.transport import open_upstream, set_request_account
from ..logging_utils import debug_dump
from .glm_auth import GLMAccessTokenManager, build_sign
from .translator import (
    GLMEventAccumulator,
    SERVER_SIDE_TOOL_NAMES,
    convert_messages,
    extract_recent_user_url,
    filter_tools,
    resolve_chat_mode,
    resolve_networking,
    resolve_upstream_model,
)


FILE_UPLOAD_URL_SUFFIX = "/backend-api/assistant/file_upload"
FILE_SIZE_LIMIT = 100 * 1024 * 1024
# Sentinel: yielded by _iter_sse_events when upstream has no data for a while,
# so generate() can send an SSE keepalive comment to the client.
_KEEPALIVE = object()
KEEPALIVE_INTERVAL = 30  # seconds
IMAGE_SIZE_TO_ASPECT_RATIO = {
    "1024x1024": "1:1",
    "1024x1536": "2:3",
    "1536x1024": "3:2",
    "1024x1792": "9:16",
    "1792x1024": "16:9",
}


class UpstreamAPIError(RuntimeError):
    def __init__(
        self,
        status_code: int,
        message: str,
        payload: dict[str, object] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload or {}
        # P0-2：保留响应头（Retry-After 等退避信号），异常穿透 failover 时仍可读
        self.headers = headers


class QueueTimeoutError(RuntimeError):
    pass


class GlobalRequestPacer:
    """P0-8 全局最小间隔节流器：单调时钟 + slot 分配"下一请求时刻"。

    补并发闸门的抖动漏洞 —— GLM_MAX_CONCURRENCY 只限同时在飞数，6 个线程
    仍可能同一瞬间醒来打上游。本节流器让所有请求的上游到达时刻彼此间隔
    ≥ min_interval（slot 间额外加少量随机抖动摊平节奏），多线程共享一把锁。
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._next_slot = 0.0

    def wait(self, min_interval_ms: float) -> float:
        """分配一个不早于上一 slot + min_interval 的发起时刻，返回需等待的秒数。"""
        if min_interval_ms <= 0:
            return 0.0
        interval = min_interval_ms / 1000.0
        now = time.monotonic()
        with self._lock:
            slot = max(self._next_slot, now) + random.uniform(0, interval * 0.25)
            wait_for = max(0.0, slot - now)
            self._next_slot = slot + interval
        return wait_for


@dataclass(slots=True)
class QueueLease:
    ticket: int
    release_callback: Callable[[int], None]
    released: bool = False

    def release(self) -> None:
        if self.released:
            return
        self.released = True
        self.release_callback(self.ticket)


class ConcurrentRequestQueue:
    def __init__(self, logger: Logger, wait_timeout: int, max_concurrency: int) -> None:
        self.logger = logger
        self.wait_timeout = wait_timeout
        self.max_concurrency = max(1, max_concurrency)
        self._condition = threading.Condition()
        self._next_ticket = 0
        self._serving_ticket = 0
        self._released_tickets: set[int] = set()

    def acquire(self, request_name: str) -> QueueLease:
        with self._condition:
            ticket = self._next_ticket
            self._next_ticket += 1
            queue_ahead = max(0, ticket - (self._serving_ticket + self.max_concurrency) + 1)
            start = time.monotonic()

            if queue_ahead > 0:
                self.logger.info("请求进入 GLM 队列 ticket=%s ahead=%s request=%s", ticket, queue_ahead, request_name)

            while ticket >= self._serving_ticket + self.max_concurrency:
                remaining = self.wait_timeout - (time.monotonic() - start)
                if remaining <= 0:
                    raise QueueTimeoutError(
                        f"GLM 队列等待超时，前方仍有 {ticket - (self._serving_ticket + self.max_concurrency) + 1} 个请求，请稍后重试。"
                    )
                self._condition.wait(timeout=remaining)

            active_slots = ticket - self._serving_ticket + 1
            self.logger.info(
                "请求获得 GLM 执行槽位 ticket=%s active=%s/%s request=%s",
                ticket,
                active_slots,
                self.max_concurrency,
                request_name,
            )
            return QueueLease(ticket=ticket, release_callback=self._release)

    def _release(self, ticket: int) -> None:
        with self._condition:
            self._released_tickets.add(ticket)
            while self._serving_ticket in self._released_tickets:
                self._released_tickets.remove(self._serving_ticket)
                self._serving_ticket += 1
            self.logger.info("请求离开 GLM 执行槽位 ticket=%s", ticket)
            self._condition.notify_all()


class GLMWebClient:
    def __init__(self, config: AppConfig, logger: Logger) -> None:
        self.config = config
        self.logger = logger
        self.auth = GLMAccessTokenManager(config=config, logger=logger)
        # 传输 seam 目标校验策略：默认阻断私网目标（自建内网上游可经 .env 放宽）
        from ..core.transport import set_upstream_policy

        set_upstream_policy(block_private=config.glm_transport_block_private)
        # 单身份单飞（D3）：同一账号同时只跑一条上游流。锁与账号槽一一对应，
        # 每个请求至多持有一把，无锁序死锁面。
        self._account_locks = [threading.Lock() for _ in range(max(1, len(config.glm_refresh_tokens)))]
        self.request_queue = ConcurrentRequestQueue(
            logger=logger,
            wait_timeout=config.glm_queue_wait_timeout,
            max_concurrency=config.glm_max_concurrency,
        )
        # P0-8 全局最小间隔节流器（默认 0 = 关闭，行为与旧版一致）
        self._request_pacer = GlobalRequestPacer()

    def _resolve_tools(self, openai_payload: dict[str, object]) -> tuple[list[dict[str, object]] | None, set[str] | None]:
        raw_tools = list(openai_payload.get("tools", [])) if isinstance(openai_payload.get("tools"), list) else None # type: ignore
        # P2 改造（7.3）：注入过滤只应用环境变量黑名单（部署者主动屏蔽）。
        # BLOCKED_NATIVE_TOOL_NAMES 不再参与此处 —— 客户端声明的工具即便与上游
        # 原生工具撞名（如 web_search）也应注入给模型；对"模型自行发明"的原生
        # 工具名，防幻觉防线保留在 tool_parser._is_allowed_tool_name（解析输出时）。
        blocked_tool_names = {
            name.strip()
            for name in self.config.blocked_tool_names
            if name.strip()
        }
        filtered_tools = filter_tools(raw_tools, blocked_tool_names)
        if raw_tools and len(raw_tools) != len(filtered_tools or []):
            blocked_names: list[str] = []
            for tool in raw_tools:
                fn = tool.get("function", {})
                tool_name = str(fn.get("name", "")).strip()
                if tool_name in blocked_tool_names:
                    blocked_names.append(tool_name)
            if blocked_names:
                self.logger.info("已过滤不受支持的工具: %s", ", ".join(blocked_names))
        return filtered_tools, {tool["function"]["name"] for tool in filtered_tools} if filtered_tools else None # type: ignore[index]

    def chat_completion(self, payload: dict[str, object]) -> tuple[dict[str, object], str | None]:
        _, allowed_tool_names = self._resolve_tools(payload)
        lease = self.request_queue.acquire(f"chat:{payload.get('model', 'unknown')}")
        try:
            response, assistant_id = self._open_chat_stream(payload, preferred_account_index=self._get_preferred_account_index(lease.ticket))
        except Exception:
            lease.release()
            raise
        accumulator = GLMEventAccumulator(
            model=str(payload["model"]),
            allowed_tool_names=allowed_tool_names,
            fallback_tool_url=extract_recent_user_url(list(payload.get("messages", []))), # type: ignore[arg-type]
            debug_enabled=self.config.debug_dump_all,
            logger=self.logger,
        )
        try:
            for event in self._iter_sse_events(response):
                if not event:
                    continue
                status = event.get("status")
                self._raise_for_event_error(event, stream=False)
                accumulator.consume_event(event)
                if status in {"finish", "intervene"}:
                    return accumulator.build_response(), accumulator.conversation_id
        finally:
            response.close() # type: ignore
            self.delete_conversation(accumulator.conversation_id, assistant_id=assistant_id)
            lease.release()
        return accumulator.build_response(), accumulator.conversation_id

    def generate_images(self, payload: dict[str, object]) -> dict[str, object]:
        lease = self.request_queue.acquire(f"image:{payload.get('model', self.config.glm_image_model_name)}")
        try:
            response, assistant_id = self._open_image_stream(payload, preferred_account_index=self._get_preferred_account_index(lease.ticket))
        except Exception:
            lease.release()
            raise

        accumulator = GLMEventAccumulator(
            model=str(payload.get("model", self.config.glm_image_model_name)),
            debug_enabled=self.config.debug_dump_all,
            logger=self.logger,
        )
        try:
            for event in self._iter_sse_events(response):
                if not event:
                    continue
                status = event.get("status")
                accumulator.consume_event(event)
                if status == "finish":
                    return self._build_images_response(payload, event, accumulator)

            return self._build_images_response(payload, {}, accumulator)
        finally:
            response.close() # type: ignore
            self.delete_conversation(accumulator.conversation_id, assistant_id=assistant_id)
            lease.release()

    def stream_chat_completion(self, payload: dict[str, object]):
        _, allowed_tool_names = self._resolve_tools(payload)
        lease = self.request_queue.acquire(f"stream:{payload.get('model', 'unknown')}")
        try:
            response, assistant_id = self._open_chat_stream(payload, preferred_account_index=self._get_preferred_account_index(lease.ticket))
        except Exception:
            lease.release()
            raise

        accumulator = GLMEventAccumulator(
            model=str(payload["model"]),
            allowed_tool_names=allowed_tool_names,
            fallback_tool_url=extract_recent_user_url(list(payload.get("messages", []))), # type: ignore[arg-type]
            debug_enabled=self.config.debug_dump_all,
            logger=self.logger,
        )

        def generate():
            try:
                for event in self._iter_sse_events(response):
                    if event is _KEEPALIVE:
                        yield b": keepalive\n\n"
                        continue
                    if not event:
                        continue
                    self._raise_for_event_error(event, stream=True)
                    chunks, status = accumulator.consume_event(event)
                    for chunk in chunks:
                        yield chunk.encode("utf-8")

                    if status in {"finish", "intervene"}:
                        for chunk in accumulator.finalize(
                            status=status,
                            last_error=event.get("last_error") if isinstance(event.get("last_error"), dict) else None,
                        ):
                            yield chunk.encode("utf-8")
                        return

                for chunk in accumulator.finalize(status="stop"):
                    yield chunk.encode("utf-8")
            finally:
                response.close() # type: ignore
                self.delete_conversation(accumulator.conversation_id, assistant_id=assistant_id)
                lease.release()

        return generate()

    def _raise_for_event_error(self, event: dict[str, object], stream: bool) -> None:
        status = str(event.get("status", "")).strip().lower()
        last_error = event.get("last_error")
        event_error = self._extract_event_error(event)
        if status != "error" and not event_error and not isinstance(last_error, dict):
            return

        error_payload: dict[str, object] = {}
        if isinstance(last_error, dict):
            error_payload.update(last_error)
        if isinstance(event_error, dict):
            error_payload.update(event_error)
        if not error_payload:
            # Event-level status is "error" but no actual error payload.
            # GLM internally sets status "error" on intermediate events during
            # tool execution / reasoning.  Without a concrete error payload
            # this is not a real error; log and ignore.
            if status == "error" and self.logger:
                self.logger.debug(
                    "event status=error 但无错误负载, 忽略 (stream=%s)",
                    stream,
                )
            return

        error_code = error_payload.get("error_code", error_payload.get("code"))
        error_message = str(
            error_payload.get("err_msg")
            or error_payload.get("message")
            or ("GLM stream request error" if stream else "GLM request error")
        ).strip()
        detail = f"code={error_code} " if error_code is not None else ""
        raise UpstreamAPIError(
            status_code=502,
            message=f"GLM 上游返回错误 | {detail}{error_message}".strip(),
            payload=error_payload or event,
        )

    def _extract_event_error(self, event: dict[str, object]) -> dict[str, object] | None:
        parts = event.get("parts")
        if not isinstance(parts, list):
            return None
        event_status = str(event.get("status", "")).strip().lower()
        # GLM may mark individual parts (e.g. a reasoning segment) with status
        # "error" while other parts and the overall event are still fine —
        # especially during tool execution where parts finish at different
        # times.  Part-level status "error" is NEVER treated as fatal; it is a
        # normal part lifecycle state, not an actual error.  Only explicit
        # error dicts inside parts are treated as real errors, and even then
        # only when the event-level status is explicitly "error".
        if event_status != "error":
            return None
        # Check for explicit error dicts in parts (these indicate actual errors)
        for part in parts:
            if not isinstance(part, dict):
                continue
            error = part.get("error")
            if isinstance(error, dict) and error:
                return error
            # Log part-level status "error" for debugging but never treat as fatal
            part_status = str(part.get("status", "")).strip().lower()
            if part_status == "error" and self.logger:
                self.logger.debug(
                    "part status=error (event status=%s, 忽略, 非致命)",
                    event_status,
                )
        return None

    def delete_conversation(self, conversation_id: str, assistant_id: str | None = None) -> None:
        if not self.config.glm_delete_conversation:
            return
        if not conversation_id:
            self.logger.warning("跳过删除 GLM 会话：未获取到 conversation_id assistant_id=%s", assistant_id or self.config.glm_assistant_id)
            return

        actual_assistant_id = assistant_id or self.config.glm_assistant_id
        body = json.dumps(
            {
                "assistant_id": actual_assistant_id,
                "conversation_id": conversation_id,
            }
        ).encode("utf-8")
        try:
            def send_request(account_index: int, access_token: str):
                timestamp, nonce, sign = build_sign()
                request = urllib.request.Request(
                    self.config.delete_conversation_url,
                    method="POST",
                    data=body,
                    headers={
                        **self.auth.get_browser_headers(),
                        "Authorization": f"Bearer {access_token}",
                        "Referer": "https://chatglm.cn/main/alltoolsdetail",
                        "X-Nonce": nonce,
                        "X-Sign": sign,
                        "X-Timestamp": timestamp,
                    },
                )
                request.headers["X-Request-Id"] = self.auth.next_request_id_for_account(account_index)
                request.headers["X-Device-Id"] = self.auth.get_device_id_for_account(account_index)
                return open_upstream(request, timeout=self.config.request_timeout)

            with self._call_with_account_failover("delete_conversation", send_request) as response: # type: ignore
                payload = self.auth.read_json_response(response)
            status = payload.get("status", payload.get("code"))
            if status not in {0, None}:
                self.logger.warning(
                    "GLM 会话删除返回非成功状态 conversation_id=%s assistant_id=%s payload=%s",
                    conversation_id,
                    actual_assistant_id,
                    payload,
                )
                return
            self.logger.info(
                "已删除 GLM 会话 conversation_id=%s assistant_id=%s",
                conversation_id,
                actual_assistant_id,
            )
        except Exception as exc:
            self.logger.warning(
                "删除 GLM 会话失败 conversation_id=%s assistant_id=%s error=%s",
                conversation_id,
                actual_assistant_id,
                exc,
            )

    def _open_chat_stream(self, openai_payload: dict[str, object], preferred_account_index: int | None = None):
        requested_model = str(openai_payload.get("model", "glm-4"))
        upstream_model, assistant_id = resolve_upstream_model(requested_model, self.config)
        filtered_tools, _ = self._resolve_tools(openai_payload)
        converted_messages = convert_messages(
            messages=list(openai_payload.get("messages", [])), # type: ignore
            tools=filtered_tools,
            blocked_tool_names={name.strip() for name in self.config.blocked_tool_names if name.strip()},
            tool_choice=openai_payload.get("tool_choice"),
            server_side_tool_names=SERVER_SIDE_TOOL_NAMES,
            tool_result_max_chars=self.config.glm_tool_result_max_chars,
            context_max_tokens=self.config.glm_context_max_tokens,
        )
        debug_dump(self.logger, self.config.debug_dump_all, "OpenAI 原始 chat 请求 payload", openai_payload)
        debug_dump(self.logger, self.config.debug_dump_all, "转换后的 GLM messages", converted_messages)
        refs = self._upload_referenced_files(list(openai_payload.get("messages", []))) # type: ignore
        if refs:
            converted_messages[0]["content"] = refs + list(converted_messages[0]["content"]) # type: ignore
            debug_dump(self.logger, self.config.debug_dump_all, "附加上传引用后的 GLM messages", converted_messages)

        chat_mode = resolve_chat_mode(
            model=requested_model,
            reasoning_effort=openai_payload.get("reasoning_effort"),
            deep_research=openai_payload.get("deep_research"),
        )
        is_networking = resolve_networking(
            model=requested_model,
            web_search=openai_payload.get("web_search"),
        )

        request_body = json.dumps(
            {
                "assistant_id": assistant_id,
                "conversation_id": "",
                "project_id": "",
                "chat_type": "user_chat",
                "messages": converted_messages,
                "meta_data": {
                    "channel": "",
                    "chat_mode": chat_mode,
                    "draft_id": "",
                    "if_plus_model": True,
                    "input_question_type": "xxxx",
                    "is_networking": is_networking,
                    "is_test": False,
                    "platform": "pc",
                    "quote_log_id": "",
                    "cogview": {"rm_label_watermark": False},
                },
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

        self.logger.info(
            "转发请求 model=%s upstream=%s stream=%s",
            requested_model,
            upstream_model,
            openai_payload.get("stream"),
        )
        debug_dump(self.logger, self.config.debug_dump_all, "转发到 GLM 的 chat 原始请求体", request_body)

        def send_request(account_index: int, access_token: str):
            for attempt in range(self.config.glm_busy_max_retries + 1):
                try:
                    timestamp, nonce, sign = build_sign()
                    request = urllib.request.Request(
                        self.config.chat_stream_url,
                        data=request_body,
                        method="POST",
                        headers={
                            **self.auth.get_browser_headers(),
                            "Authorization": f"Bearer {access_token}",
                            "X-Nonce": nonce,
                            "X-Sign": sign,
                            "X-Timestamp": timestamp,
                        },
                    )
                    request.headers["X-Request-Id"] = self.auth.next_request_id_for_account(account_index)
                    request.headers["X-Device-Id"] = self.auth.get_device_id_for_account(account_index)
                    debug_dump(
                        self.logger,
                        self.config.debug_dump_all,
                        f"转发到 GLM 的 chat 请求头 account={account_index} attempt={attempt + 1}",
                        dict(request.header_items()),
                    )
                    return self._prepare_chat_response(
                        open_upstream(request, timeout=self.config.request_timeout)
                    )
                except urllib.error.HTTPError as exc:
                    error_payload = self._read_error_payload(exc)
                    if self._should_retry_busy_error(exc.code, error_payload) and attempt < self.config.glm_busy_max_retries:
                        wait_seconds = self.config.glm_busy_retry_interval
                        self.logger.warning(
                            "GLM 正在处理其他对话，等待重试 attempt=%s/%s wait=%.1fs account=%s",
                            attempt + 1,
                            self.config.glm_busy_max_retries,
                            wait_seconds,
                            account_index,
                        )
                        time.sleep(wait_seconds)
                        continue

                    message = self._build_error_message(exc.code, error_payload)
                    raise UpstreamAPIError(status_code=exc.code, message=message, payload=error_payload, headers=dict(exc.headers)) from exc

            raise UpstreamAPIError(status_code=429, message="GLM 长时间忙碌，请稍后重试。")

        response = self._call_with_account_failover(
            f"chat:{requested_model}",
            send_request,
            preferred_account_index=preferred_account_index,
        )
        return response, assistant_id

    def _open_image_stream(self, payload: dict[str, object], preferred_account_index: int | None = None):
        prompt = str(payload.get("prompt", "")).strip()
        if not prompt:
            raise UpstreamAPIError(status_code=400, message="图片生成请求缺少 prompt")

        size = str(payload.get("size", "1024x1024")).strip().lower()
        aspect_ratio = self._resolve_aspect_ratio(size)
        user_model = str(payload.get("model", self.config.glm_image_model_name)).strip() or self.config.glm_image_model_name
        request_body = json.dumps(
            {
                "assistant_id": self.config.glm_image_assistant_id,
                "conversation_id": "",
                "project_id": "",
                "chat_type": "user_chat",
                "meta_data": {
                    "cogview": {
                        "aspect_ratio": aspect_ratio,
                        "style": self._resolve_image_style(payload),
                        "scene": self._resolve_image_scene(payload),
                        "chat_model": "",
                        "rm_label_watermark": False,
                    },
                    "is_test": False,
                    "input_question_type": "xxxx",
                    "channel": "",
                    "draft_id": "",
                    "chat_mode": "",
                    "is_networking": False,
                    "quote_log_id": "",
                    "platform": "pc",
                },
                "messages": [
                    {
                        "role": "user",
                        "content": [{"type": "text", "text": prompt}],
                    }
                ],
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

        self.logger.info(
            "转发绘图请求 model=%s assistant_id=%s size=%s n=%s",
            user_model,
            self.config.glm_image_assistant_id,
            size,
            payload.get("n", 1),
        )
        debug_dump(self.logger, self.config.debug_dump_all, "OpenAI 原始 image 请求 payload", payload)
        debug_dump(self.logger, self.config.debug_dump_all, "转发到 GLM 的 image 原始请求体", request_body)

        def send_request(account_index: int, access_token: str):
            timestamp, nonce, sign = build_sign()
            request = urllib.request.Request(
                self.config.chat_stream_url,
                data=request_body,
                method="POST",
                headers={
                    **self.auth.get_browser_headers(),
                    "Authorization": f"Bearer {access_token}",
                    "X-Nonce": nonce,
                    "X-Sign": sign,
                    "X-Timestamp": timestamp,
                },
            )
            request.headers["X-Request-Id"] = self.auth.next_request_id_for_account(account_index)
            request.headers["X-Device-Id"] = self.auth.get_device_id_for_account(account_index)
            debug_dump(
                self.logger,
                self.config.debug_dump_all,
                f"转发到 GLM 的 image 请求头 account={account_index}",
                dict(request.header_items()),
            )
            try:
                return self._prepare_chat_response(open_upstream(request, timeout=self.config.request_timeout))
            except urllib.error.HTTPError as exc:
                error_payload = self._read_error_payload(exc)
                message = self._build_error_message(exc.code, error_payload)
                raise UpstreamAPIError(status_code=exc.code, message=message, payload=error_payload, headers=dict(exc.headers)) from exc

        response = self._call_with_account_failover(
            f"image:{user_model}",
            send_request,
            preferred_account_index=preferred_account_index,
        )
        return response, self.config.glm_image_assistant_id

    def _prepare_chat_response(self, response):
        content_type = response.headers.get("Content-Type", "").lower()
        if "application/json" in content_type:
            payload = self.auth.read_json_response(response)
            debug_dump(self.logger, self.config.debug_dump_all, "GLM 非流式原始 JSON 响应", payload)
            status = payload.get("status")
            message = str(payload.get("message", "")).strip()
            if status not in (0, None) or message:
                raise UpstreamAPIError(
                    status_code=502,
                    message=self._build_error_message(200, payload),
                    payload=payload,
                )

            response_body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            return BufferedReader(BytesIO(response_body))

        return self._wrap_stream_response(response)

    def _build_images_response(
        self,
        request_payload: dict[str, object],
        final_event: dict[str, object],
        accumulator: GLMEventAccumulator,
    ) -> dict[str, object]:
        requested_count = self._coerce_positive_int(request_payload.get("n"), default=1, maximum=10)
        response_format = str(request_payload.get("response_format", "url")).strip().lower()
        created = int(time.time())

        data: list[dict[str, object]] = []
        ordered_parts = list(accumulator.parts_by_logic_id.values())
        ordered_parts.sort(key=lambda item: str(item.get("logic_id", "")))

        for part in ordered_parts:
            if len(data) >= requested_count:
                break
            if not isinstance(part, dict):
                continue
            part_status = str(part.get("status", ""))
            if part_status != "finish":
                continue
            content_items = part.get("content", [])
            if not isinstance(content_items, list):
                continue
            for content in content_items:
                if len(data) >= requested_count:
                    break
                if not isinstance(content, dict) or content.get("type") != "image":
                    continue
                images = content.get("image", [])
                if not isinstance(images, list):
                    continue
                revised_prompt = str(content.get("code", "")).strip() or None
                for image in images:
                    if len(data) >= requested_count:
                        break
                    if not isinstance(image, dict):
                        continue
                    image_url = str(image.get("image_url", "")).strip()
                    if not image_url:
                        continue
                    item: dict[str, object] = {}
                    if response_format == "b64_json":
                        item["b64_json"] = self._download_image_as_base64(image_url)
                    else:
                        item["url"] = image_url
                    if revised_prompt:
                        item["revised_prompt"] = revised_prompt
                    data.append(item)

        if not data:
            raise UpstreamAPIError(
                status_code=502,
                message="GLM 绘图请求已完成，但未返回可用图片结果。",
                payload=final_event,
            )

        self.logger.info("绘图完成 返回图片数=%s", len(data))
        return {
            "created": created,
            "data": data,
        }

    def _resolve_aspect_ratio(self, size: str) -> str:
        normalized = size.strip().lower()
        if normalized in IMAGE_SIZE_TO_ASPECT_RATIO:
            return IMAGE_SIZE_TO_ASPECT_RATIO[normalized]
        if re.fullmatch(r"\d+x\d+", normalized):
            width_str, height_str = normalized.split("x", 1)
            width = max(int(width_str), 1)
            height = max(int(height_str), 1)
            return f"{width}:{height}"
        return "1:1"

    def _resolve_image_style(self, payload: dict[str, object]) -> str:
        style = str(payload.get("style", "none")).strip().lower()
        return style if style else "none"

    def _resolve_image_scene(self, payload: dict[str, object]) -> str:
        scene = str(payload.get("scene", "none")).strip().lower()
        return scene if scene else "none"

    def _coerce_positive_int(self, value: object, default: int, maximum: int) -> int:
        try:
            parsed = int(value) if value is not None else default # type: ignore
        except (TypeError, ValueError):
            parsed = default
        return max(1, min(parsed, maximum))

    def _download_image_as_base64(self, image_url: str) -> str:
        try:
            with open_upstream(image_url, timeout=self.config.request_timeout) as response:
                image_bytes = response.read()
            return base64.b64encode(image_bytes).decode("ascii")
        except Exception as exc:
            raise UpstreamAPIError(status_code=502, message=f"下载图片失败: {image_url} error={exc}") from exc

    def _iter_sse_events(self, response):
        pending = ""
        decoder = codecs.getincrementaldecoder("utf-8")("ignore")

        def emit_block(block: str):
            lines = [line for line in block.split("\n") if line.startswith("data:")]
            if not lines:
                return None
            payload = "\n".join(line[5:].strip() for line in lines)
            debug_dump(self.logger, self.config.debug_dump_all, "GLM 原始 SSE block", block)
            if payload == "[DONE]":
                return "[DONE]"
            try:
                parsed = json.loads(payload)
                debug_dump(self.logger, self.config.debug_dump_all, "GLM 解析后的 SSE payload", parsed)
                return parsed
            except json.JSONDecodeError:
                self.logger.debug("忽略无法解析的 SSE 片段: %s", payload)
                return None

        # Set a shorter socket timeout so we can send keepalive comments
        # to the client while waiting for the upstream to respond.
        # This prevents front-end idle-timeout errors (e.g. Open WebUI 45s).
        #
        # Access the underlying raw socket through the response chain:
        #   addinfourl -> HTTPResponse -> BufferedReader -> SocketIO -> socket
        # The urllib.response.addinfourl object's .fp is the HTTPResponse,
        # which has .fp = sock.makefile("rb") — a BufferedReader wrapping SocketIO.
        sock = None
        try:
            # Non-gzip: addinfourl.fp is HTTPResponse, HTTPResponse.fp is BufferedReader
            if hasattr(response, "fp") and hasattr(response.fp, "fp"):
                inner = response.fp.fp
                if hasattr(inner, "raw") and hasattr(inner.raw, "_sock"):
                    sock = inner.raw._sock
                elif hasattr(inner, "_sock"):
                    sock = inner._sock
            # Gzip: response is BufferedReader(GzipFile(fileobj=urllib_response))
            elif hasattr(response, "raw") and hasattr(response.raw, "fileobj"):
                fileobj = response.raw.fileobj
                if hasattr(fileobj, "fp") and hasattr(fileobj.fp, "fp"):
                    inner = fileobj.fp.fp
                    if hasattr(inner, "raw") and hasattr(inner.raw, "_sock"):
                        sock = inner.raw._sock
                    elif hasattr(inner, "_sock"):
                        sock = inner._sock
        except (AttributeError, TypeError, OSError):
            sock = None

        original_timeout = None
        if sock is not None and hasattr(sock, "settimeout"):
            try:
                original_timeout = sock.gettimeout()
                sock.settimeout(KEEPALIVE_INTERVAL)
            except OSError:
                pass

        # P0-6 SSE 硬超时看门狗：单条流超过 GLM_STREAM_MAX_SECONDS 即强制关流，
        # 解除阻塞读（对照 chatgpt2api 单流挂 29.5 分钟事故）。shutdown 底层
        # socket 确保阻塞中的 recv 在 Windows 上也能被唤醒。
        watchdog = None
        stream_started_at = time.monotonic()
        max_stream_seconds = int(self.config.glm_stream_max_seconds or 0)
        if max_stream_seconds > 0:
            def _force_close_stream() -> None:
                elapsed = time.monotonic() - stream_started_at
                self.logger.warning(
                    "上游 SSE 超过硬超时上限 %ss（实际存活 %.0fs），看门狗强制关流并按已收内容收尾",
                    max_stream_seconds,
                    elapsed,
                )
                try:
                    if sock is not None and hasattr(sock, "shutdown"):
                        sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    response.close()
                except Exception:
                    pass

            watchdog = threading.Timer(max_stream_seconds, _force_close_stream)
            watchdog.daemon = True
            watchdog.start()

        try:
            while True:
                stop_after_chunk = False
                try:
                    raw_chunk = response.read(4096)
                except socket.timeout:
                    self.logger.debug("上游 SSE 读取超时（keepalive），继续等待")
                    yield _KEEPALIVE
                    continue
                except http.client.IncompleteRead as exc:
                    raw_chunk = exc.partial or b""
                    stop_after_chunk = True
                    self.logger.warning("上游 SSE 连接提前断开，按已接收内容收尾 bytes=%s", len(raw_chunk))
                except (OSError, ValueError) as exc:
                    # 看门狗强制关流 / 传输层中断：对齐 IncompleteRead 的收尾语义
                    self.logger.warning("上游 SSE 读取中断，按已接收内容收尾 error=%s", exc)
                    break
                if not raw_chunk:
                    break

                pending += decoder.decode(raw_chunk, False).replace("\r\n", "\n")

                while "\n\n" in pending:
                    block, pending = pending.split("\n\n", 1)
                    event = emit_block(block.strip())
                    if event == "[DONE]":
                        return
                    if event is not None:
                        yield event

                if stop_after_chunk:
                    break
        finally:
            if watchdog is not None:
                watchdog.cancel()
            # Restore original socket timeout
            if sock is not None and hasattr(sock, "settimeout") and original_timeout is not None:
                sock.settimeout(original_timeout)

        remaining = decoder.decode(b"", True)
        if remaining:
            pending += remaining

        if pending.strip():
            event = emit_block(pending.strip())
            if event not in (None, "[DONE]"):
                yield event

    def _upload_referenced_files(self, messages: list[dict[str, object]]) -> list[dict[str, object]]:
        refs: list[dict[str, object]] = []
        for message in messages:
            content = message.get("content")
            if not isinstance(content, list):
                continue
            for item in content:
                if not isinstance(item, dict):
                    continue
                item_type = item.get("type")
                if item_type == "image_url":
                    url = item.get("image_url", {}).get("url")
                    if isinstance(url, str) and url:
                        ref = self._upload_file_reference(url, is_image=True)
                        if ref:
                            refs.append(ref)
                elif item_type == "file":
                    url = item.get("file_url", {}).get("url")
                    if isinstance(url, str) and url:
                        ref = self._upload_file_reference(url, is_image=False)
                        if ref:
                            refs.append(ref)
        if refs:
            self.logger.info("上传附件完成 成功数=%s", len(refs))
        return refs

    def _upload_file_reference(self, file_url: str, is_image: bool) -> dict[str, object] | None:
        try:
            filename, mime_type, payload = self._fetch_file_payload(file_url)
            boundary = _make_boundary()
            body = self._build_multipart(boundary, filename, mime_type, payload)
            upload_url = f"{self.config.glm_base_url}{FILE_UPLOAD_URL_SUFFIX}"
            debug_dump(
                self.logger,
                self.config.debug_dump_all,
                f"准备上传附件 url={file_url} filename={filename} mime={mime_type}",
                {"filename": filename, "mime_type": mime_type, "bytes": len(payload)},
            )

            def send_request(account_index: int, access_token: str):
                timestamp, nonce, sign = build_sign()
                request = urllib.request.Request(
                    upload_url,
                    method="POST",
                    data=body,
                    headers={
                        **self.auth.get_browser_headers(),
                        "Authorization": f"Bearer {access_token}",
                        "Content-Type": f"multipart/form-data; boundary={boundary}",
                        "Referer": "https://chatglm.cn/",
                        "X-Nonce": nonce,
                        "X-Sign": sign,
                        "X-Timestamp": timestamp,
                    },
                )
                request.headers["X-Request-Id"] = self.auth.next_request_id_for_account(account_index)
                request.headers["X-Device-Id"] = self.auth.get_device_id_for_account(account_index)
                debug_dump(
                    self.logger,
                    self.config.debug_dump_all,
                    f"转发到 GLM 的 file_upload 请求头 account={account_index}",
                    dict(request.header_items()),
                )
                debug_dump(
                    self.logger,
                    self.config.debug_dump_all,
                    f"转发到 GLM 的 file_upload 原始请求体 account={account_index}",
                    body,
                )
                return open_upstream(request, timeout=self.config.request_timeout)

            with self._call_with_account_failover("file_upload", send_request) as response: # type: ignore
                result = self.auth.read_json_response(response).get("result", {})
            debug_dump(self.logger, self.config.debug_dump_all, "GLM 文件上传响应 result", result)
            source_id = result.get("source_id") # type: ignore
            file_result_url = result.get("file_url", file_url) # type: ignore
            if not source_id:
                return None
            if is_image:
                return {"type": "image_url", "image_url": {"url": file_result_url or source_id}}
            return {"type": "file", "file": [{"source_id": source_id, "file_url": file_result_url}]}
        except Exception as exc:
            self.logger.warning("上传附件失败 url=%s error=%s", file_url, exc)
            return None

    def _fetch_file_payload(self, file_url: str) -> tuple[str, str, bytes]:
        if file_url.startswith("data:"):
            header, encoded = file_url.split(",", 1)
            mime_type = header.split(";")[0][5:] or "application/octet-stream"
            extension = mimetypes.guess_extension(mime_type) or ".bin"
            payload = base64.b64decode(encoded)
            return f"upload-{uuid.uuid4().hex}{extension}", mime_type, payload

        parsed = urllib.parse.urlparse(file_url)
        filename = parsed.path.rsplit("/", 1)[-1] or f"upload-{uuid.uuid4().hex}.bin"
        with open_upstream(file_url, timeout=self.config.request_timeout) as response:
            payload = response.read(FILE_SIZE_LIMIT + 1)
            if len(payload) > FILE_SIZE_LIMIT:
                raise ValueError("文件超过 100MB，拒绝上传。")
            mime_type = response.headers.get_content_type()
        mime_type = mime_type or mimetypes.guess_type(filename)[0] or "application/octet-stream"
        return filename, mime_type, payload

    def _build_multipart(self, boundary: str, filename: str, mime_type: str, payload: bytes) -> bytes:
        start = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: {mime_type}\r\n\r\n"
        ).encode("utf-8")
        end = f"\r\n--{boundary}--\r\n".encode("utf-8")
        return start + payload + end

    def _wrap_stream_response(self, response):
        content_encoding = response.headers.get("Content-Encoding", "").lower()
        if content_encoding == "gzip":
            return BufferedReader(gzip.GzipFile(fileobj=response))
        return response

    def _read_error_payload(self, error: urllib.error.HTTPError) -> dict[str, object]:
        try:
            raw_body = error.read()
            content_encoding = error.headers.get("Content-Encoding", "").lower()

            if content_encoding == "gzip":
                raw_body = gzip.decompress(raw_body)

            text = raw_body.decode("utf-8", errors="ignore")
        except Exception as exc:
            return {"message": f"读取上游错误响应失败: {exc}"}
        try:
            payload = json.loads(text)
            if isinstance(payload, dict):
                return payload
        except json.JSONDecodeError:
            pass
        return {"message": text}

    def _should_retry_busy_error(self, status_code: int, payload: dict[str, object]) -> bool:
        if status_code != 429:
            return False
        message = str(payload.get("message", ""))
        inner_status = payload.get("status")
        return inner_status == 10061 or "请等待其他对话生成完毕" in message

    def _build_error_message(self, status_code: int, payload: dict[str, object]) -> str:
        message = str(payload.get("message", "")).strip()
        inner_status = payload.get("status")
        rid = payload.get("rid")
        parts = [f"GLM 请求失败 HTTP {status_code}"]
        if inner_status is not None:
            parts.append(f"status={inner_status}")
        if message:
            parts.append(message)
        if rid:
            parts.append(f"rid={rid}")
        return " | ".join(parts)

    def _get_preferred_account_index(self, ticket: int) -> int | None:
        account_count = self.auth.get_account_count()
        if account_count <= 0:
            return None
        return ticket % account_count

    def _apply_request_pacing(self, account_index: int) -> None:
        """请求发起前的节奏控制（D3）：随机抖动 + 游客槽错峰 + 全局最小间隔（P0-8）。
        只影响发起时刻，不影响流内 keepalive（_iter_sse_events 的空闲计时从首个
        响应字节才开始）。"""
        jitter_ms = self.config.glm_request_jitter_ms
        if jitter_ms > 0:
            time.sleep(random.uniform(0, jitter_ms) / 1000.0)
        self.auth.apply_guest_stagger(account_index)
        wait_for = self._request_pacer.wait(self.config.glm_min_request_interval_ms)
        if wait_for > 0:
            time.sleep(wait_for)

    def _call_with_account_failover(
        self,
        request_name: str,
        operation: Callable[[int, str], object],
        preferred_account_index: int | None = None,
    ):
        account_count = self.auth.get_account_count()
        if account_count <= 0:
            raise RuntimeError("没有可用的 GLM 账号或游客 token 配置")
        start_index = preferred_account_index % account_count if preferred_account_index is not None else self.auth.get_current_account_index()
        last_exc: Exception | None = None
        idle_rounds = 0

        while True:
            executed = False
            for offset in range(account_count):
                account_index = (start_index + offset) % account_count
                if not self.auth.is_account_available(account_index):
                    continue  # 风控冷却 / 熔断摘除中的账号不硬打上游（快速重试等于火上浇油）
                guest_retry_limit = self.config.glm_guest_max_retries if self.auth.is_guest_account(account_index) else 0
                lock = self._account_locks[account_index % len(self._account_locks)]
                if not lock.acquire(blocking=False):
                    continue  # 单身份单飞：该账号有在飞请求，按 failover 顺序试下一个
                try:
                    for attempt in range(guest_retry_limit + 1):
                        try:
                            # 账号提示（P2.5 第二批）：CDP BrowserContext 池按它把
                            # 请求路由到本账号专属 context；随 attempt 结束清理。
                            set_request_account(account_index)
                            self._apply_request_pacing(account_index)
                            # 统计口径：一次 attempt = 一次完整上游尝试（含 token 刷新）；
                            # operation 返回 = 建联成功；流中途的失败属于流层（keepalive/
                            # 流尾兜底），不计入此处。
                            self.auth.record_request(account_index)
                            access_token = self.auth.get_access_token_for_account(account_index)
                            result = operation(account_index, access_token)
                            self.auth.record_result(account_index, True)
                            executed = True
                            set_request_account(None)
                            return result
                        except Exception as exc:
                            set_request_account(None)
                            last_exc = exc
                            self.auth.record_result(account_index, False, str(exc))                            # P0-1 分类先行：风控判定（401 需权威标记）与切号判定
                            # （TRANSIENT 不切号）都由 auth 按分类给出。
                            is_risk = self.auth.classify_risk_event(exc)
                            if is_risk:
                                self.auth.register_risk_event(account_index, exc)
                            should_switch = self.auth.should_switch_account(exc)
                            if should_switch:
                                self.auth.invalidate_account(account_index)
                            # 游客身份获取是无状态动作，任何分类的失败都可重取
                            # （含 TRANSIENT 网络抖动 —— 切号语义变了，重取韧性不变）
                            if attempt < guest_retry_limit:
                                if is_risk:
                                    # P0-2：风控退避合并上游明示的 Retry-After
                                    backoff = self.auth.next_risk_backoff(attempt, self.auth.parse_retry_after(exc))
                                else:
                                    ra = self.auth.parse_retry_after(exc)
                                    backoff = ra if ra is not None else 0.0
                                self.logger.warning(
                                    "游客账号请求失败，重新获取游客 ck 重试 attempt=%s/%s backoff=%.1fs request=%s account=%s error=%s",
                                    attempt + 1,
                                    guest_retry_limit,
                                    backoff,
                                    request_name,
                                    account_index,
                                    exc,
                                )
                                if backoff > 0:
                                    time.sleep(backoff)
                                continue
                            if not should_switch or account_count == 1:
                                raise
                            self.auth.advance_account(account_index, f"{request_name}: {exc}")
                            break
                finally:
                    lock.release()
            if not executed:
                # 所有账号或在飞（单飞占满）或冷却/熔断中：整体等待后重试，
                # 上限复用 busy 重试参数 —— 与"上游忙碌"同一档的耐心。
                idle_rounds += 1
                if idle_rounds > self.config.glm_busy_max_retries:
                    raise UpstreamAPIError(
                        status_code=429,
                        message="GLM 账号全部忙碌、风控冷却或熔断摘除中，请稍后重试。",
                    )
                time.sleep(self.config.glm_busy_retry_interval)
                continue
            break

        self.auth.reset_account_cycle()
        if last_exc is not None:
            raise last_exc
        raise RuntimeError(f"账号轮换失败：{request_name}")
