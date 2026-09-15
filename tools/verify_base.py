"""glm2api 底座存活验证脚本。

依次验证：/health、/v1/models、非流式对话、流式对话、带 tools 的工具调用桥。
纯标准库实现，不引入任何依赖。

用法：
    python tools/verify_base.py [base_url]
默认 base_url = http://127.0.0.1:8000
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
TIMEOUT = 180
OUT = "D:/GLM2api/artifacts/verify.txt"
os.makedirs(os.path.dirname(OUT), exist_ok=True)

PASS: list[str] = []
FAIL: list[str] = []
LOGLINES: list[str] = []


def emit(line: str) -> None:
    LOGLINES.append(line)


def report(ok: bool, name: str, detail: str = "") -> None:
    tag = "PASS" if ok else "FAIL"
    line = f"[{tag}] {name}"
    if detail:
        line += f" :: {detail}"
    emit(line)
    (PASS if ok else FAIL).append(name)


def get(path: str) -> tuple[int, object]:
    req = urllib.request.Request(BASE + path, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001
        return -1, f"{type(exc).__name__}: {exc}"


def post_chat(payload: dict, stream: bool) -> tuple[int, list[str]]:
    req = urllib.request.Request(
        BASE + "/v1/chat/completions",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            if not stream:
                return resp.status, [resp.read().decode("utf-8", "replace")]
            lines: list[str] = []
            for raw in resp:
                lines.append(raw.decode("utf-8", "replace").rstrip("\n"))
            return resp.status, lines
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        return exc.code, [body]
    except Exception as exc:  # noqa: BLE001
        return -1, [f"{type(exc).__name__}: {exc}"]


def main() -> int:
    emit(f"=== glm2api 底座验证 :: {BASE} ===")
    emit("")

    # 1. 健康检查
    code, body = get("/health")
    report(code == 200, "GET /health", f"{code} {str(body)[:120]}")

    # 2. 模型列表
    code, body = get("/v1/models")
    model_count = -1
    if code == 200:
        try:
            data = json.loads(str(body))
            model_count = len(data.get("data", []))
        except json.JSONDecodeError:
            pass
    report(code == 200 and model_count > 0, "GET /v1/models", f"{code} models={model_count}")

    # 3. 非流式对话
    t0 = time.time()
    code, chunks = post_chat(
        {
            "model": "glm-4-flash",
            "messages": [{"role": "user", "content": "只回答两个字：收到"}],
            "stream": False,
        },
        stream=False,
    )
    content = ""
    if code == 200:
        try:
            payload = json.loads(chunks[0])
            content = payload["choices"][0]["message"].get("content") or ""
        except Exception:  # noqa: BLE001
            content = ""
    elapsed = time.time() - t0
    report(
        code == 200 and bool(content.strip()),
        "非流式对话",
        f"{code} {elapsed:.1f}s content={content.strip()[:60]!r}",
    )

    # 4. 流式对话
    t0 = time.time()
    code, lines = post_chat(
        {
            "model": "glm-4-flash",
            "messages": [{"role": "user", "content": "从1数到5，只输出数字"}],
            "stream": True,
        },
        stream=True,
    )
    delta_text = ""
    saw_done = False
    chunk_count = 0
    for line in lines:
        if line.startswith("data: "):
            body_str = line[6:].strip()
            if body_str == "[DONE]":
                saw_done = True
                continue
            chunk_count += 1
            try:
                obj = json.loads(body_str)
                delta = obj["choices"][0].get("delta", {})
                delta_text += delta.get("content") or ""
            except Exception:  # noqa: BLE001
                pass
    elapsed = time.time() - t0
    report(
        code == 200 and bool(delta_text.strip()) and saw_done,
        "流式对话",
        f"{code} {elapsed:.1f}s chunks={chunk_count} done={saw_done} text={delta_text.strip()[:60]!r}",
    )

    # 5. 工具调用桥（DSML 协议）
    tools = [
        {
            "type": "function",
            "function": {
                "name": "get_weather",
                "description": "查询指定城市的当前天气",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "city": {"type": "string", "description": "城市名称"},
                        "unit": {"type": "string", "description": "温度单位", "enum": ["c", "f"]},
                    },
                    "required": ["city"],
                },
            },
        }
    ]
    t0 = time.time()
    code, lines = post_chat(
        {
            "model": "glm-4-flash",
            "messages": [{"role": "user", "content": "帮我查一下上海现在的天气怎么样"}],
            "tools": tools,
            "stream": True,
        },
        stream=True,
    )
    tool_names: list[str] = []
    tool_args: list[str] = []
    leaked_markup = False
    for line in lines:
        if not line.startswith("data: "):
            continue
        body_str = line[6:].strip()
        if body_str == "[DONE]":
            continue
        try:
            obj = json.loads(body_str)
            delta = obj["choices"][0].get("delta", {})
        except Exception:  # noqa: BLE001
            continue
        for tc in delta.get("tool_calls") or []:
            fn = tc.get("function") or {}
            if fn.get("name"):
                tool_names.append(fn["name"])
            if fn.get("arguments"):
                tool_args.append(fn["arguments"])
        text = delta.get("content") or ""
        if "DSML" in text or "<|DSML|" in text:
            leaked_markup = True
    elapsed = time.time() - t0
    joined_args = "".join(tool_args)
    report(
        code == 200 and bool(tool_names),
        "工具调用桥 (DSML -> tool_calls)",
        f"{code} {elapsed:.1f}s names={tool_names} args={joined_args[:160]!r}",
    )
    report(
        not leaked_markup,
        "DSML 标记未泄漏到正文",
        "正文中未出现 <|DSML| 字样" if not leaked_markup else "正文泄漏了 DSML 标记！",
    )

    print("\n=== 汇总 ===", flush=True)
    print(f"PASS {len(PASS)} / FAIL {len(FAIL)}", flush=True)
    for name in FAIL:
        print(f"  FAILED: {name}", flush=True)

    emit("")
    emit("=== 汇总 ===")
    emit(f"PASS {len(PASS)} / FAIL {len(FAIL)}")
    for name in FAIL:
        emit(f"  FAILED: {name}")
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(LOGLINES) + "\n")
    return 0 if not FAIL else 1


if __name__ == "__main__":
    raise SystemExit(main())
