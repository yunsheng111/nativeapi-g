"""量化工具调用桥的稳定性：同一请求重复多次，统计成功/失败，并保存失败样本。

用法：
    python tools/probe_tools.py [base_url] [rounds] [model]
默认 base_url=http://127.0.0.1:8000 rounds=6 model=glm-4-flash
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
ROUNDS = int(sys.argv[2]) if len(sys.argv) > 2 else 6
MODEL = sys.argv[3] if len(sys.argv) > 3 else "glm-4-flash"
OUT = "D:/GLM2api/artifacts/probe_tools.txt"
FAIL_DIR = "D:/GLM2api/artifacts/fail_samples"

import os  # noqa: E402

os.makedirs(FAIL_DIR, exist_ok=True)

TOOLS = [
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

PROMPT = "帮我查一下上海现在的天气怎么样"

records: list[str] = []
ok = 0
fail = 0

for i in range(1, ROUNDS + 1):
    payload = {
        "model": MODEL,
        "messages": [{"role": "user", "content": PROMPT}],
        "tools": TOOLS,
        "stream": True,
    }
    req = urllib.request.Request(
        BASE + "/v1/chat/completions",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    raw_lines: list[str] = []
    t0 = time.time()
    status = -1
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            status = resp.status
            for raw in resp:
                raw_lines.append(raw.decode("utf-8", "replace").rstrip("\n"))
    except urllib.error.HTTPError as exc:
        status = exc.code
        raw_lines.append("HTTPError " + exc.read().decode("utf-8", "replace"))
    except Exception as exc:  # noqa: BLE001
        raw_lines.append(f"{type(exc).__name__}: {exc}")
    elapsed = time.time() - t0

    names: list[str] = []
    args = ""
    text = ""
    finish = None
    leaked = False
    for line in raw_lines:
        if not line.startswith("data: "):
            continue
        body = line[6:].strip()
        if body == "[DONE]":
            continue
        try:
            obj = json.loads(body)
            choice = obj["choices"][0]
        except Exception:  # noqa: BLE001
            continue
        delta = choice.get("delta") or {}
        if choice.get("finish_reason"):
            finish = choice["finish_reason"]
        for tc in delta.get("tool_calls") or []:
            fn = tc.get("function") or {}
            if fn.get("name"):
                names.append(fn["name"])
            if fn.get("arguments"):
                args += fn["arguments"]
        piece = delta.get("content") or ""
        text += piece
        if "<|DSML|" in piece or "DSML" in piece:
            leaked = True

    good = bool(names) and not leaked
    if good:
        ok += 1
        records.append(
            f"[{i:>2}] OK   {elapsed:5.1f}s name={names} finish={finish} args={args[:110]!r}"
        )
    else:
        fail += 1
        records.append(
            f"[{i:>2}] FAIL {elapsed:5.1f}s status={status} names={names} "
            f"finish={finish} leaked={leaked} content={text.strip()[:200]!r}"
        )
        with open(f"{FAIL_DIR}/fail_{i}.txt", "w", encoding="utf-8") as fh:
            fh.write("\n".join(raw_lines))
    print(records[-1], flush=True)

total = ok + fail
rate = (ok / total * 100) if total else 0.0
summary = [
    f"=== 工具调用桥稳定性探针 :: model={MODEL} rounds={total} ===",
    *records,
    "",
    f"成功 {ok} / 失败 {fail}  成功率 {rate:.0f}%",
    f"失败原始流样本已保存到 {FAIL_DIR}/",
]
with open(OUT, "w", encoding="utf-8") as fh:
    fh.write("\n".join(summary))

print(f"\n成功率 {rate:.0f}%  ({ok}/{total})", flush=True)
print(f"详情: {OUT}", flush=True)
