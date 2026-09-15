"""抓取带 tools 请求的原始 SSE 流，用于定位 DSML 解析断点。

用法：
    python tools/raw_tool_stream.py [base_url] [out_file]
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
OUT = sys.argv[2] if len(sys.argv) > 2 else "D:/GLM2api/artifacts/raw_tool.txt"
os.makedirs(os.path.dirname(OUT), exist_ok=True)

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

payload = {
    "model": "glm-4-flash",
    "messages": [{"role": "user", "content": "帮我查一下上海现在的天气怎么样"}],
    "tools": TOOLS,
    "stream": True,
}

req = urllib.request.Request(
    BASE + "/v1/chat/completions",
    data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
    headers={"Content-Type": "application/json"},
    method="POST",
)

lines: list[str] = []
with urllib.request.urlopen(req, timeout=300) as resp:
    lines.append(f"HTTP {resp.status}")
    for raw in resp:
        lines.append(raw.decode("utf-8", "replace").rstrip("\n"))

with open(OUT, "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines))

print(f"wrote {len(lines)} lines to {OUT}")
