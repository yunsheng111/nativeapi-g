"""glm2api 全链路压测脚本（P5-c）。

对中转服务做受控压测，三种 profile：
    local  —— GET /health 与 GET /v1/models 交替，只打不耗上游的端点，测面板/协议层开销；
    chat   —— POST /v1/chat/completions 非流式单条短消息，走真实上游（风控敏感）；
    tools  —— 声明 get_weather 工具的请求，成功 = 响应含 tool_calls 且 finish_reason=tool_calls
              （判定口径对齐 tools/probe_tools.py 的工具桥探针）。

设计取舍：失败零重试。压测要的是真实成功率与真实延迟分位，任何重试都会把上游波动
美化掉，让失败率与 p99 失真——所以一次失败就是一次失败，如实归类、如实统计。

用法：
    python tools/loadtest.py --base http://127.0.0.1:8000 --profile chat --n 10 --threads 2

退出码：全成功 0，否则 1（可被 CI/脚本消费）。
纯标准库实现（urllib.request / threading / queue / argparse / statistics）。
"""

from __future__ import annotations

import argparse
import json
import queue
import socket
import statistics
import sys
import threading
import time
import urllib.error
import urllib.request

DEFAULT_BASE = "http://127.0.0.1:8000"
DEFAULT_MODEL = "glm-4-flash"
# chat/tools 走真实上游，默认量级刻意压低：n=10、threads=2（可调，但有风控提示）
DEFAULT_N = 10
DEFAULT_THREADS = 2
DEFAULT_TIMEOUT = 120

CHAT_PROMPT = "回复 OK 两个字母即可"
TOOLS_PROMPT = "帮我查一下上海现在的天气怎么样"

# 失败分类口径：HTTP 状态码（细分到码）/ 超时 / 连接错误 / 响应不符合 profile 判定
CAT_HTTP = "http_error"
CAT_TIMEOUT = "timeout"
CAT_CONN = "connection_error"
CAT_PROFILE = "profile_mismatch"

# 与 tools/probe_tools.py 完全一致的工具声明，保证 tools 档与探针同构可比
TOOLS_DECLARATION = [
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="glm2api 全链路压测（P5-c）：local=本地端点 / chat=真实上游对话 / tools=工具调用桥",
    )
    parser.add_argument("--base", default=DEFAULT_BASE, help="被测服务地址（默认 %(default)s）")
    parser.add_argument(
        "--profile",
        choices=("local", "chat", "tools"),
        default="chat",
        help="压测档位（默认 chat）",
    )
    parser.add_argument("--n", type=int, default=DEFAULT_N, help="总请求数（默认 10）")
    parser.add_argument(
        "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help="并发线程数（建议不超过服务端 GLM_MAX_CONCURRENCY，默认 2）",
    )
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="单请求超时秒（默认 120）")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="chat/tools 使用的模型名（默认 glm-4-flash）")
    parser.add_argument(
        "--mode",
        default="",
        help="附加请求头 X-GLM2API-Tool-Mode 的值（passthrough/builtin），默认不发送",
    )
    parser.add_argument("--json", default="", help="结果 JSON 落盘路径（可选）")
    return parser.parse_args()


def _force_utf8_stdout() -> None:
    """Windows 控制台默认 GBK，中文进度行可能直接 UnicodeEncodeError，统一按 UTF-8 输出。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def _clean(text: str, limit: int = 200) -> str:
    """压平换行并截断，让失败样本既能看懂又能安全进单行进度与 JSON。"""
    return " ".join(str(text).split())[:limit]


def endpoint_for(profile: str, index: int) -> tuple[str, str]:
    """返回该任务序号对应的 (method, path)。local 档奇数打 /health、偶数打 /v1/models 交替。"""
    if profile == "local":
        return "GET", "/health" if index % 2 == 1 else "/v1/models"
    return "POST", "/v1/chat/completions"


def check_profile(profile: str, path: str, status: int, body: str) -> tuple[bool, str]:
    """按 profile 判定 2xx 响应是否合格。返回 (是否合格, 失败原因)。"""
    if status != 200:
        return False, f"HTTP {status}"
    if profile == "local":
        if path == "/health":
            return True, ""
        # /v1/models 走协议层有效性：JSON 可解析且含 data 列表（对齐 verify_base 的口径）
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return False, "响应不是合法 JSON"
        if not isinstance(data.get("data"), list):
            return False, "响应缺少 data 列表"
        return True, ""
    try:
        data = json.loads(body)
        choice = data["choices"][0]
    except (json.JSONDecodeError, KeyError, IndexError, TypeError):
        return False, "响应不是合法的 chat.completion JSON"
    message = choice.get("message") or {}
    if profile == "chat":
        content = str(message.get("content") or "").strip()
        if not content:
            return False, f"content 为空 finish_reason={choice.get('finish_reason')!r}"
        return True, ""
    # tools 档：tool_calls 出现且 finish_reason=tool_calls
    tool_calls = message.get("tool_calls") or []
    if not tool_calls:
        return False, f"未产生 tool_calls finish_reason={choice.get('finish_reason')!r}"
    if choice.get("finish_reason") != "tool_calls":
        return False, f"finish_reason={choice.get('finish_reason')!r} (期望 tool_calls)"
    return True, ""


def run_one(index: int, args: argparse.Namespace, payload: dict | None) -> dict:
    """执行单个请求并返回结果记录。失败零重试——压测测的是真实成功率。"""
    method, path = endpoint_for(args.profile, index)
    headers = {"Content-Type": "application/json"}
    if args.mode:
        headers["X-GLM2API-Tool-Mode"] = args.mode
    data = None
    if method == "POST":
        # 中文经由 dict -> json.dumps(ensure_ascii=False) -> UTF-8 字节，绕开控制台编码坑
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        args.base.rstrip("/") + path,
        data=data,
        headers=headers,
        method=method,
    )

    status = -1
    category = ""
    detail = ""
    body = ""
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as resp:
            status = resp.status
            body = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status = exc.code
        try:
            body = exc.read().decode("utf-8", "replace")
        except OSError:
            body = ""
        category = f"{CAT_HTTP}:{status}"
        detail = _clean(body)
    except urllib.error.URLError as exc:
        # URLError 包着底层原因：reason 是超时才算超时，其余（拒连/断连/DNS）归连接错误
        if isinstance(exc.reason, (socket.timeout, TimeoutError)):
            category = CAT_TIMEOUT
            detail = f"urlopen 超时 {args.timeout}s"
        else:
            category = CAT_CONN
            detail = _clean(str(exc.reason))
    except (socket.timeout, TimeoutError):
        # 读响应体中途超时不会包成 URLError，而是直接抛 socket.timeout
        category = CAT_TIMEOUT
        detail = f"读响应超时 {args.timeout}s"
    except OSError as exc:
        # ConnectionRefusedError / ConnectionResetError 等全部归连接错误
        category = CAT_CONN
        detail = _clean(str(exc))

    elapsed_ms = (time.perf_counter() - t0) * 1000
    if not category:
        ok, why = check_profile(args.profile, path, status, body)
        if not ok:
            category = CAT_PROFILE
            detail = _clean(why)
    return {
        "index": index,
        "endpoint": f"{method} {path}",
        "ok": not category,
        "status": status,
        "elapsed_ms": round(elapsed_ms, 1),
        "category": category,
        "detail": detail,
    }


def print_progress(result: dict, total: int) -> None:
    tag = "OK" if result["ok"] else "FAIL"
    status = str(result["status"]) if result["status"] > 0 else "-"
    width = max(2, len(str(total)))
    line = (
        f"[#{result['index']:>{width}}/{total}] {tag:<4} {status:>3} "
        f"{result['elapsed_ms']:>9.1f}ms  {result['endpoint']}"
    )
    if not result["ok"]:
        line += f"  :: {result['category']}"
        if result["detail"]:
            line += f" ({result['detail'][:80]})"
    print(line, flush=True)


def worker(task_q: "queue.Queue[int]", results: list[dict], lock: threading.Lock,
           args: argparse.Namespace, payload: dict | None) -> None:
    """消费线程：从任务队列取序号，跑一个请求，把结果在锁保护下收集并打进度行。"""
    while True:
        try:
            index = task_q.get_nowait()
        except queue.Empty:
            return
        result = run_one(index, args, payload)
        with lock:
            results.append(result)
            print_progress(result, args.n)
        task_q.task_done()


def percentiles(sorted_ms: list[float], wanted: tuple[int, ...]) -> dict[str, float]:
    """输入升序延迟序列，输出 {pXX: 毫秒}。线性插值口径与 numpy percentile 一致。"""
    if not sorted_ms:
        return {}
    if len(sorted_ms) == 1:
        return {f"p{p}": sorted_ms[0] for p in wanted}
    cuts = statistics.quantiles(sorted_ms, n=100, method="inclusive")
    # cuts[0..98] 依次是 1%..99% 分位
    return {f"p{p}": cuts[p - 1] for p in wanted if 1 <= p <= 99}


def summarize(results: list[dict], args: argparse.Namespace, total_seconds: float, started_at: str) -> dict:
    ok_n = sum(1 for r in results if r["ok"])
    fail_n = len(results) - ok_n
    lat = sorted(r["elapsed_ms"] for r in results)
    lat_summary: dict[str, float] = {}
    if lat:
        lat_summary.update(percentiles(lat, (50, 90, 95, 99)))
        lat_summary["min"] = lat[0]
        lat_summary["max"] = lat[-1]
    fail_categories: dict[str, int] = {}
    for r in results:
        if not r["ok"]:
            key = r["category"] or "unknown"
            fail_categories[key] = fail_categories.get(key, 0) + 1
    rps = (len(results) / total_seconds) if total_seconds > 0 else 0.0
    rate = (ok_n / len(results) * 100) if results else 0.0
    return {
        "meta": {
            "profile": args.profile,
            "base": args.base,
            "model": args.model if args.profile != "local" else "",
            "n": args.n,
            "threads": args.threads,
            "timeout_s": args.timeout,
            "tool_mode": args.mode,
            "started_at": started_at,
            "total_seconds": round(total_seconds, 3),
        },
        "summary": {
            "ok": ok_n,
            "fail": fail_n,
            "success_rate": round(rate, 1),
            "rps": round(rps, 4),
            "latency_ms": {k: round(v, 1) for k, v in lat_summary.items()},
            "fail_categories": fail_categories,
        },
        "results": results,
    }


def print_summary(report: dict) -> None:
    meta = report["meta"]
    s = report["summary"]
    lat = s["latency_ms"]
    lines = [
        "=" * 56,
        "glm2api 压测汇总",
        "-" * 56,
        f"profile       : {meta['profile']}",
        f"base           : {meta['base']}",
    ]
    if meta["model"]:
        lines.append(f"model          : {meta['model']}")
    if meta["tool_mode"]:
        lines.append(f"tool_mode      : {meta['tool_mode']} (X-GLM2API-Tool-Mode)")
    lines += [
        f"n / threads    : {meta['n']} / {meta['threads']}",
        f"timeout        : {meta['timeout_s']} s",
        f"started_at     : {meta['started_at']}",
        f"total_seconds  : {meta['total_seconds']}",
        f"ok / fail      : {s['ok']} / {s['fail']}   success_rate={s['success_rate']}%",
        f"rps            : {s['rps']} (总耗时口径 = n / total_seconds)",
        "latency_ms     : "
        + " ".join(f"{k}={lat[k]}" for k in ("p50", "p90", "p95", "p99") if k in lat),
        "                 "
        + " ".join(f"{k}={lat[k]}" for k in ("min", "max") if k in lat),
    ]
    if s["fail_categories"]:
        lines.append("fail_categories:")
        for key, count in sorted(s["fail_categories"].items()):
            lines.append(f"  {key:<28} x{count}")
        lines.append("fail_details:")
        for r in report["results"]:
            if r["ok"]:
                continue
            lines.append(f"  [#{r['index']}] {r['category']} {r['elapsed_ms']:.1f}ms {r['endpoint']}")
            if r["detail"]:
                lines.append(f"        {r['detail']}")
    else:
        lines.append("fail_categories: (无)")
    lines.append("=" * 56)
    print("\n".join(lines), flush=True)


def main() -> int:
    args = parse_args()
    _force_utf8_stdout()
    if args.n < 1 or args.threads < 1:
        print("参数错误：--n 与 --threads 至少为 1", flush=True)
        return 2

    payload: dict | None = None
    if args.profile == "chat":
        payload = {
            "model": args.model,
            "messages": [{"role": "user", "content": CHAT_PROMPT}],
            "stream": False,
        }
    elif args.profile == "tools":
        payload = {
            "model": args.model,
            "messages": [{"role": "user", "content": TOOLS_PROMPT}],
            "tools": TOOLS_DECLARATION,
            "stream": False,
        }

    print(
        f"=== glm2api 压测 :: profile={args.profile} base={args.base} "
        f"n={args.n} threads={args.threads} timeout={args.timeout}s ===",
        flush=True,
    )
    if args.profile in ("chat", "tools"):
        print(
            "[风控提示] 该档位走真实上游（GLM 网页协议）：服务端有全局并发上限"
            "（GLM_MAX_CONCURRENCY）、单身份单飞与最小间隔节流。\n"
            "           建议 threads <= 服务端并发配置值、n 不贪多，"
            "避免高并发打穿上游触发风控。",
            flush=True,
        )

    # 任务队列 + N 个消费线程：任务即请求序号，local 档由序号决定交替端点
    task_q: "queue.Queue[int]" = queue.Queue()
    for i in range(1, args.n + 1):
        task_q.put(i)
    results: list[dict] = []
    lock = threading.Lock()
    worker_count = max(1, min(args.threads, args.n))
    started_at = time.strftime("%Y-%m-%dT%H:%M:%S")
    t0 = time.perf_counter()
    workers = [
        threading.Thread(target=worker, args=(task_q, results, lock, args, payload), daemon=True)
        for _ in range(worker_count)
    ]
    for th in workers:
        th.start()
    for th in workers:
        th.join()
    total_seconds = time.perf_counter() - t0

    results.sort(key=lambda r: r["index"])
    report = summarize(results, args, total_seconds, started_at)
    print(flush=True)
    print_summary(report)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        print(f"结果已落盘: {args.json}", flush=True)

    return 0 if report["summary"]["fail"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
