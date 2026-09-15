"""一键跑完全部自检脚本，并汇总 PASS/FAIL。

用法：
    python tools/run_all_checks.py            # 常规自检（含网络与真浏览器）
    python tools/run_all_checks.py --no-net   # 跳过需要外网的基线连通检查
    python tools/run_all_checks.py --soak     # 额外跑工具桥稳定性压测

会先确保 glm2api 服务在 127.0.0.1:8000 上运行。

输出：artifacts/run_all_checks.txt
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RELAY = ROOT / "relay"
SRC = RELAY / "src"
PY = sys.executable
BASE = "http://127.0.0.1:8000"
LOG = ROOT / "artifacts" / "run_all_checks.txt"

# (脚本, 说明, 是否依赖外网)
CHECKS: list[tuple[str, str, bool]] = [
    ("verify_base.py", "基线连通 / 模型列表 / 工具桥", True),
    ("test_cdp.py", "自研 CDP 客户端自检", False),
    ("test_import.py", "账号存储 / 文本抽取 / 导入逻辑", True),
    ("test_admin_ext.py", "管理扩展端点集成", False),
    ("test_login_capture.py", "登录导入正向抓取链路", True),
    ("test_panel.py", "管理面板界面（CDP 驱动）", False),
]

SOAK = ("probe_tools.py", "工具桥稳定性压测（51 次）")

SUMMARY = re.compile(r"汇总:\s*PASS\s*(\d+)\s*/\s*FAIL\s*(\d+)")

out: list[str] = []


def log(t: str = "") -> None:
    out.append(str(t))


def child_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC)
    env["ADMIN_KEY"] = "glm2api-admin"
    env["HOST"] = "127.0.0.1"
    env["PORT"] = "8000"
    env["PYTHONUNBUFFERED"] = "1"
    return env


def probe(timeout: float = 2.5) -> bool:
    try:
        with urllib.request.urlopen(BASE + "/health", timeout=timeout) as resp:
            return resp.status == 200
    except Exception:  # noqa: BLE001
        return False


def ensure_server() -> None:
    if probe():
        log("[server] 已在运行")
        return
    log("[server] 未就绪，启动中 ...")
    srv_log = open(ROOT / "artifacts" / "server_run.log", "w", encoding="utf-8")  # noqa: SIM115
    flags = 0
    if os.name == "nt":
        flags = subprocess.CREATE_NEW_PROCESS_GROUP | 0x00000008
    proc = subprocess.Popen(
        [PY, "-m", "glm2api"],
        cwd=str(RELAY),
        env=child_env(),
        stdout=srv_log,
        stderr=subprocess.STDOUT,
        creationflags=flags,
    )
    for i in range(40):
        time.sleep(1.0)
        if probe():
            log(f"[server] 已就绪（{i + 1}s）")
            return
        if proc.poll() is not None:
            log(f"[server] 进程退出 code={proc.returncode}，详见 artifacts/server_run.log")
            return
    log("[server] 启动超时")


def run_one(script: str, label: str) -> tuple[int, int, int]:
    log("")
    log(f"┌─ {script}  ·  {label}")
    t0 = time.time()
    try:
        res = subprocess.run(
            [PY, str(ROOT / "tools" / script), BASE],
            cwd=str(RELAY),
            env=child_env(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=900,
        )
        text = (res.stdout or "") + (res.stderr or "")
        code = res.returncode
    except subprocess.TimeoutExpired:
        text, code = "[超时]", 124

    match = None
    for line in text.splitlines():
        m = SUMMARY.search(line)
        if m:
            match = m
    p, f = (int(match.group(1)), int(match.group(2))) if match else (0, 0)
    cost = time.time() - t0
    log(f"└─ {'PASS' if code == 0 else 'FAIL'}  {p} 通过 / {f} 失败  ({cost:.1f}s)")
    if code != 0 and not match:
        for line in text.strip().splitlines()[-12:]:
            log(f"     {line}")
    return code, p, f


def main() -> int:
    args = set(sys.argv[1:])
    log("=== glm2api 全量自检 ===")
    log(f"时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    log("")
    ensure_server()

    todo = list(CHECKS)
    if "--no-net" in args:
        todo = [c for c in todo if not c[2]]
        log("")
        log("[info] --no-net：已跳过需要外网的检查")
    if "--soak" in args:
        todo.append(SOAK)

    total_p = total_f = 0
    failed_scripts: list[str] = []
    for script, label, _net in todo:
        code, p, f = run_one(script, label)
        total_p += p
        total_f += f
        if code != 0:
            failed_scripts.append(script)

    log("")
    log("=== 汇总 ===")
    log(f"脚本 {len(todo) - len(failed_scripts)}/{len(todo)} 通过")
    log(f"断言 {total_p} 通过 / {total_f} 失败")
    if failed_scripts:
        log(f"失败脚本: {', '.join(failed_scripts)}")
    log(f"总结果: {'PASS' if not failed_scripts else 'FAIL'}")

    LOG.write_text("\n".join(out) + "\n", encoding="utf-8")
    print("\n".join(out))
    return 0 if not failed_scripts else 1


if __name__ == "__main__":
    raise SystemExit(main())
