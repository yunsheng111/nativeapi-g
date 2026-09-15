"""Ensure the glm2api server is running, then run the panel self-check.

Combines server bootstrap + browser-driven UI regression into one entry point
so a single command can verify the admin panel end to end.

Output: artifacts/run_panel_test.txt
        artifacts/server_run.log   (server stdout, only if we started it)
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RELAY = ROOT / "relay"
SRC = RELAY / "src"
PY = sys.executable
BASE = "http://127.0.0.1:8000"

ART = ROOT / "artifacts"
ART.mkdir(parents=True, exist_ok=True)
LOG = ART / "run_panel_test.txt"
SRV_LOG = ART / "server_run.log"

out: list[str] = []


def log(text: str = "") -> None:
    out.append(str(text))


def child_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC)
    env["ADMIN_KEY"] = "glm2api-admin"
    env["HOST"] = "127.0.0.1"
    env["PORT"] = "8000"
    env["PYTHONUNBUFFERED"] = "1"
    return env


def probe(timeout: float = 2.5) -> tuple[bool, str]:
    try:
        with urllib.request.urlopen(BASE + "/health", timeout=timeout) as resp:
            return resp.status == 200, resp.read().decode("utf-8", "replace")[:160]
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


def ensure_server() -> subprocess.Popen | None:
    ok, detail = probe()
    if ok:
        log(f"[server] 已在运行 :: {detail}")
        return None

    log(f"[server] 未就绪（{detail}），启动中 ...")
    srv_log = open(SRV_LOG, "w", encoding="utf-8")  # noqa: SIM115
    # 独立进程组，避免随本脚本退出而被回收
    flags = 0
    if os.name == "nt":
        flags = subprocess.CREATE_NEW_PROCESS_GROUP | 0x00000008  # DETACHED_PROCESS
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
        ok, detail = probe()
        if ok:
            log(f"[server] 已就绪（{i + 1}s） :: {detail}")
            return proc
        if proc.poll() is not None:
            log(f"[server] 进程已退出，code={proc.returncode}")
            break
    log(f"[server] 启动失败 :: {detail}")
    return proc


def run_panel(browser: str) -> tuple[int, str]:
    cmd = [PY, str(ROOT / "tools" / "test_panel.py"), BASE, browser]
    log(f"[panel] 执行 :: {' '.join(cmd)}")
    try:
        res = subprocess.run(
            cmd,
            cwd=str(RELAY),
            env=child_env(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=420,
        )
    except subprocess.TimeoutExpired:
        return 124, "[panel] 超时"
    return res.returncode, (res.stdout or "") + (res.stderr or "")


def main() -> int:
    log("=== 面板端到端验证 ===")
    log("")

    ensure_server()
    log("")

    last = (1, "")
    for browser in ("edge", "chrome"):
        code, text = run_panel(browser)
        last = (code, text)
        log(text)
        if code == 0:
            log(f"[panel] PASS（{browser}）")
            break
        log(f"[panel] FAIL（{browser}）code={code}")
        if "浏览器" not in text and "browser" not in text.lower():
            log("[panel] 非浏览器问题，不再重试其它内核")
            break
        log("")

    code, _ = last
    log("")
    log(f"=== 总结果: {'PASS' if code == 0 else 'FAIL'} (code={code}) ===")
    LOG.write_text("\n".join(out) + "\n", encoding="utf-8")
    print("\n".join(out))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
