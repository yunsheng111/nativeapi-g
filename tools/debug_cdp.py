"""排查 CDP 目标地址：打印原始目标列表与 DNS 解析结果。"""

from __future__ import annotations

import json
import os
import shutil
import socket
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "relay", "src"))

from glmrelay.browser import cdp  # noqa: E402

OUT = "D:/GLM2api/artifacts/debug_cdp.txt"
lines: list[str] = []


def log(t: str = "") -> None:
    lines.append(t)


def main() -> int:
    profile = tempfile.mkdtemp(prefix="glmrelay-dbg-")
    try:
        browser = cdp.find_browser("edge")
        log(f"browser: {browser}")

        proc = cdp.launch_browser(
            browser,
            port=9334,
            user_data_dir=profile,
            url="https://example.com",
            headless=True,
        )
        log(f"launched pid={proc.pid}")
        try:
            version = cdp.wait_for_devtools(9334, timeout=45)
            log(f"/json/version -> {json.dumps(version, ensure_ascii=False)}")
        except Exception as exc:  # noqa: BLE001
            log(f"wait_for_devtools 失败: {exc}")
            return finish()

        time.sleep(2)
        targets = cdp.list_targets(9334)
        log(f"\n/json/list -> {len(targets)} 个目标")
        for t in targets:
            log(
                "  type={:<10} url={:<45} ws={}".format(
                    str(t.get("type")), str(t.get("url"))[:45], str(t.get("webSocketDebuggerUrl"))
                )
            )

        log("")
        log("--- DNS 解析 ---")
        for host in ("localhost", "127.0.0.1"):
            try:
                infos = socket.getaddrinfo(host, 9334, proto=socket.IPPROTO_TCP)
                log(f"{host}: {sorted({i[4][0] for i in infos})}")
            except Exception as exc:  # noqa: BLE001
                log(f"{host}: 解析失败 {exc}")

        log("")
        log("--- 逐 host 直连测试 ---")
        for host in ("127.0.0.1", "localhost", "::1"):
            try:
                s = socket.create_connection((host, 9334), timeout=3)
                s.close()
                log(f"{host}:9334 连接成功")
            except Exception as exc:  # noqa: BLE001
                log(f"{host}:9334 连接失败 -> {type(exc).__name__}: {exc}")

        # 用 127.0.0.1 强制重写 ws url 再试
        page = next((t for t in targets if t.get("type") == "page"), None)
        if page:
            raw_ws = page["webSocketDebuggerUrl"]
            fixed = raw_ws.replace("localhost", "127.0.0.1") if "localhost" in raw_ws else raw_ws
            log("")
            log(f"原始 ws: {raw_ws}")
            log(f"重写 ws: {fixed}")
            try:
                client = cdp.CDPClient(fixed).connect()
                title = client.evaluate("document.title")
                log(f"重写后连接成功！title={title!r}")
                client.close()
            except Exception as exc:  # noqa: BLE001
                log(f"重写后仍失败 -> {type(exc).__name__}: {exc}")
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=10)
        except Exception:  # noqa: BLE001
            pass
        shutil.rmtree(profile, ignore_errors=True)
    return finish()


def finish() -> int:
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
