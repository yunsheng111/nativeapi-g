"""端到端验证「登录导入」的正向抓取链路。

test_import.py 覆盖的是「未登录 → 不误抓」这条安全路径；本脚本补上真正的
价值主张：localStorage 里出现 refresh_token 之后，是否会被抓取、去重、落盘。

做法：启动一个无头导入会话，再用自研 CDP 客户端连到**同一个**浏览器，
往 chatglm.cn 的 localStorage 写入假 token，模拟「用户刚登录成功」。
这样一个真人登录才会触发的路径就能被自动化验证。

顺带验证第二点：同一个调试目标允许多个 CDP 客户端并存（面板轮询 + 外部接入）。

输出：artifacts/test_login_capture.txt
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "relay" / "src"))

from glmrelay.accounts.importer import LoginImportSession  # noqa: E402
from glmrelay.accounts.store import TokenStore  # noqa: E402
from glmrelay.browser import CDPClient, CDPError, find_page_target  # noqa: E402

PORT = 9335
OUT = ROOT / "artifacts" / "test_login_capture.txt"
OUT.parent.mkdir(parents=True, exist_ok=True)

# 必须满足 token 形态 ^[A-Za-z0-9_\-\.]{20,4096}$
TOKEN_A = "zzZtestLOGINtokenAAAA111122223333444455556666"
TOKEN_B = "zzZtestLOGINtokenBBBB111122223333444455556666"
DEV_A = "device-aaa-0001"
DEV_B = "device-bbb-0002"

# 键名走模糊匹配：含 refresh+token / 含 deid
TOKEN_KEY = "chatglm-refresh-token"
DEVICE_KEY = "chatglm-deid"

lines: list[str] = []
passed = 0
failed = 0


def log(t: str = "") -> None:
    lines.append(str(t))


def check(ok: bool, name: str, detail: str = "") -> None:
    global passed, failed
    if ok:
        passed += 1
    else:
        failed += 1
    log(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" :: {detail}" if detail else ""))


def wait_for(pred, timeout: float, interval: float = 0.4):
    """轮询等待 pred() 为真，返回 (是否成功, 最后取值)。"""
    deadline = time.time() + timeout
    value = None
    while time.time() < deadline:
        value = pred()
        if value:
            return True, value
        time.sleep(interval)
    return False, value


def inject(client: CDPClient, token: str, device: str) -> int:
    """把假的登录态写进页面 localStorage，返回写入后读回的长度。"""
    expr = (
        "(()=>{"
        f"localStorage.setItem({json.dumps(TOKEN_KEY)}, {json.dumps(token)});"
        f"localStorage.setItem({json.dumps(DEVICE_KEY)}, {json.dumps(device)});"
        f"const v = localStorage.getItem({json.dumps(TOKEN_KEY)});"
        "return v ? v.length : -1;"
        "})()"
    )
    return int(client.evaluate(expr) or -1)


def main() -> int:
    log("=== 登录导入正向抓取链路验证 ===")
    log("")

    root = tempfile.mkdtemp(prefix="glmrelay-login-capture-")
    token_file = Path(root) / "token.txt"
    meta_file = Path(root) / "accounts.json"
    snap_dir = Path(root) / "snapshots"

    store = TokenStore(token_file=token_file, meta_file=meta_file)
    session = LoginImportSession(
        store=store,
        profile_dir=Path(root) / "profile",
        port=PORT,
        preferred="edge",
        headless=True,
        snapshot_dir=snap_dir,
        poll_interval=0.5,
    )
    client = None
    try:
        status = session.start()
        check(
            status["state"] == "waiting_login",
            "导入会话启动进入等待登录",
            f"state={status['state']} err={status.get('last_error') or '无'}",
        )
        if status["state"] != "waiting_login":
            log("    [debug] 会话未能就绪，后续断言无意义")
            log(json.dumps(status, ensure_ascii=False, indent=2))
            return finish()

        # ── 外部 CDP 接入同一个调试目标 ────────────────────────────────
        try:
            target = find_page_target(PORT, url_contains="chatglm.cn", timeout=25)
            client = CDPClient(target["webSocketDebuggerUrl"]).connect()
            state = client.wait_loaded(timeout=30)
            href = str((state or {}).get("href") or "")
            check("chatglm.cn" in href, "外部 CDP 已接入同一页面", href[:70])
            if "chatglm.cn" not in href:
                client.navigate("https://chatglm.cn")
                state = client.wait_loaded(timeout=30)
                href = str((state or {}).get("href") or "")
                check("chatglm.cn" in href, "导航到 chatglm.cn 后接入", href[:70])
        except CDPError as exc:
            check(False, "外部 CDP 接入同一页面", f"{type(exc).__name__}: {exc}")
            return finish()

        # ── 写入账号 A ────────────────────────────────────────────────
        written = inject(client, TOKEN_A, DEV_A)
        check(written == len(TOKEN_A), "假登录态已写入 localStorage", f"len={written}")

        ok, _ = wait_for(lambda: session.status()["captured_count"] >= 1, timeout=20)
        st = session.status()
        check(ok, "账号 A 被抓取", f"captured={st['captured_count']} msg={st['message']}")

        tokens = store.load_tokens()
        check(tokens == [TOKEN_A], "token.txt 只写入账号 A", f"count={len(tokens)}")

        meta = store.load_meta()
        entry = next(iter(meta.values()), None)
        check(entry is not None and entry.device_id == DEV_A, "device_id 一并落盘", str(getattr(entry, "device_id", None)))
        check(
            entry is not None and entry.source == "browser-login",
            "来源标记为 browser-login",
            str(getattr(entry, "source", None)),
        )

        snaps = sorted(p.name for p in snap_dir.glob("*")) if snap_dir.is_dir() else []
        check(len(snaps) >= 1, "首次抓取写入诊断快照", str(snaps))

        # ── 重复注入 → 去重 ───────────────────────────────────────────
        before = session.status()["captured_count"]
        inject(client, TOKEN_A, DEV_A)
        time.sleep(3.0)
        after = session.status()["captured_count"]
        check(after == before, "重复登录态不重复导入", f"{before} -> {after}")
        check(len(store.load_tokens()) == 1, "token.txt 未出现重复行", f"count={len(store.load_tokens())}")

        # ── 换账号 → 第二个账号被追加 ─────────────────────────────────
        inject(client, TOKEN_B, DEV_B)
        ok, _ = wait_for(lambda: session.status()["captured_count"] >= 2, timeout=20)
        st = session.status()
        check(ok, "账号 B 被抓取（换号场景）", f"captured={st['captured_count']}")

        tokens = store.load_tokens()
        check(
            set(tokens) == {TOKEN_A, TOKEN_B} and len(tokens) == 2,
            "两个账号都在 token.txt",
            f"count={len(tokens)}",
        )
        metas = store.load_meta()
        devices = {m.device_id for m in metas.values()}
        check(devices == {DEV_A, DEV_B}, "两个 device_id 各自落盘", str(sorted(devices)))

        # ── 收尾 ──────────────────────────────────────────────────────
        status = session.stop()
        check(status["state"] == "stopped", "会话正常停止", f"state={status['state']}")
        time.sleep(1.2)
        check(session.status()["browser_alive"] is False, "浏览器已关闭")

    except Exception as exc:  # noqa: BLE001
        check(False, "登录导入正向链路", f"{type(exc).__name__}: {exc}")
        log(traceback.format_exc())
        try:
            session.stop()
        except Exception:  # noqa: BLE001
            pass
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass
        shutil.rmtree(root, ignore_errors=True)

    return finish()


def finish() -> int:
    log("")
    log(f"=== 汇总: PASS {passed} / FAIL {failed} ===")
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
