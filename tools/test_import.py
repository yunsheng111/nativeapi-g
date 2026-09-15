"""账号导入自检：存储层、文本抽取、粘贴导入、登录会话（无头）。

全程使用临时目录与临时 profile，不会碰项目里真实的 token.txt。

用法：
    python tools/test_import.py [edge|chrome]
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "relay", "src"))

from glmrelay.accounts import TokenStore, extract_candidates, import_from_text  # noqa: E402
from glmrelay.accounts.importer import LoginImportSession  # noqa: E402

OUT = "D:/GLM2api/artifacts/test_import.txt"
os.makedirs(os.path.dirname(OUT), exist_ok=True)

lines: list[str] = []
passed = 0
failed = 0


def log(t: str = "") -> None:
    lines.append(t)


def check(ok: bool, name: str, detail: str = "") -> None:
    global passed, failed
    if ok:
        passed += 1
    else:
        failed += 1
    log(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" :: {detail}" if detail else ""))


TOKEN_A = "eyJhbGciOiJIUzI1NiJ9.PAYLOADA.SIGNATUREA_aaaaaaaaaaaaaaaa"
TOKEN_B = "eyJhbGciOiJIUzI1NiJ9.PAYLOADB.SIGNATUREB_bbbbbbbbbbbbbbbb"


def test_store(root: str) -> None:
    log("--- 1. 存储层 ---")
    store = TokenStore(
        token_file=os.path.join(root, "token.txt"),
        meta_file=os.path.join(root, "accounts.json"),
    )

    check(store.load_tokens() == [], "空文件读取", "返回空列表")

    check(store.add_token(TOKEN_A) is True, "新增 token")
    check(store.add_token(TOKEN_A) is False, "重复 token 被拒绝", "返回 False")
    check(store.add_token(TOKEN_B) is True, "新增第二个 token")
    check(len(store.load_tokens()) == 2, "token 数量", f"{len(store.load_tokens())}")

    # 底座解析规则：跳空行、跳 # 注释
    raw = open(store.token_file, encoding="utf-8").read()
    open(store.token_file, "w", encoding="utf-8").write("# 注释行\n\n" + raw)
    check(len(store.load_tokens()) == 2, "兼容底座的注释/空行解析", f"{len(store.load_tokens())} 条")

    store.record(TOKEN_A, device_id="deid-aaa", source="browser-login")
    store.record(TOKEN_B, device_id="deid-bbb", source="paste")
    rows = store.list_accounts()
    check(len(rows) == 2 and rows[0]["device_id"] == "deid-aaa", "元数据旁挂读写")
    check(
        rows[0]["token_masked"].startswith("eyJhbG") and "*" in rows[0]["token_masked"],
        "token 脱敏",
        rows[0]["token_masked"],
    )
    check(not os.path.exists(os.path.join(root, "token.txt.tmp")), "落盘无残留临时文件")

    stats = store.stats()
    check(stats["token_count"] == 2 and stats["with_device_id"] == 2, "统计", str(stats))

    check(store.remove_token(TOKEN_B) is True, "删除 token")
    check(len(store.load_tokens()) == 1, "删除后数量", f"{len(store.load_tokens())}")


def test_extract() -> None:
    log("")
    log("--- 2. 文本抽取 ---")

    cases: list[tuple[str, str, int]] = [
        ("裸 token", TOKEN_A, 1),
        ("devtools 键值对", f"chatglm_refresh_token\t{TOKEN_A}", 1),
        ("JSON 片段", '{"chatglm_refresh_token":"' + TOKEN_A + '"}', 1),
        (".env 风格", f"GLM_REFRESH_TOKEN={TOKEN_A}", 1),
        ("等号键值", f"refresh_token = {TOKEN_A}", 1),
        ("多 token", f"chatglm_refresh_token={TOKEN_A}\nchatglm_refresh_token={TOKEN_B}", 2),
    ]
    for name, text, expected in cases:
        got = extract_candidates(text)
        check(len(got["tokens"]) == expected, f"抽取：{name}", f"得到 {len(got['tokens'])} 条 {got['tokens']}")

    got = extract_candidates(f"chatglm-deid=deid-xyz\nchatglm_refresh_token={TOKEN_A}")
    check(got["devices"] == ["deid-xyz"], "抽取 device_id", str(got["devices"]))

    got = extract_candidates("   ")
    check(got["tokens"] == [], "空文本不误抽取")

    got = extract_candidates("这是随便一段中文，没有任何 token")
    check(got["tokens"] == [], "无关文本不误抽取")


def test_paste_import(root: str) -> None:
    log("")
    log("--- 3. 粘贴导入 ---")
    store = TokenStore(
        token_file=os.path.join(root, "paste-token.txt"),
        meta_file=os.path.join(root, "paste-accounts.json"),
    )
    blob = (
        f"chatglm_refresh_token\t{TOKEN_A}\n"
        f"chatglm-deid\tdeid-xyz\n"
        f'{{"chatglm_refresh_token":"{TOKEN_B}"}}\n'
        "GLM_REFRESH_TOKEN=not-a-real-token-placeholder-0000\n"
    )
    result = import_from_text(store, blob)
    check(
        len(result["added"]) == 3,
        "导入三条新账号（制表符 / JSON / .env 三种格式）",
        str([a["token_masked"] for a in result["added"]]),
    )
    check(result["added"][0]["device_id"] == "deid-xyz", "device_id 配到首个 token")
    check(result["restart_required"] is True, "提示需要重启服务")

    # 已存在的 token 应被跳过而不是重复写入
    before = len(store.load_tokens())
    again = import_from_text(store, f"chatglm_refresh_token={TOKEN_A}\nchatglm_refresh_token={TOKEN_B}")
    check(len(again["added"]) == 0, "已存在 token 不再新增", str(again["added"]))
    check(len(again["skipped"]) == 2, "已存在 token 计入 skipped", str(again["skipped"]))
    check(len(store.load_tokens()) == before, "token.txt 未被重复污染", f"{before} -> {len(store.load_tokens())}")


def test_login_session(root: str, preferred: str | None) -> None:
    log("")
    log("--- 4. 登录导入会话（无头，未登录状态） ---")
    store = TokenStore(
        token_file=os.path.join(root, "live-token.txt"),
        meta_file=os.path.join(root, "live-accounts.json"),
    )
    profile = os.path.join(root, "profile")
    session = LoginImportSession(
        store=store,
        profile_dir=profile,
        port=9334,
        preferred=preferred,
        headless=True,
        snapshot_dir=os.path.join(root, "snapshots"),
        poll_interval=1.0,
    )
    try:
        status = session.start()
        check(status["state"] == "waiting_login", "会话启动进入等待登录", f"state={status['state']}")
        check(bool(status["browser"]), "识别到浏览器", status["browser"])

        # 未登录：应稳定轮询且不误报账号
        deadline = time.time() + 20
        while time.time() < deadline and session.poll_count < 5:
            time.sleep(0.5)
        status = session.status()
        check(status["poll_count"] >= 5, "轮询持续运行", f"polls={status['poll_count']}")
        check(status["captured_count"] == 0, "未登录时不误抓账号")
        check(store.load_tokens() == [], "未登录时不写入 token.txt")
        check(not status["last_error"], "轮询无异常", status.get("last_error") or "无")

        # 快照只在真正抓到 token 时才写，此处不应存在
        snaps = []
        snap_dir = os.path.join(root, "snapshots")
        if os.path.isdir(snap_dir):
            snaps = os.listdir(snap_dir)
        check(snaps == [], "未抓到 token 时不写诊断快照", str(snaps))

        status = session.stop()
        check(status["state"] == "stopped", "会话正常停止", f"state={status['state']}")
        time.sleep(1.0)
        check(session.status()["browser_alive"] is False, "浏览器已关闭")
    except Exception as exc:  # noqa: BLE001
        check(False, "登录导入会话", f"{type(exc).__name__}: {exc}")
        log(traceback.format_exc())
        try:
            session.stop()
        except Exception:  # noqa: BLE001
            pass


def main() -> int:
    preferred = sys.argv[1] if len(sys.argv) > 1 else None
    log("=== 账号导入自检 ===")
    log("")
    root = tempfile.mkdtemp(prefix="glmrelay-import-test-")
    try:
        test_store(root)
        test_extract()
        test_paste_import(root)
        test_login_session(root, preferred)
    finally:
        shutil.rmtree(root, ignore_errors=True)

    log("")
    log(f"=== 汇总: PASS {passed} / FAIL {failed} ===")
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
