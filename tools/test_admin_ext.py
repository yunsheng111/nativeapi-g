"""管理面板扩展端点集成测试。

验证：鉴权、账号列表、粘贴导入、删除、登录导入会话启停。
测试过程中会向真实 token.txt 写入两条假 token，结束时通过 delete 端点清理，
顺带把删除接口也验证一遍。

用法：
    python tools/test_admin_ext.py [base_url]
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
ADMIN_KEY = os.environ.get("ADMIN_KEY", "glm2api-admin")
TOKEN_FILE = Path(r"D:\GLM2api\relay\token.txt")

OUT = "D:/GLM2api/artifacts/test_admin_ext.txt"
os.makedirs(os.path.dirname(OUT), exist_ok=True)

FAKE_A = "FAKE_TEST_TOKEN_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
FAKE_B = "FAKE_TEST_TOKEN_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

lines: list[str] = []
passed = 0
failed = 0
session_token = ""


def log(t: str = "") -> None:
    lines.append(t)


def check(ok: bool, name: str, detail: str = "") -> None:
    global passed, failed
    if ok:
        passed += 1
    else:
        failed += 1
    log(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" :: {detail}" if detail else ""))


def request(method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body, ensure_ascii=False).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json"}
    if session_token:
        headers["x-admin-session"] = session_token
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, {"raw": raw}
    except Exception as exc:  # noqa: BLE001
        return -1, {"error": f"{type(exc).__name__}: {exc}"}


def main() -> int:
    global session_token
    log("=== 管理面板扩展端点集成测试 ===")
    log("")

    existed_before = TOKEN_FILE.exists()
    baseline = 0
    if existed_before:
        baseline = len([l for l in TOKEN_FILE.read_text(encoding="utf-8").splitlines() if l.strip()])

    # 1. 鉴权
    code, resp = request("POST", "/admin/api/login", {"key": "wrong-key"})
    check(code == 401, "错误密钥被拒绝", f"HTTP {code}")

    code, resp = request("POST", "/admin/api/login", {"key": ADMIN_KEY})
    session_token = str((resp.get("data") or {}).get("_session_token") or "")
    check(code == 200 and bool(session_token), "管理员登录", f"HTTP {code}")

    code, resp = request("GET", "/admin/api/accounts")
    # 底座响应结构是 {"code":0,"msg":"ok","data":{...}}，没有 ok 字段
    check(code == 200 and resp.get("code") == 0, "GET /admin/api/accounts 鉴权通过", f"HTTP {code}")
    stats_before = (resp.get("data") or {}).get("stats") or {}
    check(
        int(stats_before.get("token_count", -1)) == baseline,
        "初始账号数与 token.txt 一致",
        f"{stats_before.get('token_count')} vs {baseline}",
    )

    # 2. 未鉴权应被拒
    saved = session_token
    session_token = ""
    code, _ = request("GET", "/admin/api/accounts")
    check(code == 401, "未带会话时被拒绝", f"HTTP {code}")
    session_token = saved

    # 3. 粘贴导入
    blob = f"chatglm_refresh_token\t{FAKE_A}\nchatglm-deid\tdeid-fake-1234\n{{\"chatglm_refresh_token\":\"{FAKE_B}\"}}"
    code, resp = request("POST", "/admin/api/accounts/paste", {"text": blob})
    data = resp.get("data") or {}
    added = data.get("added") or []
    check(code == 200 and len(added) == 2, "粘贴导入两条", f"HTTP {code} added={len(added)}")
    check(data.get("restart_required") is True, "返回需重启提示")

    # 4. 幂等
    code, resp = request("POST", "/admin/api/accounts/paste", {"text": blob})
    data = resp.get("data") or {}
    check(len(data.get("added") or []) == 0, "重复粘贴不新增")
    check(len(data.get("skipped") or []) == 2, "重复粘贴计入 skipped")

    # 5. 落盘校验
    on_disk = TOKEN_FILE.read_text(encoding="utf-8").splitlines() if TOKEN_FILE.exists() else []
    on_disk = [l.strip() for l in on_disk if l.strip()]
    check(FAKE_A in on_disk and FAKE_B in on_disk, "token.txt 已落盘", f"共 {len(on_disk)} 行")
    check(len(on_disk) == baseline + 2, "行数正确", f"{baseline} + 2 = {len(on_disk)}")

    # 6. 列表与元数据
    code, resp = request("GET", "/admin/api/accounts")
    accounts = (resp.get("data") or {}).get("accounts") or []
    row_a = next((a for a in accounts if a["token_masked"].startswith("FAKE_T")), None)
    check(row_a is not None, "列表包含新账号")
    check(row_a and row_a["device_id"] == "deid-fake-1234", "device_id 已旁挂", str(row_a and row_a["device_id"]))
    check(row_a and "*" in row_a["token_masked"] and row_a["token_masked"].endswith("aaaa"), "列表脱敏", str(row_a and row_a["token_masked"]))
    check(row_a and row_a["source"] == "paste", "来源标记", str(row_a and row_a["source"]))

    # 7. 改备注
    if row_a:
        code, resp = request(
            "POST", "/admin/api/accounts/update", {"fingerprint": row_a["fingerprint"], "label": "测试账号A"}
        )
        check(code == 200, "更新备注")
        code, resp = request("GET", "/admin/api/accounts")
        again = next(
            (a for a in ((resp.get("data") or {}).get("accounts") or []) if a["fingerprint"] == row_a["fingerprint"]),
            None,
        )
        check(again is not None and again["label"] == "测试账号A", "备注已保存", str(again and again["label"]))

    # 8. 登录导入会话启停（无头模式，仅验证管道）
    code, resp = request("POST", "/admin/api/accounts/import/start", {"headless": True, "browser": "edge"})
    session = (resp.get("data") or {}).get("session") or {}
    check(code == 200 and session.get("state") in ("starting", "waiting_login"), "启动导入会话", f"state={session.get('state')}")
    check(bool(session.get("browser")), "会话识别到浏览器", str(session.get("browser")))

    time.sleep(6)
    code, resp = request("GET", "/admin/api/accounts/import/status")
    session = (resp.get("data") or {}).get("session") or {}
    check(int(session.get("poll_count", 0)) >= 2, "会话持续轮询", f"polls={session.get('poll_count')}")
    check(int(session.get("captured_count", -1)) == 0, "无头未登录时不误抓")

    code, resp = request("POST", "/admin/api/accounts/import/stop")
    session = (resp.get("data") or {}).get("session") or {}
    check(session.get("state") == "stopped", "停止导入会话", f"state={session.get('state')}")

    code, resp = request("GET", "/admin/api/accounts")
    accounts = (resp.get("data") or {}).get("accounts") or []
    check(
        int(((resp.get("data") or {}).get("stats") or {}).get("token_count", -1)) == baseline + 2,
        "会话期间账号数未被意外改动",
    )

    # 9. 清理：删除测试账号
    for fp in [a["fingerprint"] for a in accounts if a["token_masked"].startswith("FAKE_T")]:
        code, resp = request("POST", "/admin/api/accounts/delete", {"fingerprint": fp})
        check(code == 200, f"删除测试账号 {fp}")

    code, resp = request("GET", "/admin/api/accounts")
    final_count = int(((resp.get("data") or {}).get("stats") or {}).get("token_count", -1))
    check(final_count == baseline, "清理后账号数回到基线", f"{final_count} vs {baseline}")

    final_disk = TOKEN_FILE.read_text(encoding="utf-8").splitlines() if TOKEN_FILE.exists() else []
    leftovers = [l for l in final_disk if "FAKE_TEST_TOKEN" in l]
    check(leftovers == [], "token.txt 无测试残留", str(leftovers))

    log("")
    log(f"=== 汇总: PASS {passed} / FAIL {failed} ===")
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
