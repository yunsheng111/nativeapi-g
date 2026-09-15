"""用自研 CDP 客户端给管理面板做界面自检。

这既是面板的回归测试，也是 glmrelay.browser 的真实用例验证：
拉起无头浏览器 → 预置管理会话 → 进入「账号池」页 → 检查渲染与 JS 报错。

前置：服务需已在 BASE 上运行。

用法：
    python tools/test_panel.py [base_url] [edge|chrome]
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "relay", "src"))

from glmrelay.browser import CDPError, ManagedBrowser  # noqa: E402

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
PREFERRED = sys.argv[2] if len(sys.argv) > 2 else "edge"
ADMIN_KEY = os.environ.get("ADMIN_KEY", "glm2api-admin")

OUT = "D:/GLM2api/artifacts/test_panel.txt"
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


def get_session_token() -> str:
    req = urllib.request.Request(
        BASE + "/admin/api/login",
        data=json.dumps({"key": ADMIN_KEY}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        payload = json.loads(resp.read().decode("utf-8", "replace"))
    token = str((payload.get("data") or {}).get("_session_token") or "")
    if not token:
        raise RuntimeError("登录未返回会话令牌")
    return token


def main() -> int:
    log("=== 管理面板界面自检（CDP 驱动） ===")
    log("")

    try:
        token = get_session_token()
        check(True, "取得管理会话令牌", f"len={len(token)}")
    except Exception as exc:  # noqa: BLE001
        check(False, "取得管理会话令牌", f"{type(exc).__name__}: {exc}")
        return finish()

    profile = tempfile.mkdtemp(prefix="glmrelay-panel-test-")
    managed = ManagedBrowser(
        user_data_dir=profile,
        port=9336,
        preferred=PREFERRED,
        headless=True,
        start_url=BASE + "/admin",
    )
    client = None
    try:
        _, client = managed.start(page_url_contains="/admin")
        try:
            client.call("Log.enable", timeout=8)
        except CDPError:
            pass

        state = client.wait_loaded(timeout=30)
        check(bool(state.get("href")), "打开管理面板", str(state.get("href"))[:60])

        # 预置会话，避开驱动登录表单的脆弱写法
        client.evaluate(f"localStorage.setItem('glm2api_admin_session', {json.dumps(token)}); 1")
        client.call("Page.reload", {"ignoreCache": True})
        time.sleep(3)
        client.wait_loaded(timeout=30)
        time.sleep(1.5)

        authed = client.evaluate("!document.querySelector('.login-shell') && !!document.querySelector('.app-shell')")
        check(bool(authed), "会话生效，进入主界面")

        navs = client.evaluate("[...document.querySelectorAll('.nav-item')].map(e=>e.textContent.trim())")
        check(isinstance(navs, list) and any("账号池" in str(n) for n in navs), "侧栏出现「账号池」", str(navs))

        clicked = client.evaluate(
            "(()=>{const el=[...document.querySelectorAll('.nav-item')]"
            ".find(e=>e.textContent.includes('账号池'));if(!el)return false;el.click();return true;})()"
        )
        check(bool(clicked), "点击「账号池」导航")
        time.sleep(1.5)

        body = client.evaluate("document.body.innerText")
        body = str(body or "")
        for keyword in ("账号池", "一键登录导入", "结束导入", "粘贴导入", "账号总数"):
            check(keyword in body, f"页面渲染出「{keyword}」")

        btn_texts = client.evaluate("[...document.querySelectorAll('button')].map(b=>b.textContent.trim())")
        log(f"    [debug] 页面按钮: {btn_texts}")
        log(f"    [debug] body 含『结束』: {'结束' in body}")

        # 自闭合标签陷阱回归点：<n-select ... /> 会吞掉后续兄弟节点，
        # 导致 n-button 根本不产出 <button>，这里必须按真实 DOM 断言。
        main_btns = client.evaluate(
            "[...document.querySelectorAll('.main button')].map(b=>b.textContent.trim()).filter(Boolean)"
        )
        check(
            isinstance(main_btns, list) and len(main_btns) >= 4,
            "账号池操作按钮渲染为真实 <button>",
            str(main_btns),
        )
        main_html = client.evaluate("(document.querySelector('.main')||{}).innerHTML || ''")
        log("    [debug] .main 结构（前 30 行）:")
        for ln in str(main_html).split("><")[:30]:
            log(f"      {ln[:150]}")
        tag_names = client.evaluate(
            "[...document.querySelectorAll('.main *')].map(e=>e.tagName.toLowerCase())"
            ".filter((v,i,a)=>a.indexOf(v)===i)"
        )
        log(f"    [debug] .main 内出现的标签: {tag_names}")

        # 概览接口是否真的被调用成功：检查统计卡片的数字
        cards = client.evaluate(
            "[...document.querySelectorAll('.stat-card')].map(c=>c.querySelector('.label').textContent+'='+c.querySelector('.value').textContent)"
        )
        check(isinstance(cards, list) and len(cards) >= 4, "统计卡片已渲染", str(cards))

        table_or_empty = client.evaluate(
            "!!document.querySelector('.data-table') || !!document.querySelector('.empty-state')"
        )
        check(bool(table_or_empty), "账号表格或空状态已渲染")

        # JS 报错检查
        errors: list[str] = []
        for event in client.events:
            if event.get("method") in ("Log.entryAdded",):
                entry = (event.get("params") or {}).get("entry") or {}
                if entry.get("level") == "error":
                    errors.append(f"{entry.get('text')} @ {entry.get('url')}")
        check(errors == [], "控制台无 error 级日志", str(errors[:3]))

        vue_err = client.evaluate("(window.__errors||[]).join(' | ')")
        check(not vue_err, "无未捕获的 Vue 错误", str(vue_err)[:200])

    except Exception as exc:  # noqa: BLE001
        check(False, "面板自检全流程", f"{type(exc).__name__}: {exc}")
        import traceback

        log(traceback.format_exc())
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass
        managed.stop()
        shutil.rmtree(profile, ignore_errors=True)

    return finish()


def finish() -> int:
    log("")
    log(f"=== 汇总: PASS {passed} / FAIL {failed} ===")
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
