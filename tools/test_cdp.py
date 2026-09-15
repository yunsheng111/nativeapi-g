"""CDP 客户端自检 —— 验证手写 WebSocket 到 CDP 全链路可用。

用无头模式跑，不会弹窗打扰。全程使用临时 profile，跑完即清理。

用法：
    python tools/test_cdp.py [edge|chrome]
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "relay", "src"))

from glmrelay.browser import CDPError, ManagedBrowser, find_browser  # noqa: E402

OUT = "D:/GLM2api/artifacts/test_cdp.txt"
os.makedirs(os.path.dirname(OUT), exist_ok=True)

lines: list[str] = []
passed = 0
failed = 0


def log(text: str = "") -> None:
    lines.append(text)


def check(ok: bool, name: str, detail: str = "") -> None:
    global passed, failed
    if ok:
        passed += 1
    else:
        failed += 1
    tag = "PASS" if ok else "FAIL"
    log(f"[{tag}] {name}" + (f" :: {detail}" if detail else ""))


def main() -> int:
    preferred = sys.argv[1] if len(sys.argv) > 1 else None
    log("=== CDP 客户端自检 ===")
    log("")

    # 1. 浏览器发现
    try:
        browser = find_browser(preferred)
        check(True, "浏览器发现", str(browser))
    except CDPError as exc:
        check(False, "浏览器发现", str(exc))
        return finish()

    profile = tempfile.mkdtemp(prefix="glmrelay-cdp-test-")
    managed = ManagedBrowser(
        user_data_dir=profile,
        port=9333,
        preferred=preferred,
        headless=True,
        start_url="https://example.com",
    )

    proc = None
    client = None
    try:
        proc, client = managed.start(page_url_contains="example.com")
        check(True, "启动无头浏览器 + 调试端口就绪")
        check(True, "CDP 会话建立", "WebSocket 握手 + 域启用成功")

        # 2. 基础求值
        title = client.evaluate("document.title")
        check(isinstance(title, str) and len(title) > 0, "Runtime.evaluate 基础求值", f"title={title!r}")

        # 3. 数字 / 对象 / 中文 往返
        num = client.evaluate("1 + 41")
        check(num == 42, "数字往返", f"1+41 = {num!r}")
        obj = client.evaluate("({a:1, b:'中文', c:[1,2,3]})")
        check(
            isinstance(obj, dict) and obj.get("b") == "中文" and obj.get("c") == [1, 2, 3],
            "对象 + 中文往返",
            f"{obj!r}",
        )

        # 4. localStorage 写 / 读 往返
        client.evaluate("(() => { localStorage.setItem('glmrelay_probe', 'hello-世界'); return 1; })()")
        got = client.evaluate("localStorage.getItem('glmrelay_probe')")
        check(got == "hello-世界", "localStorage 读写往返", f"{got!r}")

        # 5. 大载荷（验证 16 位长度分支 + 中文多字节）
        big = "汉" * 30000
        client.evaluate(f"(() => {{ localStorage.setItem('glmrelay_big', '{big}'); return 1; }})()")
        back = client.evaluate("localStorage.getItem('glmrelay_big')")
        check(back == big, "大载荷帧编解码（30000 字符）", f"len={len(back) if back else 0}")

        # 6. DOMStorage 域直读（不依赖页面脚本）
        origin = client.evaluate("location.origin")
        items = client.dom_storage_items(str(origin))
        check(
            items.get("glmrelay_probe") == "hello-世界" and "glmrelay_big" in items,
            "DOMStorage.getDOMStorageItems 直读",
            f"origin={origin} keys={len(items)}",
        )

        # 7. 异常传播
        try:
            client.evaluate("throw new Error('probe-failure')")
            check(False, "页面异常正确抛出", "未抛出异常")
        except CDPError as exc:
            check("probe-failure" in str(exc), "页面异常正确抛出", str(exc)[:80])

        # 8. 访问 chatglm.cn，确认能读到真实站点的 localStorage 结构
        try:
            client.call("Page.navigate", {"url": "https://chatglm.cn"}, timeout=30)
            import time

            time.sleep(4)
            current = client.evaluate("location.href")
            token = client.evaluate(
                "(() => { try { return localStorage.getItem('chatglm_refresh_token') || ''; }"
                " catch (e) { return 'ERR:' + e.message; } })()"
            )
            keys = client.evaluate("Object.keys(localStorage).join(',')")
            check(
                "chatglm.cn" in str(current),
                "导航到 chatglm.cn",
                f"href={str(current)[:60]}",
            )
            check(
                isinstance(token, str),
                "读取 chatglm_refresh_token（未登录应为空）",
                f"token={'(空)' if not token else token[:20] + '...'}",
            )
            check(
                isinstance(keys, str),
                "枚举 localStorage 键名",
                f"keys={keys[:300] if keys else '(无)'}",
            )
        except Exception as exc:  # noqa: BLE001
            check(False, "导航到 chatglm.cn", f"{type(exc).__name__}: {exc}")

    except Exception as exc:  # noqa: BLE001
        check(False, "CDP 全链路", f"{type(exc).__name__}: {exc}")
        log(traceback.format_exc())
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass
        managed.stop()
        try:
            shutil.rmtree(profile, ignore_errors=True)
        except Exception:  # noqa: BLE001
            pass

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
