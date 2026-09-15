"""Fix Vue in-DOM template pitfall: self-closing custom-element tags.

The HTML5 parser ignores `/` on non-void elements, so `<n-input ... />` is
parsed as an *unclosed* opening tag and swallows every following sibling.
Vue then receives those siblings as slot children of the swallowed component,
so they never render.  Rewrite `<n-foo ... />` -> `<n-foo ...></n-foo>`.

Native void elements (input, br, img, hr, ...) are left untouched.
"""
import re
import sys
from pathlib import Path

TARGET = Path(r"D:\GLM2api\relay\src\glm2api\admin_static\index.html")

# custom elements only: at least one hyphen, lowercase; attributes contain no '<'
PATTERN = re.compile(r"<(n-[a-z0-9-]+)([^<>]*?)\s*/>")


def main() -> int:
    text = TARGET.read_text(encoding="utf-8")
    hits: list[str] = []

    def repl(m: re.Match) -> str:
        hits.append(m.group(0))
        return f"<{m.group(1)}{m.group(2)}></{m.group(1)}>"

    fixed = PATTERN.sub(repl, text)

    if fixed == text:
        print("no self-closing custom tags found; nothing to do")
        return 0

    TARGET.write_text(fixed, encoding="utf-8", newline="")
    print(f"rewrote {len(hits)} tag(s):")
    for h in hits:
        print("  -", h[:110])
    return 0


if __name__ == "__main__":
    sys.exit(main())
