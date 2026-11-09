#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Fail if a relative link in a Markdown file under <dir> points to a file that is not there.

  scripts/ci/check-md-links.py <dir>

scripts/package.sh runs it on every package, so README.md and docs/ keep working links once unpacked. Web links
(scheme:), in-page anchors (#...) and links inside code are not checked; the anchor part of a file link is
ignored.
"""
import re
import sys
from pathlib import Path

LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
FENCE = re.compile(r"^(```|~~~)")
INLINE_CODE = re.compile(r"`[^`]*`")


def broken_links(root):
    for md in sorted(p for p in root.rglob("*.md") if p.is_file()):
        in_fence = False
        for number, line in enumerate(md.read_text(encoding="utf-8").splitlines(), 1):
            if FENCE.match(line.lstrip()):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            for target in LINK.findall(INLINE_CODE.sub("", line)):
                if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", target) or target.startswith("#"):
                    continue
                path = target.split("#", 1)[0]
                if path and not (md.parent / path).exists():
                    yield f"{md.relative_to(root)}:{number}: {target}"


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    root = Path(sys.argv[1])
    broken = list(broken_links(root))
    if broken:
        sys.exit("broken relative links:\n  " + "\n  ".join(broken))


if __name__ == "__main__":
    main()
