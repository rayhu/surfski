#!/usr/bin/env python3
"""Print the CHANGELOG.md section for one version (without its heading), for release notes.

    python3 scripts/changelog_section.py 0.1.0 [CHANGELOG.md]

Accepts "0.1.0" or "v0.1.0". Exits 1 if the version has no section or the section is empty.
Standard library only, so the release workflow can run it without installing anything."""

from __future__ import annotations

import re
import sys
from pathlib import Path

HEADING = re.compile(r"^## \[(?P<version>[^\]]+)\]")


def section(text: str, version: str) -> str | None:
    version = version.strip().removeprefix("v")
    out: list[str] = []
    inside = False
    for line in text.splitlines():
        m = HEADING.match(line)
        if m:
            if inside:
                break
            inside = m.group("version") == version
            continue
        if inside:
            if re.match(r"^\[[^\]]+\]:\s", line):  # link reference definitions at the bottom
                break
            out.append(line)
    if not inside and not out:
        return None
    body = "\n".join(out).strip()
    return body or None


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print(__doc__, file=sys.stderr)
        return 2
    path = Path(argv[2] if len(argv) == 3 else "CHANGELOG.md")
    body = section(path.read_text(encoding="utf-8"), argv[1])
    if body is None:
        print(f"no (non-empty) section for {argv[1]} in {path}", file=sys.stderr)
        return 1
    print(body)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
