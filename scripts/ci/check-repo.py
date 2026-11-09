#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Repository rules that no compiler checks. Exit status 1, with one line per violation, if any is broken.

  scripts/ci/check-repo.py [--include-untracked]

1. Nothing under testdata/private/ but its README.md is in the index: real signed documents may hold personal
   data (testdata/private/README.md). The index includes staged files, so this also works as a pre-commit hook:
   `ln -s ../../scripts/ci/check-repo.py .git/hooks/pre-commit`.
2. Every file has an SPDX licence header (the SPDX licence-identifier tag in its first 30 lines) or is covered
   by an annotation in REUSE.toml (LICENSING.md). The licence texts in LICENSES/ need neither.
3. The GraalVM CE release CI installs (scripts/ci/install-graalvm.sh) is the one java/pom.xml compiles against
   (graalvm.sdk.version).
4. LICENSES/ holds `<id>.txt` for exactly the licences the headers and REUSE.toml use, as `reuse lint` requires:
   none missing, none unused; LICENSES/LGPL-2.1-or-later.txt is a copy of LICENSE.

Files are the ones in git's index; --include-untracked adds untracked files that .gitignore does not exclude.
"""
import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path

root = Path(__file__).resolve().parent.parent.parent
# REUSE ignores licence texts themselves.
IGNORED_NAMES = {"LICENSE", "COPYING"}
# Built by concatenation, so that `reuse lint` does not read this file's own code as a licence expression.
TAG = "SPDX-License-" + "Identifier:"
# Operators of SPDX licence expressions; everything else between them is a licence identifier.
OPERATORS = {"AND", "OR", "WITH"}


def git_files(include_untracked):
    files = subprocess.run(["git", "ls-files", "-z"], cwd=root, check=True, capture_output=True).stdout
    names = {f for f in files.decode().split("\0") if f}
    if include_untracked:
        extra = subprocess.run(["git", "ls-files", "-z", "--others", "--exclude-standard"], cwd=root, check=True,
                               capture_output=True).stdout
        names |= {f for f in extra.decode().split("\0") if f}
    return sorted(names)


def reuse_pattern(glob):
    """REUSE.toml globbing: `*` stays within a path segment, `**` crosses them; `\\*` is a literal star."""
    out, i = "", 0
    while i < len(glob):
        if glob.startswith("**", i):
            out += ".*"
            i += 2
        elif glob[i] == "*":
            out += "[^/]*"
            i += 1
        elif glob.startswith("\\*", i):
            out += re.escape("*")
            i += 2
        else:
            out += re.escape(glob[i])
            i += 1
    return re.compile(out + r"\Z")


def licence_ids(expression):
    """The licence identifiers of an SPDX expression, without operators, parentheses or a comment's end."""
    return {t for t in re.findall(r"[A-Za-z0-9][A-Za-z0-9.+-]*[A-Za-z0-9+]|[A-Za-z0-9]", expression)
            if t not in OPERATORS}


def annotations():
    """(compiled path patterns, licence identifiers) of REUSE.toml's annotations that set a licence."""
    path = root / "REUSE.toml"
    if not path.exists():
        return [], set()
    config = tomllib.loads(path.read_text(encoding="utf-8"))
    patterns, ids = [], set()
    for annotation in config.get("annotations", []):
        paths = annotation.get("path", [])
        if isinstance(paths, str):
            paths = [paths]
        expression = annotation.get("SPDX-License-Identifier")
        if expression:
            patterns += [reuse_pattern(p) for p in paths]
            ids |= licence_ids(expression)
    return patterns, ids


def header_licences(path):
    """The licence identifiers of the file's SPDX header (first 30 lines), or None when it has none."""
    try:
        with open(path, "rb") as f:
            head = b"".join(f.readline() for _ in range(30)).decode("utf-8", "replace")
    except OSError:
        return None
    lines = [line.split(TAG, 1)[1] for line in head.splitlines() if TAG in line]
    if not lines:
        return None
    return set().union(*(licence_ids(line) for line in lines))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--include-untracked", action="store_true")
    args = parser.parse_args()
    files = git_files(args.include_untracked)
    errors = []

    for f in files:
        if f.startswith("testdata/private/") and f != "testdata/private/README.md":
            errors.append(f"{f}: testdata/private/ is for local documents only and must never be committed")

    patterns, used = annotations()
    for f in files:
        p = root / f
        if not p.is_file() or p.name in IGNORED_NAMES or f.startswith("LICENSES/"):
            continue
        ids = header_licences(p)
        if ids is None and not any(pat.match(f) for pat in patterns):
            errors.append(f"{f}: no SPDX-License-Identifier header and no annotation in REUSE.toml")
        used |= ids or set()

    # From the directory, as `reuse lint` reads it (a new licence text can be checked before it is staged).
    texts = {t.stem for t in (root / "LICENSES").glob("*.txt")}
    for missing in sorted(used - texts):
        errors.append(f"LICENSES/{missing}.txt: missing; the text of every licence in use must be there (REUSE)")
    for unused in sorted(texts - used):
        errors.append(f"LICENSES/{unused}.txt: no file uses this licence; remove it or the reference is wrong")
    licence, copy = root / "LICENSE", root / "LICENSES/LGPL-2.1-or-later.txt"
    if licence.is_file() and copy.is_file() and licence.read_bytes() != copy.read_bytes():
        errors.append("LICENSES/LGPL-2.1-or-later.txt: must be a byte-for-byte copy of LICENSE")

    script = (root / "scripts/ci/install-graalvm.sh").read_text(encoding="utf-8")
    pom = (root / "java/pom.xml").read_text(encoding="utf-8")
    installed = re.search(r'^release="graal-([^"]+)"', script, re.M)
    compiled = re.search(r"<graalvm\.sdk\.version>([^<]+)</graalvm\.sdk\.version>", pom)
    if not installed or not compiled or installed.group(1) != compiled.group(1):
        errors.append("scripts/ci/install-graalvm.sh installs GraalVM CE "
                      f"{installed and installed.group(1)}, java/pom.xml compiles against "
                      f"graalvm.sdk.version {compiled and compiled.group(1)}: they must be the same release")

    for e in errors:
        print(e, file=sys.stderr)
    if errors:
        sys.exit(1)
    print(f"{len(files)} files checked")


if __name__ == "__main__":
    main()
