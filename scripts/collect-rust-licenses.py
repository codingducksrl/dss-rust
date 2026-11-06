#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Copy the licence files of every crate compiled into dss-cli and dss-server, and the Rust standard library's
copyright notice, into <out_dir>. Release packages ship them as licenses/rust/ (scripts/package.sh, LICENSING.md).

  scripts/collect-rust-licenses.py <out_dir>

  <out_dir>/<crate>-<version>/   the crate's LICENSE*, COPYING*, COPYRIGHT*, NOTICE*, UNLICENSE* files
  <out_dir>/rust-std/            COPYRIGHT-library.html and the licence texts it refers to, from the toolchain
  <out_dir>/crates.tsv           crate, version, SPDX expression, repository

The crates are the ones Cargo.lock resolves for this machine's target, following normal dependencies only. Build
dependencies, dev-dependencies and procedural macros run at build time and are not part of the executables. A
crate that ships no licence file is an error, so a new dependency cannot slip into a package without its notice.
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

BINARIES = ("dss-cli", "dss-server")
LICENSE_PREFIXES = ("LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "NOTICE", "UNLICENSE")
# What COPYRIGHT-library.html refers to for the standard library's own sources; the texts of its out-of-tree
# dependencies are inside the HTML.
STD_LICENSES = ("Apache-2.0.txt", "MIT.txt", "BSD-2-Clause.txt", "Unicode-3.0.txt")

rust = Path(__file__).resolve().parent.parent / "rust"


def run(*cmd):
    return subprocess.run(cmd, cwd=rust, check=True, capture_output=True, text=True).stdout


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    out = Path(sys.argv[1])
    host = next(line.split()[1] for line in run("rustc", "-vV").splitlines() if line.startswith("host:"))
    meta = json.loads(run("cargo", "metadata", "--format-version", "1", "--locked", "--filter-platform", host))
    packages = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    workspace = set(meta["workspace_members"])

    def proc_macro(pkg_id):
        return any("proc-macro" in t["kind"] for t in packages[pkg_id]["targets"])

    todo = [i for i in workspace if packages[i]["name"] in BINARIES]
    linked = set()
    while todo:
        pkg_id = todo.pop()
        if pkg_id in linked:
            continue
        linked.add(pkg_id)
        for dep in nodes[pkg_id]["deps"]:
            normal = any(kind["kind"] is None for kind in dep["dep_kinds"])
            if normal and not proc_macro(dep["pkg"]):
                todo.append(dep["pkg"])

    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    index = []
    missing = []
    for pkg in sorted((packages[i] for i in linked - workspace), key=lambda p: (p["name"], p["version"])):
        src = Path(pkg["manifest_path"]).parent
        files = [f for f in src.iterdir() if f.is_file() and f.name.upper().startswith(LICENSE_PREFIXES)]
        if pkg.get("license_file"):
            files.append(src / pkg["license_file"])
        if not files:
            missing.append(f"{pkg['name']} {pkg['version']}")
            continue
        dest = out / f"{pkg['name']}-{pkg['version']}"
        dest.mkdir()
        for f in sorted(set(files)):
            shutil.copy(f, dest / f.name)
        index.append("\t".join((pkg["name"], pkg["version"], pkg["license"] or "", pkg["repository"] or "")))
    if missing:
        sys.exit("crates without a licence file: " + ", ".join(missing))
    (out / "crates.tsv").write_text("crate\tversion\tlicense\trepository\n" + "\n".join(index) + "\n")

    doc = Path(run("rustc", "--print", "sysroot").strip()) / "share" / "doc" / "rust"
    std = out / "rust-std"
    (std / "licenses").mkdir(parents=True)
    shutil.copy(doc / "COPYRIGHT-library.html", std)
    for name in STD_LICENSES:
        shutil.copy(doc / "licenses" / name, std / "licenses")
    print(f"{len(index)} crates + the standard library -> {out}")


if __name__ == "__main__":
    main()
