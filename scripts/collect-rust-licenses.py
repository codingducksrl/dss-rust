#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Copy the licence files of every crate compiled into dss-cli and dss-server, and the Rust standard library's
copyright notice, into <out_dir>. Release packages ship them as licenses/rust/ (scripts/package.sh, LICENSING.md).

  scripts/collect-rust-licenses.py <out_dir> [--sbom FILE] [--force]

  <out_dir>/<crate>-<version>/   the crate's LICENSE*, COPYING*, COPYRIGHT*, NOTICE*, UNLICENSE* files
  <out_dir>/rust-std/            COPYRIGHT-library.html and the licence texts it refers to, from the toolchain
  <out_dir>/crates.tsv           crate, version, SPDX expression, repository
  --sbom FILE                    also a CycloneDX 1.6 JSON SBOM of the same crates

<out_dir> must not exist or be empty: the script fills it from scratch. --force lets it delete the contents of a
non-empty <out_dir> first; the repository itself, rust/, dist/, the home directory and / are refused even then.

The crates are the ones Cargo.lock resolves for this machine's target, following normal dependencies only. Build
dependencies, dev-dependencies and procedural macros run at build time and are not part of the executables. A
crate that ships no licence file is an error, so a new dependency cannot slip into a package without its notice.
"""
import argparse
import json
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

BINARIES = ("dss-cli", "dss-server")
LICENSE_PREFIXES = ("LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "NOTICE", "UNLICENSE")
# What COPYRIGHT-library.html refers to for the standard library's own sources; the texts of its out-of-tree
# dependencies are inside the HTML.
STD_LICENSES = ("Apache-2.0.txt", "MIT.txt", "BSD-2-Clause.txt", "Unicode-3.0.txt")

repo = Path(__file__).resolve().parent.parent
rust = repo / "rust"


def run(*cmd):
    return subprocess.run(cmd, cwd=rust, check=True, capture_output=True, text=True).stdout


def check_out_dir(out, force):
    """Refuses a directory whose contents would be lost: anything non-empty without --force, and folders that
    are never an output (the repository, its rust/ and dist/, the home directory, /) even with it."""
    resolved = out.resolve()
    protected = {Path("/"), Path.home().resolve(), repo, rust, repo / "dist"}
    if resolved in protected or resolved in repo.parents:
        sys.exit(f"refusing to write into {out}: choose a new, empty directory")
    if out.exists():
        if not out.is_dir():
            sys.exit(f"{out} exists and is not a directory")
        if any(out.iterdir()) and not force:
            sys.exit(f"{out} is not empty: choose a new directory, or pass --force to replace its contents")


def write_sbom(path, pkgs):
    """CycloneDX 1.6: one library component per crate compiled into dss-cli or dss-server."""
    components = []
    for pkg in pkgs:
        purl = f"pkg:cargo/{pkg['name']}@{pkg['version']}"
        component = {"type": "library", "bom-ref": purl, "name": pkg["name"], "version": pkg["version"], "purl": purl}
        if pkg["license"]:
            # Old manifests write "MIT/Apache-2.0"; SPDX (and CycloneDX) wants "MIT OR Apache-2.0".
            component["licenses"] = [{"expression": pkg["license"].replace("/", " OR ")}]
        if pkg["repository"]:
            component["externalReferences"] = [{"type": "vcs", "url": pkg["repository"]}]
        components.append(component)
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, json.dumps(components, sort_keys=True))}",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "dss-native (dss-cli, dss-server)"}},
        "components": components,
    }
    Path(path).write_text(json.dumps(bom, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("out_dir")
    parser.add_argument("--sbom")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    out = Path(args.out_dir)
    check_out_dir(out, args.force)
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
    pkgs = sorted((packages[i] for i in linked - workspace), key=lambda p: (p["name"], p["version"]))
    index = []
    missing = []
    for pkg in pkgs:
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
    if args.sbom:
        write_sbom(args.sbom, pkgs)
    print(f"{len(index)} crates + the standard library -> {out}")


if __name__ == "__main__":
    main()
