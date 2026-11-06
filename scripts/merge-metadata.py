#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Fold tracing-agent output (scripts/run-agent.sh) into the committed reachability-metadata.json files.

  main  <- java/target/agent-output/main (+ online, if present), minus entries covered elsewhere (DROP_* below)
  test  <- java/target/agent-output/full, minus everything already in main

Existing entries are kept (union), so hand-written additions survive re-runs. Use --replace to rebuild both
files from the agent output alone. Run with `python3 -I scripts/merge-metadata.py`.
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
AGENT = ROOT / "java/target/agent-output"
MAIN = ROOT / "java/src/main/resources/META-INF/native-image/it.codingduck.dssnative/dss-native/reachability-metadata.json"
TEST = ROOT / "java/src/test/resources/META-INF/native-image/it.codingduck.dssnative/dss-native-tests/reachability-metadata.json"

# Test infrastructure. The caller filter already drops calls made *by* these, but the JDK's ServiceLoader and
# resource lookups made on their behalf are attributed to JDK callers.
TEST_ONLY = re.compile(
    r"^(org\.junit|org\.opentest4j|org\.apiguardian|org\.apache\.maven|org\.testng|kotlin\.|it\.codingduck\.dssnative)"
    r"|META-INF/services/(org\.junit|org\.apache\.maven|com\.sun\.net\.httpserver)|^junit-platform\.properties$"
    r"|^com\.sun\.net\.httpserver\.|^sun\.net\.httpserver\."
    r"|^jdk/jfr/|^sun\.management\.|^jdk\.jfr\."
)

# Registered as whole families by DssFeature (java/src/main/java/.../nativeimage/DssFeature.java).
DROP_FEATURE = re.compile(
    r"^eu\.europa\.esig\..*\.jaxb(\.|$)"              # JAXB-generated model classes and adapters
    r"|^eu\.europa\.esig\.(validationreport|xmldsig|xades|trustedlist|trustedlist211)\.jaxb"
    r"|^org\.bouncycastle\.(jcajce|pqc\.jcajce|jce)\.provider\."  # BouncyCastle provider services + $Mappings
    r"|^jakarta\.xml\.bind\.annotation\."             # JAXB annotation types (members + proxies)
    r"|^org\.apache\.xml\.security\.(algorithms|c14n|transforms|keys\.keyresolver|utils\.resolver)\.implementations\."
    r"|^(xsd/|policy/|suite/)|^dss-messages"          # resources registered by glob
    r"|^org/apache/(pdfbox/resources|fontbox/cmap)/|^fonts/PTSerifRegular\.ttf$"
    r"|^org\.apache\.pdfbox\.pdmodel\.encryption\.[A-Za-z]+SecurityHandler$"
)

# JCA service implementations of the JDK's own providers: native-image's security services support registers
# them when the corresponding getInstance call is reachable. Platform-specific (e.g. Apple, NativePRNG).
DROP_JDK_PROVIDERS = re.compile(
    r"^(sun\.security\.(provider|rsa|ec|pkcs12|ssl)\.|com\.sun\.crypto\.provider\.|apple\.security\.)"
)

# ImageIO and the JDK's colour management, used only by the JVM-only tests (@DisabledInNativeImage) that compare
# our PNG decoder and sRGB profile with them. The agent attributes those calls to JDK callers; neither the library
# (visible signatures are drawn without AWT) nor the native tests need them.
DROP_JVM_ONLY_TESTS = re.compile(
    r"^javax\.imageio\.|^META-INF/services/javax\.imageio\."
    r"|^sun\.awt\.image\.(ByteComponentRaster|BytePackedRaster|ShortComponentRaster)$"
    r"|^java\.awt\.image\.IndexColorModel$|^sun\.java2d\.Disposer$"
    r"|^sun\.awt\.resources\.awt$|^sun/awt/resources/|^sun/java2d/cmm/profiles/"
)


def without_feature_serialization(doc):
    """Drops the agent's Java-serialization records for library classes.

    DssFeature registers the trusted-list snapshot's serialization, both ways, from TlSnapshotFile's own allowlist
    (whole DSS model packages); the agent only sees the classes the test lists happen to contain. Test classes
    keep theirs. An entry recorded for serialization alone disappears; one with other members keeps them.
    """
    kept = []
    for e in doc.get("reflection", []):
        if e.get("serializable") and not TEST_ONLY.search(type_name(e)):
            e = {k: v for k, v in e.items() if k != "serializable"}
            if set(e) == {"type"}:
                continue
        kept.append(e)
    return {**doc, "reflection": kept} if doc else doc


def type_name(entry):
    t = entry.get("type")
    if isinstance(t, dict):
        if "proxy" in t:
            return t["proxy"][0]
        return json.dumps(t, sort_keys=True)
    return t or ""


def resource_name(entry):
    return entry.get("glob") or entry.get("bundle") or ""


def load(path):
    if path.exists():
        return json.loads(path.read_text())
    return {}


def key(entry):
    return json.dumps(entry.get("type"), sort_keys=True)


def merge_members(target, source):
    for flag, value in source.items():
        if flag in ("type", "fields", "methods"):
            continue
        if isinstance(value, bool):
            target[flag] = target.get(flag, False) or value
        elif flag not in target:
            target[flag] = value
    for member in ("fields", "methods"):
        if member in source:
            seen = {json.dumps(m, sort_keys=True) for m in target.get(member, [])}
            for m in source[member]:
                if json.dumps(m, sort_keys=True) not in seen:
                    target.setdefault(member, []).append(m)
                    seen.add(json.dumps(m, sort_keys=True))


def union(base, extra, keep=lambda e, kind: True):
    out = {"reflection": [], "resources": []}
    index = {}
    for doc in (base, extra):
        for e in doc.get("reflection", []):
            if not keep(e, "reflection"):
                continue
            k = key(e)
            if k in index:
                merge_members(index[k], e)
            else:
                copy = json.loads(json.dumps(e))
                index[k] = copy
                out["reflection"].append(copy)
        seen = {json.dumps(r, sort_keys=True) for r in out["resources"]}
        for r in doc.get("resources", []):
            if keep(r, "resources") and json.dumps(r, sort_keys=True) not in seen:
                out["resources"].append(r)
                seen.add(json.dumps(r, sort_keys=True))
    for kind in ("jni", "serialization"):
        for doc in (base, extra):
            for e in doc.get(kind, []):
                if keep(e, kind):
                    out.setdefault(kind, []).append(e)
    out["reflection"].sort(key=type_name)
    out["resources"].sort(key=lambda r: (r.get("module", ""), resource_name(r)))
    return out


def main_filter(entry, kind):
    name = type_name(entry) if kind != "resources" else resource_name(entry)
    return not (TEST_ONLY.search(name) or DROP_FEATURE.search(name) or DROP_JDK_PROVIDERS.search(name)
                or DROP_JVM_ONLY_TESTS.search(name))


def write(path, doc):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2) + "\n")
    counts = {k: len(v) for k, v in doc.items() if isinstance(v, list)}
    print(f"{path.relative_to(ROOT)}: {counts}")


def main():
    replace = "--replace" in sys.argv
    agent_main = without_feature_serialization(load(AGENT / "main/reachability-metadata.json"))
    agent_full = without_feature_serialization(load(AGENT / "full/reachability-metadata.json"))
    if not agent_main:
        sys.exit("no agent output: run scripts/run-agent.sh first")

    # from run-agent.sh --online, optional
    agent_online = without_feature_serialization(load(AGENT / "online/reachability-metadata.json"))
    main_doc = union(union({} if replace else load(MAIN), agent_main, main_filter), agent_online, main_filter)
    write(MAIN, main_doc)

    in_main = {key(e) for e in main_doc["reflection"]}
    main_res = {json.dumps(r, sort_keys=True) for r in main_doc["resources"]}

    def test_filter(entry, kind):
        if kind == "resources":
            name = resource_name(entry)
            return (json.dumps(entry, sort_keys=True) not in main_res and not DROP_FEATURE.search(name)
                    and not DROP_JVM_ONLY_TESTS.search(name))
        name = type_name(entry)
        if DROP_FEATURE.search(name) or DROP_JDK_PROVIDERS.search(name) or DROP_JVM_ONLY_TESTS.search(name):
            return False
        return key(entry) not in in_main

    write(TEST, union({} if replace else load(TEST), agent_full, test_filter))


if __name__ == "__main__":
    main()
