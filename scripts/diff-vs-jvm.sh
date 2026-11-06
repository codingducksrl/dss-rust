#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Differential test: every fixture, and testdata/private/ when it holds documents, through plain DSS on the JVM
# and through the Rust -> native path. Compares per signature: indication, sub-indication, signature level,
# qualification, signing time, signer DN (at every nesting level). Any difference: exit status 1.
#
#   scripts/diff-vs-jvm.sh [--private-config FILE] [--private-cache DIR]
#
# Fixtures use a cache seeded from the synthetic trusted lists and embedded revocation only (no network).
# Private documents use testdata/private/config.json if present, else the real EU LOTL with online revocation;
# their cache defaults to build/diff/real-cache and is filled online on first use.
# Reports: build/diff/<set>.md. Needs scripts/build-native.sh first, JAVA_HOME (any JDK 21+), cargo.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
private_config="" private_cache=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --private-config) private_config="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"; shift 2 ;;
    --private-cache) mkdir -p "$2"; private_cache="$(cd "$2" && pwd)"; shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 64 ;;
  esac
done

work="$root/build/diff"
mkdir -p "$work"
(cd "$root/rust" && cargo build -q --release -p dss-cli)
cli="$root/rust/target/release/dss-cli"
(cd "$root/java" && ./mvnw -q -B test-compile)
validation_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
status=0

# Failures that only a native image produces. Libraries often catch and log them (PDFBox fell back to another
# charset this way), so the verdicts can still agree: the native log is checked as well.
native_only='Missing[A-Za-z]*RegistrationError|UnsupportedCharsetException|UnsupportedFeatureError|UnsatisfiedLinkError|NoClassDefFoundError'

# compare <name> <config> <cache> <cases>
compare() {
  local name="$1" config="$2" cache="$3" cases="$4"
  "$cli" --config "$config" --cache-dir "$cache" --log-level warn validate-batch --cases "$cases" \
    --validation-time "$validation_time" > "$work/$name.native.jsonl" 2> "$work/$name.native.log"
  if grep -qE "$native_only" "$work/$name.native.log"; then
    echo "$name: native-only failures in $work/$name.native.log:" >&2
    grep -E "$native_only" "$work/$name.native.log" | sort | uniq -c >&2
    status=1
  fi
  (cd "$root/java" && ./mvnw -q -B exec:java -Dexec.classpathScope=test \
    -Dexec.mainClass=it.codingduck.dssnative.diff.DiffVsNative \
    -Dorg.slf4j.simpleLogger.defaultLogLevel=error \
    -Dexec.args="--name $name --config $config --cache $cache --cases $cases --native $work/$name.native.jsonl --validation-time $validation_time --report $work/$name.md --base $root") \
    || status=1
}

# --- fixtures (synthetic trusted lists, offline)
synthetic="$work/synthetic"
rm -rf "$synthetic"
(cd "$root/java" && ./mvnw -q -B exec:java -Dexec.classpathScope=test \
  -Dexec.mainClass=it.codingduck.dssnative.testsupport.SyntheticCacheSeeder \
  -Dexec.args="$synthetic" -Ddssnative.repoRoot="$root" -Dorg.slf4j.simpleLogger.defaultLogLevel=error) >/dev/null
fx="$root/testdata/fixtures"
{
  find "$fx" -type f ! -path "*/pki/*" ! -name "README.md" | sort
  printf '%s\t%s\n' "$fx/cades/detached.txt.p7s" "$fx/content/document.txt"
  printf '%s\t%s\n' "$fx/cades/detached.txt.p7s" "$fx/tampered/content/document.txt"
} > "$work/fixtures.cases"
compare fixtures "$synthetic/config.json" "$synthetic/cache" "$work/fixtures.cases"

# --- private documents (real trusted lists)
priv="$root/testdata/private"
mapfile_cases() {
  find "$priv" -type f ! -name "README.md" ! -name "config.json" ! -name ".*" | sort | while read -r f; do
    if [[ "$f" == *.p7s && -f "${f%.p7s}" ]]; then
      printf '%s\t%s\n' "$f" "${f%.p7s}"
    else
      printf '%s\n' "$f"
    fi
  done
}
if [[ -n "$(mapfile_cases)" ]]; then
  config="${private_config:-}"
  if [[ -z "$config" ]]; then
    if [[ -f "$priv/config.json" ]]; then
      config="$priv/config.json"
    else
      config="$work/real-config.json"
      printf '{"oj_keystore":{"path":"%s"},"revocation":"online","log_level":"error"}' "$root/trust/oj-keystore.p12" > "$config"
    fi
  fi
  cache="${private_cache:-$work/real-cache}"
  if [[ ! -d "$cache/tl" ]] || [[ -z "$(ls -A "$cache/tl" 2>/dev/null)" ]]; then
    echo "Filling $cache from the real EU LOTL (online)..."
    "$cli" --config "$config" --cache-dir "$cache" tl refresh >/dev/null || true
  fi
  mapfile_cases > "$work/private.cases"
  compare private "$config" "$cache" "$work/private.cases"
else
  echo "testdata/private: no documents, skipped"
fi

exit "$status"
