#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Runs an unpacked release package on the machine it is on, offline, with the committed fixtures:
#
#   scripts/ci/package-smoke.sh <package_dir> <fixtures_dir> [<expected_version>]
#
# 1. bin/dss-cli version: the library loads (glibc / macOS floor, zlib, rpath) and reports the expected version;
#    bin/dss-server --version.
# 2. Validation of committed fixtures with the test root trusted and embedded revocation only: PAdES LTA passes,
#    a tampered PAdES fails with HASH_FAILURE.
# 3. Every recorded external signature in <fixtures_dir>/signing/ completes (`dss-cli sign complete`). Completing
#    needs the same digest the JVM computed when the fixture was recorded, so this also proves that this
#    machine's zlib (zlib-ng on Fedora, for instance) and the native drawing of visible signatures produce the
#    same bytes.
#
# CI runs it on the oldest supported systems (almalinux:9 = glibc 2.34, ubuntu:22.04, macOS 14) and on a zlib-ng
# distribution before a release is published. Needs only bash and the package: no Java, no network.
set -euo pipefail
pkg="$(cd "${1:?usage: package-smoke.sh <package_dir> <fixtures_dir> [version]}" && pwd)"
fx="$(cd "${2:?usage: package-smoke.sh <package_dir> <fixtures_dir> [version]}" && pwd)"
expected="${3:-}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cli=("$pkg/bin/dss-cli" --cache-dir "$work/cache" --offline-revocation --allow-without-trusted-lists
  --trust "$fx/pki/root-ca.pem" --log-level error)

echo "== version"
"${cli[@]}" version | tee "$work/version"
"$pkg/bin/dss-server" --version
if [[ -n "$expected" ]]; then
  grep -qxF "libdssnative $expected" "$work/version" || { echo "libdssnative is not $expected" >&2; exit 1; }
fi

# validate <file> <expected indication> [<expected sub-indication>]
validate() {
  local status=0
  "${cli[@]}" validate "$fx/$1" --json > "$work/result.json" || status=$?
  [[ $status == 0 || $status == 1 ]] || { echo "$1: dss-cli exited with $status" >&2; exit 1; }
  grep -q "\"indication\" *: *\"$2\"" "$work/result.json" || { echo "$1: expected $2:" >&2; cat "$work/result.json" >&2; exit 1; }
  if [[ -n "${3:-}" ]]; then
    grep -q "\"sub_indication\" *: *\"$3\"" "$work/result.json" || { echo "$1: expected $3:" >&2; cat "$work/result.json" >&2; exit 1; }
  fi
  echo "$1: $2${3:+ / $3}"
}
echo "== validation"
validate pades/b-lta.pdf TOTAL_PASSED
validate tampered/pades/b-lta.pdf TOTAL_FAILED HASH_FAILURE

echo "== recorded external signatures"
for case in pades-signature-value:content/document.pdf pades-cms:content/document.pdf \
  cades-cms:content/document.txt cades-signature-value:content/document.txt \
  pades-visible-cms:content/document.pdf pades-visible-field-signature-value:content/form.pdf; do
  name="${case%%:*}" document="${case#*:}"
  [[ -f "$fx/signing/$name.json" ]] || { echo "missing fixture signing/$name.json" >&2; exit 1; }
  "${cli[@]}" sign complete "$fx/$document" --request "$fx/signing/$name.json" \
    --signature "$fx/signing/$name.sig" --out "$work/$name.signed" --json > "$work/$name.result.json" \
    || { echo "$name: sign complete failed:" >&2; cat "$work/$name.result.json" >&2; exit 1; }
  [[ -s "$work/$name.signed" ]] || { echo "$name: no signed document" >&2; exit 1; }
  echo "$name: completed"
done
echo "package OK on $(uname -s) $(uname -m)"
