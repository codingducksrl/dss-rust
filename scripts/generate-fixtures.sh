#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Regenerates the synthetic fixtures in testdata/fixtures/ (FixtureGenerator in the test sources).
#
#   scripts/generate-fixtures.sh [--new-pki] [--signing-only] [--out=<dir>] [--time=<ISO-8601 instant>]
#
#   --new-pki          also replace the test PKI (pki/test-pki.p12); it is derived from fixed seeds, so it is the
#                      same PKI again (only the PKCS#12 container's salts change)
#   --signing-only     only write signing/ (external-signing cases), from the content/ and PKI already there
#   --out=<dir>        write into <dir> instead of testdata/fixtures (a relative path is taken from the current
#                      directory); a directory without a PKI or content/stamp.jpg gets a copy of the committed ones.
#                      To check that a regeneration is byte-identical:
#                        scripts/generate-fixtures.sh --out=/tmp/check && diff -r -x README.md testdata/fixtures /tmp/check
#   --time=<instant>   the fixture clock's start (default 2026-11-01T09:00:00Z), e.g. --time=2027-01-01T00:00:00Z
#
# The generator runs in its own JVM, started with -XX:+UnlockExperimentalVMOptions -XX:hashCode=2
# (FixtureGenerator.JVM_OPTIONS): DSS orders a PAdES DSS dictionary's certificates by identity hash codes, so
# without it pades/b-lt.pdf and b-lta.pdf could differ from one run to the next. exec:java would run it inside
# Maven's own JVM, which does not have the flag. Uses $JAVA_HOME/bin/java (JDK 21 or later), else java on PATH.
# Needs no network beyond Maven dependency resolution (MAVEN_ARGS=-o for an offline Maven).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
# exec.args is split again by exec-maven-plugin on whitespace outside quotes: every argument is double-quoted, so
# one that contains a double quote cannot be passed through.
quote() {
  [[ "$1" != *\"* ]] || { echo "generate-fixtures: an argument cannot contain a double quote: $1" >&2; exit 2; }
  printf '"%s"' "$1"
}
args=()
for arg in "$@"; do
  case "$arg" in
    --out=)
      echo "generate-fixtures: --out needs a directory" >&2; exit 2 ;;
    --out=/*) ;;
    --out=*)
      # Maven runs the generator in java/: resolve a relative directory against the caller's directory instead.
      arg="--out=$PWD/${arg#--out=}" ;;
  esac
  args+=("$(quote "$arg")")
done
java_bin="${JAVA_HOME:+$JAVA_HOME/bin/}java"
cd "$root/java"
./mvnw -q -B test-compile exec:exec \
  -Dexec.classpathScope=test \
  -Dexec.executable="$java_bin" \
  -Dexec.args="-XX:+UnlockExperimentalVMOptions -XX:hashCode=2 -Djava.awt.headless=true -Dorg.slf4j.simpleLogger.defaultLogLevel=warn -Ddssnative.repoRoot=$(quote "$root") -classpath %classpath it.codingduck.dssnative.testsupport.FixtureGenerator ${args[*]+${args[*]}}"
