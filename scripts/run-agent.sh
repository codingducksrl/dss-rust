#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Runs the JVM test suite under the GraalVM tracing agent (native-image-agent) and writes raw reachability
# metadata to java/target/agent-output/:
#
#   main/   calls made by library code: DSS and its dependencies. JUnit, Maven/Surefire and all of our own code
#           (engine and test support) are excluded as callers (scripts/agent/caller-filter.json).
#   full/   everything, including what only the tests need.
#   online/ with --online: the real-LOTL suite (needs internet), library calls only. Catches what only real
#           networks exercise (servers, TLS, redirects); merged into the library metadata.
#
# Then scripts/merge-metadata.py folds the results into the committed reachability-metadata.json files.
# Requires JAVA_HOME to point at GraalVM (the agent ships with it).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/java/target/agent-output"
: "${JAVA_HOME:?JAVA_HOME must point at GraalVM CE}"
if [[ ! -e "$JAVA_HOME/lib/libnative-image-agent.dylib" && ! -e "$JAVA_HOME/lib/libnative-image-agent.so" ]]; then
  echo "native-image-agent not found under $JAVA_HOME: is JAVA_HOME a GraalVM?" >&2
  exit 1
fi
rm -rf "$out"
cd "$root/java"
run() {
  local name="$1" extra="$2"; shift 2
  ./mvnw -B -q test "$@" \
    -DargLine="-agentlib:native-image-agent=config-output-dir=$out/$name$extra" \
    -Dsurefire.printSummary=true
}
filter=",caller-filter-file=$root/scripts/agent/caller-filter.json"
run main "$filter"
run full ""
if [[ "${1:-}" == "--online" ]]; then
  run online "$filter" -Pintegration
fi
echo "Agent output in $out/"
