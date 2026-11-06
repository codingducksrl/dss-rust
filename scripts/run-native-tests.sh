#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Re-runs the native JUnit executable built by `./mvnw -Pnative test` without rebuilding it.
# Extra arguments go to the executable first, e.g. runtime options:
#
#   scripts/run-native-tests.sh -XX:MissingRegistrationReportingMode=Warn
#   scripts/run-native-tests.sh -XX:MissingRegistrationReportingMode=Exit
#   LANG=it_IT.UTF-8 TZ=Europe/Rome scripts/run-native-tests.sh -Duser.language=it -Duser.country=IT
set -euo pipefail
java_dir="$(cd "$(dirname "$0")/../java" && pwd)"
exe="$java_dir/target/native-tests"
[[ -x "$exe" ]] || { echo "missing $exe: run 'cd java && ./mvnw -Pnative test' first" >&2; exit 1; }
exec "$exe" "$@" \
  --xml-output-dir "$java_dir/target/native-test-reports" \
  -Ddssnative.repoRoot="$java_dir/.." \
  -Djunit.platform.listeners.uid.tracking.enabled=true \
  -Djunit.platform.listeners.uid.tracking.output.dir="$java_dir/target/maven-surefire-plugin-test-ids" \
  -Dorg.slf4j.simpleLogger.defaultLogLevel=warn
