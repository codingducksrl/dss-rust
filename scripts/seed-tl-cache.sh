#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Builds a trusted-list cache snapshot to ship with the application.
#
#   scripts/seed-tl-cache.sh <cache_dir> [config.json]
#
# Downloads and validates the EU LOTL and national TLs into <cache_dir>/tl/. The default config uses
# trust/oj-keystore.p12 and the full LOTL. Exit status: 0 all lists OK, 1 some list has a problem (snapshot still
# written), 2 nothing loaded. Runs on the JVM until the native CLI exists (Phase 4).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cache_dir="${1:?usage: seed-tl-cache.sh <cache_dir> [config.json]}"
config="${2:-}"
mkdir -p "$cache_dir"
cache_dir="$(cd "$cache_dir" && pwd)"
if [[ -z "$config" ]]; then
  config="$(mktemp)"
  trap 'rm -f "$config"' EXIT
  printf '{"oj_keystore":{"path":"%s"}}' "$root/trust/oj-keystore.p12" > "$config"
fi
cd "$root/java"
./mvnw -q -B compile exec:java \
  -Dexec.mainClass=it.codingduck.dssnative.engine.CacheSeeder \
  -Dexec.args="$cache_dir $config"
