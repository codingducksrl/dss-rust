#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Runs the Rust workspace tests against the native library in build/native/<os>-<arch>/ (scripts/build-native.sh),
# including the tests that need setup:
#   synthetic_*  a trusted-list cache seeded from the synthetic LOTL/TLs (generated here via the Java test support)
#   online_*     the real EU LOTL; only with --online
#
#   scripts/test-rust.sh [--online]
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
synthetic="$root/rust/target/synthetic-tl"
rm -rf "$synthetic"
# exec.args is split again by exec-maven-plugin, on whitespace outside quotes: each argument is quoted.
(cd "$root/java" && ./mvnw -q -B test-compile exec:java -Dexec.classpathScope=test \
  -Dexec.mainClass=it.codingduck.dssnative.testsupport.SyntheticCacheSeeder \
  -Dexec.args="\"$synthetic\"" -Ddssnative.repoRoot="$root")
export DSS_TEST_SYNTHETIC_DIR="$synthetic"
skip=(--skip online_)
[[ "${1:-}" == "--online" ]] && skip=()
cd "$root/rust"
cargo test --locked --workspace --all-features -- --include-ignored ${skip[@]+"${skip[@]}"}
