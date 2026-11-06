#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Regenerates the synthetic fixtures in testdata/fixtures/.
#   --new-pki        also replace the test PKI (testdata/fixtures/pki/test-pki.p12)
#   --signing-only   only write signing/ (external-signing cases), from the committed content and PKI
# Needs no network beyond Maven dependency resolution.
set -euo pipefail
cd "$(dirname "$0")/../java"
./mvnw -q -B test-compile exec:java \
  -Dexec.classpathScope=test \
  -Dexec.mainClass=it.codingduck.dssnative.testsupport.FixtureGenerator \
  -Dexec.args="$*" \
  -Ddssnative.repoRoot="$(cd .. && pwd)"
