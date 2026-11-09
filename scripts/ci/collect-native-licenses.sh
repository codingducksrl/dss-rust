#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Collects the licences and the SBOM of what libdssnative contains next to it (scripts/build-native.sh):
#
#   scripts/ci/collect-native-licenses.sh <java_target_dir> <out_dir> <java_home>
#
#   <out_dir>/licenses/   LICENSING.md, "Release packages"
#   <out_dir>/sbom/java.cdx.json
#
# <java_target_dir> is java/target after `./mvnw -Pnative package`: third-party-licenses/ (the pom's
# third-party-licenses execution) and dss-native.cdx.json (its sbom execution). <java_home> is the GraalVM CE the
# library was built with. Both outputs are replaced, never merged with an earlier build's.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
t="${1:?usage: collect-native-licenses.sh <java_target_dir> <out_dir> <java_home>}"
out="${2:?usage: collect-native-licenses.sh <java_target_dir> <out_dir> <java_home>}"
JAVA_HOME="${3:?usage: collect-native-licenses.sh <java_target_dir> <out_dir> <java_home>}"
[[ -d "$t/third-party-licenses" ]] || { echo "no $t/third-party-licenses: build with -Pnative first" >&2; exit 1; }
[[ -f "$t/dss-native.cdx.json" ]] || { echo "no $t/dss-native.cdx.json: build with -Pnative first" >&2; exit 1; }

# Licences of what the library contains, to ship with it (LICENSING.md, "Release packages"): the LGPL (dss-native
# and DSS), notices for DSS, PT Serif, the XML Signature schema (W3C) and the Public Suffix List (MPL-2.0), every
# other third-party jar's own LICENSE/NOTICE files (collected by the pom's third-party-licenses execution, with
# full notices for Stax2 API and Woodstox, whose jars only point to their licence), the GraalVM SDK's UPL, and
# GraalVM CE's licences, JDK notices included.
lic="$out/licenses"
rm -rf "$lic" "$out/sbom"
mkdir -p "$lic/java" "$lic/graalvm"
cp "$root/LICENSE" "$lic/LGPL-2.1.txt"
cp "$root/third-party/dss.txt" "$root/third-party/pt-serif.txt" "$root/third-party/xmldsig-core-schema.txt" "$lic/"
for jar in "$t/third-party-licenses"/*/; do
  name="$(basename "$jar")"
  mkdir -p "$lic/java/$name"
  cp "$jar"META-INF/* "$lic/java/$name/"
done
# The one folder of <artifact>-<version>; anything but exactly one match is an error.
artifact_dir() {
  local matches=("$lic/java/$1-"[0-9]*/)
  [[ ${#matches[@]} == 1 && -d "${matches[0]}" ]] || { echo "expected one $1 folder in $lic/java, found: ${matches[*]}" >&2; exit 1; }
  echo "${matches[0]}"
}
# Assigned first: a failing $(...) inside cp's arguments would not stop the script.
stax2="$(artifact_dir stax2-api)"; woodstox="$(artifact_dir woodstox-core)"; httpclient="$(artifact_dir httpclient5)"
cp "$root/third-party/stax2-api.txt" "$stax2"
cp "$root/third-party/woodstox.txt" "$woodstox"
cp "$root/third-party/public-suffix-list.txt" "$httpclient"
cp "$root/third-party/graalvm-sdk.txt" "$lic/graalvm/"
cp -L "$JAVA_HOME/LICENSE.txt" "$JAVA_HOME/THIRD_PARTY_LICENSE.txt" "$lic/graalvm/"
# `release` records the source commit of every GraalVM component (SOURCE=...): the corresponding source of the
# GPL-licensed runtime in the library.
cp -L "$JAVA_HOME/release" "$lic/graalvm/"
cp -RL "$JAVA_HOME/legal" "$lic/graalvm/legal"
mkdir -p "$out/sbom"
cp "$t/dss-native.cdx.json" "$out/sbom/java.cdx.json"

