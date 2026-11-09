#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Downloads the corresponding source of the third-party code compiled into libdssnative, to attach to a GitHub
# release next to the packages (LICENSING.md, "Source of the release packages"):
#
#   dss-<version>-source.tar.gz                 EU DSS (LGPL-2.1-or-later), the tag of java/pom.xml's dss.version
#   graal-<commit>-source.tar.gz                GraalVM CE's own components (Substrate VM, SDK, compiler: GPLv2 +
#                                               Classpath Exception, UPL), the commit in the build's release file
#   labs-openjdk-<tag>-source.tar.gz            the JDK class library GraalVM CE is built from (GPLv2 + CPE), the
#                                               jvmci tag of the build's JAVA_RUNTIME_VERSION
#
#   scripts/ci/fetch-sources.sh <graalvm_release_file> <out_dir> [--print-urls]
#
# <graalvm_release_file> is licenses/graalvm/release from the package (the GraalVM CE the library was built
# with). --print-urls prints "<file> <url>" lines instead of downloading.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
release_file="${1:?usage: fetch-sources.sh <graalvm_release_file> <out_dir> [--print-urls]}"
out="${2:?usage: fetch-sources.sh <graalvm_release_file> <out_dir> [--print-urls]}"
print_only=false
[[ "${3:-}" == "--print-urls" ]] && print_only=true

field() { sed -n "s/^$1=\"\(.*\)\"\$/\1/p" "$release_file" | head -1; }
[[ "$(field IMPLEMENTOR)" == "GraalVM Community" ]] || { echo "$release_file is not GraalVM Community Edition's" >&2; exit 1; }
runtime="$(field JAVA_RUNTIME_VERSION)"
jvmci="${runtime##*-jvmci-}"
[[ -n "$runtime" && "$jvmci" != "$runtime" ]] || { echo "no -jvmci- tag in JAVA_RUNTIME_VERSION=$runtime" >&2; exit 1; }
graal_commit="$(field SOURCE | tr ' ' '\n' | sed -n 's/^substratevm:\([0-9a-f]\{40\}\)$/\1/p' | head -1)"
[[ -n "$graal_commit" ]] || { echo "no substratevm commit in SOURCE of $release_file" >&2; exit 1; }
dss_version="$(sed -n 's#^ *<dss.version>\(.*\)</dss.version>#\1#p' "$root/java/pom.xml")"
[[ -n "$dss_version" ]] || { echo "no dss.version in java/pom.xml" >&2; exit 1; }

sources=(
  "dss-$dss_version-source.tar.gz https://github.com/esig/dss/archive/refs/tags/$dss_version.tar.gz"
  "graal-$graal_commit-source.tar.gz https://github.com/oracle/graal/archive/$graal_commit.tar.gz"
  "labs-openjdk-jvmci-$jvmci-source.tar.gz https://github.com/graalvm/labs-openjdk/archive/refs/tags/jvmci-$jvmci.tar.gz"
)
if $print_only; then
  printf '%s\n' "${sources[@]}"
  exit 0
fi
mkdir -p "$out"
for entry in "${sources[@]}"; do
  file="${entry%% *}" url="${entry#* }"
  echo "$file <- $url"
  curl -fsSL --retry 3 -o "$out/$file.part" "$url"
  gzip -t "$out/$file.part"
  mv "$out/$file.part" "$out/$file"
done
