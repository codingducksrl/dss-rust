#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Checks that a JDK is the GraalVM Community Edition release the project pins, before it compiles the library.
#
#   scripts/ci/check-graalvm.sh <java_home>
#
# - Another vendor (Oracle GraalVM, any other JDK) is an error: the library would contain a runtime under a
#   different licence than LICENSING.md and the package's SOURCE describe.
# - Another Community Edition release than graalvm.sdk.version in java/pom.xml (the release
#   scripts/ci/install-graalvm.sh pins) is an error in CI (CI=true, or DSS_STRICT_GRAALVM=1) and a warning
#   otherwise, so a developer can still build with the release installed locally.
# Prints "<vendor>\t<version>" of the JDK on success.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
home="${1:?usage: check-graalvm.sh <java_home>}"
release="$home/release"
[[ -f "$release" ]] || { echo "$home has no release file: not a JDK" >&2; exit 1; }
field() { sed -n "s/^$1=\"\(.*\)\"\$/\1/p" "$release" | head -1; }
vendor="$(field IMPLEMENTOR)"
version="$(field GRAALVM_VERSION)"
if [[ "$vendor" != "GraalVM Community" || -z "$version" ]]; then
  echo "$home is ${vendor:-an unknown vendor}${version:+ GraalVM $version}, not GraalVM Community Edition:" \
    "only GraalVM CE may be compiled into the library (docs/DECISIONS.md, LICENSING.md)" >&2
  exit 1
fi
pinned="$(sed -n 's#^ *<graalvm.sdk.version>\(.*\)</graalvm.sdk.version>#\1#p' "$root/java/pom.xml")"
[[ -n "$pinned" ]] || { echo "no graalvm.sdk.version in java/pom.xml" >&2; exit 1; }
if [[ "$version" != "$pinned" ]]; then
  if [[ "${CI:-}" == true || "${DSS_STRICT_GRAALVM:-}" == 1 ]]; then
    echo "$home is GraalVM CE $version, but java/pom.xml pins $pinned" >&2
    exit 1
  fi
  echo "warning: building with GraalVM CE $version, but java/pom.xml pins $pinned: the library will embed" \
    "that release's JDK and CA bundle (CI refuses this)" >&2
fi
printf '%s\t%s\n' "$vendor" "$version"
