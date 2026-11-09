#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Builds the native shared library and collects what an application needs into build/native/<os>-<arch>/:
#
#   libdssnative.{so,dylib}   the library (DSS + wrapper + Substrate VM runtime)
#   libdssnative.h            dss_* functions        libdssnative_dynamic.h   same, as function-pointer types
#   graal_isolate.h           isolate/thread API      graal_isolate_dynamic.h
#   licenses/                 licence texts and notices of everything compiled into the library (LICENSING.md)
#   sbom/java.cdx.json        CycloneDX SBOM of the jars compiled into the library
#
#   scripts/build-native.sh [--with-tests]   (default skips the JVM and native test suites)
#
# Requires JAVA_HOME = GraalVM Community Edition, the release java/pom.xml pins (graalvm.sdk.version, the same as
# scripts/ci/install-graalvm.sh). Another vendor is refused: the library would contain a runtime under a
# different licence (LICENSING.md). Another CE release is refused in CI (CI=true) and only warned about locally.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
skip=(-DskipTests)
[[ "${1:-}" == "--with-tests" ]] && skip=()
"$root/scripts/ci/check-graalvm.sh" "${JAVA_HOME:?JAVA_HOME must be GraalVM Community Edition}"
"$JAVA_HOME/bin/native-image" --version | head -1
t="$root/java/target"
# The licence folders and SBOM are regenerated on every build: a dependency that was bumped or dropped must not
# leave its old notices behind. The dependency plugin skips artifacts it has markers for, so those go too.
rm -rf "$t/third-party-licenses" "$t/dependency-maven-plugin-markers" "$t/dss-native.cdx.json"
# ${skip[@]+...}: an empty array is "unbound" under set -u in bash 3.2 (macOS's /bin/bash).
(cd "$root/java" && ./mvnw -B -Pnative ${skip[@]+"${skip[@]}"} package)

case "$(uname -s)" in
  Darwin) os=macos; ext=dylib ;;
  Linux)  os=linux; ext=so ;;
  *) echo "unsupported OS $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=x64 ;;
  arm64|aarch64) arch=aarch64 ;;
  *) arch="$(uname -m)" ;;
esac
out="$root/build/native/$os-$arch"
rm -rf "$out" && mkdir -p "$out"
cp "$t/libdssnative.$ext" "$t/libdssnative.h" "$t/libdssnative_dynamic.h" \
   "$t/graal_isolate.h" "$t/graal_isolate_dynamic.h" "$out/"
# native-image also writes JDK AWT libraries (libawt*, libfontmanager, ...) next to the image, because PDFBox
# references java.awt. They are deliberately not shipped, on any platform:
# - validation does not need them. PDDocument's static initializer creates a Raster, which tries to load libawt,
#   and PDFBox catches the UnsatisfiedLinkError;
# - the JDK's libawt keeps process-wide state and crashes when several isolates load it at the same time.
# scripts/smoke-test-c.sh runs from this directory, including isolates that validate PDFs concurrently.

# Licences of what the library contains, and its SBOM, to ship with it (LICENSING.md, "Release packages").
"$root/scripts/ci/collect-native-licenses.sh" "$t" "$out" "$JAVA_HOME"

echo "Native library in $out:"
ls -la "$out"
