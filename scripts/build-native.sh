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
#
#   scripts/build-native.sh [--with-tests]   (default skips the JVM and native test suites)
#
# Requires JAVA_HOME = GraalVM Community Edition 25 (see docs/DECISIONS.md).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
skip=(-DskipTests)
[[ "${1:-}" == "--with-tests" ]] && skip=()
"$JAVA_HOME/bin/native-image" --version | head -1
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
t="$root/java/target"
cp "$t/libdssnative.$ext" "$t/libdssnative.h" "$t/libdssnative_dynamic.h" \
   "$t/graal_isolate.h" "$t/graal_isolate_dynamic.h" "$out/"
# native-image also writes JDK AWT libraries (libawt*, libfontmanager, ...) next to the image, because PDFBox
# references java.awt. They are deliberately not shipped, on any platform:
# - validation does not need them. PDDocument's static initializer creates a Raster, which tries to load libawt,
#   and PDFBox catches the UnsatisfiedLinkError;
# - the JDK's libawt keeps process-wide state and crashes when several isolates load it at the same time.
# scripts/smoke-test-c.sh runs from this directory, including isolates that validate PDFs concurrently.

# Licences of what the library contains, to ship with it (LICENSING.md, "Release packages"): the LGPL (dss-native
# and DSS), notices for DSS, PT Serif and stax2-api, every other third-party jar's own LICENSE/NOTICE files
# (collected by the pom's third-party-licenses execution), and GraalVM CE's licences, JDK notices included.
lic="$out/licenses"
mkdir -p "$lic/java" "$lic/graalvm"
cp "$root/LICENSE" "$lic/LGPL-2.1.txt"
cp "$root/third-party/dss.txt" "$root/third-party/pt-serif.txt" "$lic/"
for jar in "$t/third-party-licenses"/*/; do
  name="$(basename "$jar")"
  mkdir -p "$lic/java/$name"
  cp "$jar"META-INF/* "$lic/java/$name/"
done
cp "$root/third-party/stax2-api.txt" "$lic/java/stax2-api-"*/
cp -L "$JAVA_HOME/LICENSE.txt" "$JAVA_HOME/THIRD_PARTY_LICENSE.txt" "$lic/graalvm/"
# `release` records the source commit of every GraalVM component (SOURCE=...): the corresponding source of the
# GPL-licensed runtime in the library.
cp -L "$JAVA_HOME/release" "$lic/graalvm/"
cp -RL "$JAVA_HOME/legal" "$lic/graalvm/legal"

echo "Native library in $out:"
ls -la "$out"
