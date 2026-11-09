#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Installs the pinned GraalVM Community Edition (see docs/DECISIONS.md) and prints its JAVA_HOME.
#
#   home="$(scripts/ci/install-graalvm.sh <install_dir>)"
#
# The tarball's SHA-256 is checked against the values pinned below, not against a checksum file downloaded
# from the same place. Community Edition only (GPLv2 + Classpath Exception); never Oracle GraalVM.
#
# <install_dir>/download/ keeps the tarball (CI caches only that folder). Its checksum is verified on every run,
# and the JDK is extracted afresh into <install_dir>/<release>/, so neither a stale nor a tampered cache can
# become the compiler. Bumping the pin: release, asset_version and the three SHA-256 values below (the cache key
# in .github/actions/setup hashes this file), and graalvm.sdk.version in java/pom.xml.
set -euo pipefail
release="graal-25.5.5.0.3"
asset_version="25i5-25.0.5.0.3"
graalvm_version="${release#graal-}"
# Pinned SHA-256 per platform (bash 3.2 compatible: macOS's /bin/bash has no associative arrays). Taken from the
# release's published .sha256 files and checked against GitHub's own asset digests.
expected_sha256() {
  case "$1" in
    linux-x64) echo c6438dee6c3ade2220d40b7ccdcad24b512d30e233e61bb4fc70519522de34ef ;;
    linux-aarch64) echo 41741c0650ae7564a78335f9e4fc353a902e6ff1d4140f2e4fabd1c55d5cce66 ;;
    macos-aarch64) echo 54369d4a5931a5a2101c7c52444a4e7e6647a3a4e041335053cda6fd22295e0c ;;
  esac
}
dest="${1:?usage: install-graalvm.sh <install_dir>}"
case "$(uname -s)" in Darwin) os=macos ;; Linux) os=linux ;; *) echo "unsupported OS" >&2; exit 1 ;; esac
case "$(uname -m)" in x86_64|amd64) arch=x64 ;; arm64|aarch64) arch=aarch64 ;; *) echo "unsupported arch" >&2; exit 1 ;; esac
platform="$os-$arch"
expected="$(expected_sha256 "$platform")"
[[ -n "$expected" ]] || { echo "GraalVM CE $release has no build for $platform" >&2; exit 1; }

sha256_of() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}
home_of() { if [[ "$os" == macos ]]; then echo "$1/Contents/Home"; else echo "$1"; fi; }

file="graalvm-community-jdk-${asset_version}_${platform}_bin.tar.gz"
downloads="$dest/download"
tarball="$downloads/$file"
mkdir -p "$downloads"
# A cached tarball is used only if it still has the pinned checksum; anything else in download/ is dropped.
if [[ -f "$tarball" && "$(sha256_of "$tarball")" != "$expected" ]]; then
  echo "cached $file does not have the pinned SHA-256: downloading it again" >&2
  rm -f "$tarball"
fi
find "$downloads" -mindepth 1 -maxdepth 1 ! -name "$file" -exec rm -rf {} +
if [[ ! -f "$tarball" ]]; then
  curl -fsSL --retry 3 -o "$tarball.part" "https://github.com/graalvm/graalvm-ce-builds/releases/download/$release/$file"
  actual="$(sha256_of "$tarball.part")"
  [[ "$actual" == "$expected" ]] || { rm -f "$tarball.part"; echo "SHA-256 mismatch for $file: $actual" >&2; exit 1; }
  mv "$tarball.part" "$tarball"
fi

# Always a fresh extraction from the verified tarball.
target="$dest/$release"
rm -rf "$target" && mkdir -p "$target"
tar -xzf "$tarball" -C "$target"
installed="$(find "$target" -mindepth 1 -maxdepth 1 -type d -name 'graalvm-community-*' | head -1)"
[[ -n "$installed" ]] || { echo "$file holds no graalvm-community-* folder" >&2; exit 1; }
home="$(home_of "$installed")"
# The release file must name the pinned Community Edition: guards against a wrong pin above.
grep -qx 'IMPLEMENTOR="GraalVM Community"' "$home/release" \
  || { echo "$home is not GraalVM Community Edition" >&2; exit 1; }
grep -qx "GRAALVM_VERSION=\"$graalvm_version\"" "$home/release" \
  || { echo "$home is not GraalVM $graalvm_version" >&2; exit 1; }
[[ -x "$home/bin/native-image" ]] || { echo "$home has no bin/native-image" >&2; exit 1; }
echo "$home"
