#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Installs the pinned GraalVM Community Edition (see docs/DECISIONS.md) and prints its JAVA_HOME.
#
#   JAVA_HOME="$(scripts/ci/install-graalvm.sh <install_dir>)"
#
# The tarball's SHA-256 is checked against the values pinned below, not against a checksum file downloaded
# from the same place. Community Edition only (GPLv2 + Classpath Exception); never Oracle GraalVM.
set -euo pipefail
release="graal-25.4.4.1.1"
asset_version="25i4-25.0.4.1.1"
# Pinned SHA-256 per platform (bash 3.2 compatible: macOS's /bin/bash has no associative arrays).
expected_sha256() {
  case "$1" in
    linux-x64) echo 05ccbbe783210b6886ff7b08fcd0b061c5dce4852b05db87284fc0e24abb08e2 ;;
    linux-aarch64) echo e5f5e2f59643cf96765c741dc00b206f86c69c8c1bf843fe26050c871e0e2dbc ;;
    macos-aarch64) echo 4ec9932aa4aab1afca0ea31982d32d6f956615c61fe21a227b49756b25adda4f ;;
  esac
}
dest="${1:?usage: install-graalvm.sh <install_dir>}"
case "$(uname -s)" in Darwin) os=macos ;; Linux) os=linux ;; *) echo "unsupported OS" >&2; exit 1 ;; esac
case "$(uname -m)" in x86_64|amd64) arch=x64 ;; arm64|aarch64) arch=aarch64 ;; *) echo "unsupported arch" >&2; exit 1 ;; esac
platform="$os-$arch"
expected="$(expected_sha256 "$platform")"
[[ -n "$expected" ]] || { echo "GraalVM CE $release has no build for $platform" >&2; exit 1; }

home_of() { if [[ "$os" == macos ]]; then echo "$1/Contents/Home"; else echo "$1"; fi; }
mkdir -p "$dest"
existing="$(find "$dest" -maxdepth 1 -type d -name 'graalvm-community-*' | head -1)"
if [[ -n "$existing" && -x "$(home_of "$existing")/bin/native-image" ]]; then
  home_of "$existing"
  exit 0
fi

file="graalvm-community-jdk-${asset_version}_${platform}_bin.tar.gz"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL --retry 3 -o "$tmp/$file" "https://github.com/graalvm/graalvm-ce-builds/releases/download/$release/$file"
if command -v sha256sum >/dev/null; then actual="$(sha256sum "$tmp/$file" | cut -d' ' -f1)"; else actual="$(shasum -a 256 "$tmp/$file" | cut -d' ' -f1)"; fi
[[ "$actual" == "$expected" ]] || { echo "SHA-256 mismatch for $file: $actual" >&2; exit 1; }
tar -xzf "$tmp/$file" -C "$dest"
installed="$(find "$dest" -maxdepth 1 -type d -name 'graalvm-community-*' | head -1)"
home_of "$installed"
