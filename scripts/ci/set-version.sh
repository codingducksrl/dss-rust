#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Stamps a version into java/pom.xml (the project version) and rust/Cargo.toml (the workspace version). From
# there it reaches the library (dss_version), the crates, dss-cli and the package names.
#
#   scripts/ci/set-version.sh <version>
#
# CI runs it on release builds with the version from the release tag (v1.2.3 -> 1.2.3). The committed files keep
# the 0.0.0-dev placeholder: nothing else holds a version.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
version="${1:?usage: set-version.sh <version>}"
# A semantic version, as Cargo requires; Maven accepts it too.
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
  echo "not a semantic version (like 1.2.0 or 1.2.0-rc.1): $version" >&2
  exit 1
fi
pom="$root/java/pom.xml"
cargo="$root/rust/Cargo.toml"
# The project's own <version> is the pom's only one indented by four spaces. In the workspace manifest the version
# lives in [workspace.package].
[[ "$(grep -c '^    <version>' "$pom")" == 1 ]] || { echo "expected exactly one project <version> in $pom" >&2; exit 1; }
sed -i.bak -E "s#^    <version>[^<]*</version>\$#    <version>$version</version>#" "$pom"
sed -i.bak -E "/^\[workspace\.package\]/,/^\[/ s#^version = \"[^\"]*\"#version = \"$version\"#" "$cargo"
rm -f "$pom.bak" "$cargo.bak"
grep -q "^    <version>$version</version>\$" "$pom" || { echo "could not set the version in $pom" >&2; exit 1; }
grep -q "^version = \"$version\"\$" "$cargo" || { echo "could not set the version in $cargo" >&2; exit 1; }
echo "version $version"
