#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Packages the built native library, headers, CLI and OJ keystore for this platform:
#
#   <out_dir>/dss-native-<version>-<os>-<arch>.tar.gz (+ .sha256)
#     lib/libdssnative.{so,dylib}        bin/dss-cli, bin/dss-server (find lib/ and share/ relative to themselves)
#     include/*.h                        share/dss-native/oj-keystore.p12 (+ README)
#     LICENSE, LICENSING.md, README.md   docs/, trust/README.md, php/, docker/: what README.md and docs/ link to,
#                                        in the repository's layout, so the links work in the package
#     SOURCE                             repository, commit and the sources of what the library contains
#     licenses/                          third-party licences: the library's (build-native.sh), plus rust/ for the
#                                        crates in the CLI and the server (collect-rust-licenses.py)
#     sbom/                              CycloneDX SBOMs: java.cdx.json (the library), rust.cdx.json (CLI, server)
#
#   scripts/package.sh [--out-dir DIR]   (default: dist/)
#
# Needs scripts/build-native.sh first. Builds the CLI and the server itself, without the development rpath and
# with Cargo.lock as committed (--locked). The tarball is reproducible from the same inputs: sorted entries, owner
# 0:0, every mtime set to the commit's time (SOURCE_DATE_EPOCH), no build-machine paths in the executables.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
dist="$root/dist"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir) mkdir -p "$2"; dist="$(cd "$2" && pwd)"; shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 64 ;;
  esac
done
case "$(uname -s)" in Darwin) os=macos; ext=dylib ;; Linux) os=linux; ext=so ;; *) echo "unsupported OS" >&2; exit 1 ;; esac
case "$(uname -m)" in x86_64|amd64) arch=x64 ;; arm64|aarch64) arch=aarch64 ;; *) arch="$(uname -m)" ;; esac
platform="$os-$arch"
lib="$root/build/native/$platform"
[[ -f "$lib/libdssnative.$ext" ]] || { echo "no library in $lib: run scripts/build-native.sh" >&2; exit 1; }
[[ -d "$lib/licenses" ]] || { echo "no licenses/ in $lib: run scripts/build-native.sh again" >&2; exit 1; }
[[ -f "$lib/sbom/java.cdx.json" ]] || { echo "no sbom/ in $lib: run scripts/build-native.sh again" >&2; exit 1; }

# Reproducibility: one timestamp for every file (the commit's, unless the caller sets one), and the build
# machine's paths mapped to fixed prefixes in the Rust executables (panic locations of dependencies).
if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
  SOURCE_DATE_EPOCH="$(git -C "$root" log -1 --format=%ct 2>/dev/null || echo 0)"
fi
export SOURCE_DATE_EPOCH
# CARGO_ENCODED_RUSTFLAGS (0x1f-separated) rather than RUSTFLAGS, so a path with spaces stays one argument.
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
remap="--remap-path-prefix=$cargo_home=/cargo"$'\x1f'"--remap-path-prefix=$root=/dss-native"
(cd "$root/rust" && DSS_RELEASE_RPATH_ONLY=1 CARGO_ENCODED_RUSTFLAGS="$remap" \
  cargo build -q --locked --release -p dss-cli -p dss-server --target-dir target/package)
cli="$root/rust/target/package/release/dss-cli"
server="$root/rust/target/package/release/dss-server"

version_file="$root/java/target/classes/it/codingduck/dssnative/version.properties"
[[ -f "$version_file" ]] || { echo "no $version_file: run scripts/build-native.sh" >&2; exit 1; }
version="$(sed -n 's/^library=//p' "$version_file")"
dss_version="$(sed -n 's/^dss=//p' "$version_file")"
[[ -n "$version" && -n "$dss_version" ]] || { echo "no library/dss version in $version_file" >&2; exit 1; }
# The GraalVM CE release the library was built with, from its own release file (vendor checked there too).
IFS=$'\t' read -r graal_vendor graal_version < <(DSS_STRICT_GRAALVM=0 CI= "$root/scripts/ci/check-graalvm.sh" "$lib/licenses/graalvm" 2>/dev/null) \
  || { echo "the library was not built with GraalVM Community Edition ($lib/licenses/graalvm/release)" >&2; exit 1; }
runtime_version="$(sed -n 's/^JAVA_RUNTIME_VERSION="\(.*\)"$/\1/p' "$lib/licenses/graalvm/release")"
graal_commit="$(sed -n 's/^SOURCE="\(.*\)"$/\1/p' "$lib/licenses/graalvm/release" | tr ' ' '\n' \
  | sed -n 's/^substratevm:\([0-9a-f]\{40\}\)$/\1/p' | head -1)"
# One canonical public URL for the source, the same as the pom's (and Cargo.toml's, the image's): not the build
# machine's git remote, which may be a fork or a private mirror.
repo_url="$(sed -n 's#^    <url>\(.*\)</url>$#\1#p' "$root/java/pom.xml" | head -1)"
[[ -n "$repo_url" ]] || { echo "no project <url> in java/pom.xml" >&2; exit 1; }
commit="$(git -C "$root" rev-parse HEAD 2>/dev/null || echo unknown)"
name="dss-native-$version-$platform"
out="$dist/$name"
rm -rf "$out" && mkdir -p "$out"/{lib,include,bin,share/dss-native,sbom}
cp "$lib/libdssnative.$ext" "$out/lib/"
cp "$lib"/*.h "$out/include/"
cp "$cli" "$server" "$out/bin/"
cp "$root/trust/oj-keystore.p12" "$root/trust/README.md" "$out/share/dss-native/"
"$root/scripts/ci/copy-package-docs.sh" "$out"
cp -R "$lib/licenses" "$out/licenses"
python3 -I "$root/scripts/collect-rust-licenses.py" "$out/licenses/rust" --sbom "$out/sbom/rust.cdx.json"
cp "$lib/sbom/java.cdx.json" "$out/sbom/"
python3 -I "$root/scripts/ci/check-md-links.py" "$out"
cat > "$out/SOURCE" <<EOF
dss-native $version ($platform), commit $commit
Source and build scripts (LGPL-2.1-or-later, see LICENSING.md): $repo_url
  tag v$version, or the commit above; the GitHub release v$version also has the source archive attached
Rebuild the library against a modified DSS with scripts/build-native.sh (LICENSING.md, "Why LGPL").

Corresponding source of what libdssnative contains, attached to the same GitHub release (scripts/ci/fetch-sources.sh):
  EU DSS $dss_version (LGPL-2.1-or-later): dss-$dss_version-source.tar.gz
    = https://github.com/esig/dss/tree/$dss_version
  $graal_vendor $graal_version runtime (GPL-2.0-only WITH Classpath-exception-2.0; SDK modules UPL-1.0):
    graal-${graal_commit:-unknown}-source.tar.gz = https://github.com/oracle/graal/tree/${graal_commit:-unknown}
    labs-openjdk-jvmci-${runtime_version##*-jvmci-}-source.tar.gz (the JDK class library, Java $runtime_version)
      = https://github.com/graalvm/labs-openjdk/tree/jvmci-${runtime_version##*-jvmci-}
    binaries: https://github.com/graalvm/graalvm-ce-builds/releases/tag/graal-$graal_version
    source commit of each component: licenses/graalvm/release
EOF

# Oldest supported OS (docs/DECISIONS.md, "Binary compatibility"): fail if a toolchain or runner change raises it.
if [[ "$os" == linux ]]; then
  floor=GLIBC_2.34
  need="$(objdump -T "$out/lib/libdssnative.so" "$out/bin/dss-cli" "$out/bin/dss-server" | grep -o 'GLIBC_[0-9.]*' | sort -Vu | tail -1)"
  [[ "$(printf '%s\n' "$need" "$floor" | sort -V | tail -1)" == "$floor" ]] || { echo "needs $need > $floor" >&2; exit 1; }
else
  floor=14.0
  need="$(otool -l "$out/lib/libdssnative.dylib" | awk '/LC_BUILD_VERSION/ { b = 1 } b && $1 == "minos" { print $2; exit }')"
  [[ "$need" == "$floor" ]] || { echo "libdssnative.dylib needs macOS $need, expected $floor" >&2; exit 1; }
fi

# The packaged CLI and server must run from the package alone (no JVM, library found through their rpath), and
# report the version the package is named after: library, CLI and server built from the same sources. `version`
# opens no cache. Without --oj-keystore the CLI must find the packaged keystore through bin/../share/dss-native/:
# these release builds (DSS_RELEASE_RPATH_ONLY=1) have no fallback to the repository's trust/oj-keystore.p12.
reported="$(env -u DSS_OJ_KEYSTORE "$out/bin/dss-cli" version)"
expect_line() {
  local line
  for line in "$@"; do grep -qxF "$line" <<<"$reported" && return 0; done
  printf 'the packaged dss-cli does not report "%s":\n%s\n' "$1" "$reported" >&2
  exit 1
}
expect_line "dss-cli $version"
expect_line "libdssnative $version"
expect_line "EU DSS $dss_version"
# The executable's path as the OS reports it: as invoked (macOS) or with symbolic links resolved (Linux).
expect_line "OJ keystore: $out/bin/../share/dss-native/oj-keystore.p12" \
  "OJ keystore: $(cd -P "$out" && pwd)/bin/../share/dss-native/oj-keystore.p12"
server_version="$("$out/bin/dss-server" --version)"
[[ "$server_version" == "dss-server $version" ]] \
  || { echo "the packaged dss-server reports \"$server_version\", expected \"dss-server $version\"" >&2; exit 1; }

"$root/scripts/ci/deterministic-tar.sh" "$dist" "$name" "$dist/$name.tar.gz"
if command -v sha256sum >/dev/null; then (cd "$dist" && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256");
else (cd "$dist" && shasum -a 256 "$name.tar.gz" > "$name.tar.gz.sha256"); fi
echo "$dist/$name.tar.gz"
