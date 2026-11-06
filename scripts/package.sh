#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Packages the built native library, headers, CLI and OJ keystore for this platform:
#
#   dist/dss-native-<version>-<os>-<arch>.tar.gz (+ .sha256)
#     lib/libdssnative.{so,dylib}        bin/dss-cli, bin/dss-server (find lib/ and share/ relative to themselves)
#     include/*.h                        share/dss-native/oj-keystore.p12 (+ README)
#     LICENSE, LICENSING.md, README.md, native-library.md, SOURCE (repository + commit, for LGPL rebuilds)
#     licenses/                          third-party licences: the library's (build-native.sh), plus rust/ for the
#                                        crates in the CLI and the server (collect-rust-licenses.py)
#
# Needs scripts/build-native.sh first. Builds the CLI and the server itself, without the development rpath.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
case "$(uname -s)" in Darwin) os=macos; ext=dylib ;; Linux) os=linux; ext=so ;; *) echo "unsupported OS" >&2; exit 1 ;; esac
case "$(uname -m)" in x86_64|amd64) arch=x64 ;; arm64|aarch64) arch=aarch64 ;; *) arch="$(uname -m)" ;; esac
platform="$os-$arch"
lib="$root/build/native/$platform"
[[ -f "$lib/libdssnative.$ext" ]] || { echo "no library in $lib: run scripts/build-native.sh" >&2; exit 1; }
[[ -d "$lib/licenses" ]] || { echo "no licenses/ in $lib: run scripts/build-native.sh again" >&2; exit 1; }
(cd "$root/rust" && DSS_RELEASE_RPATH_ONLY=1 cargo build -q --release -p dss-cli -p dss-server --target-dir target/package)
cli="$root/rust/target/package/release/dss-cli"
server="$root/rust/target/package/release/dss-server"

version_file="$root/java/target/classes/it/codingduck/dssnative/version.properties"
version="$(sed -n 's/^library=//p' "$version_file")"
dss_version="$(sed -n 's/^dss=//p' "$version_file")"
graal_version="$(sed -n 's/^GRAALVM_VERSION="\(.*\)"$/\1/p' "$lib/licenses/graalvm/release")"
commit="$(git -C "$root" rev-parse HEAD 2>/dev/null || echo unknown)"
name="dss-native-$version-$platform"
out="$root/dist/$name"
rm -rf "$out" && mkdir -p "$out"/{lib,include,bin,share/dss-native}
cp "$lib/libdssnative.$ext" "$out/lib/"
cp "$lib"/*.h "$out/include/"
cp "$cli" "$server" "$out/bin/"
cp "$root/trust/oj-keystore.p12" "$root/trust/README.md" "$out/share/dss-native/"
cp "$root/LICENSE" "$root/LICENSING.md" "$root/README.md" "$root/docs/native-library.md" "$out/"
cp -R "$lib/licenses" "$out/licenses"
python3 "$root/scripts/collect-rust-licenses.py" "$out/licenses/rust"
cat > "$out/SOURCE" <<EOF
dss-native $version ($platform), commit $commit
Source and build scripts (LGPL-2.1-or-later, see LICENSING.md): $(git -C "$root" remote get-url origin 2>/dev/null || echo "this repository")
Rebuild the library against a modified DSS with scripts/build-native.sh.
DSS $dss_version source: https://github.com/esig/dss/tree/$dss_version
GraalVM Community Edition $graal_version: https://github.com/graalvm/graalvm-ce-builds/releases/tag/graal-$graal_version
  source commit of each component: licenses/graalvm/release (GraalVM's own components: https://github.com/oracle/graal)
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

# The packaged CLI and server must run from the package alone: no JVM, library found through their rpath.
"$out/bin/dss-cli" --oj-keystore "$out/share/dss-native/oj-keystore.p12" --cache-dir "$(mktemp -d)" version >/dev/null
"$out/bin/dss-server" --version >/dev/null

(cd "$root/dist" && tar -czf "$name.tar.gz" "$name")
if command -v sha256sum >/dev/null; then (cd "$root/dist" && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256");
else (cd "$root/dist" && shasum -a 256 "$name.tar.gz" > "$name.tar.gz.sha256"); fi
echo "$root/dist/$name.tar.gz"
