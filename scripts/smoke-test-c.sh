#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Smoke-tests the native library through its C API (java/src/test/c/smoke.c).
#
#   scripts/smoke-test-c.sh            offline: synthetic trusted lists from a seeded cache, no network
#   scripts/smoke-test-c.sh --online   real EU LOTL (IT only): empty cache, online refresh, refresh while validating
#
# Needs the library from scripts/build-native.sh and a C compiler. The program runs against
# build/native/<os>-<arch>/, which contains only the library and headers (no JDK/AWT side libraries).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
case "$(uname -s)" in Darwin) os=macos ;; Linux) os=linux ;; *) echo "unsupported OS" >&2; exit 1 ;; esac
case "$(uname -m)" in x86_64|amd64) arch=x64 ;; arm64|aarch64) arch=aarch64 ;; *) arch="$(uname -m)" ;; esac
lib="$root/build/native/$os-$arch"
[[ -f "$lib/libdssnative.h" ]] || { echo "no library in $lib: run scripts/build-native.sh" >&2; exit 1; }

work="$root/java/target/c-smoke"
rm -rf "$work" && mkdir -p "$work"
# The header must be self-contained: compile a file that includes it first, with nothing before it.
printf '#include "libdssnative.h"\nint main(void) { return 0; }\n' > "$work/header_first.c"
"${CC:-cc}" -std=c11 -Wall -Werror -fsyntax-only -I"$lib" "$work/header_first.c"
"${CC:-cc}" -std=c11 -O1 -Wall -Wextra -Werror -I"$lib" -o "$work/smoke" "$root/java/src/test/c/smoke.c" \
  -L"$lib" -ldssnative -lpthread -Wl,-rpath,"$lib"

fixtures="$root/testdata/fixtures"
# A JSON string with the path in it: backslashes and double quotes escaped.
json_str() { local s="${1//\\/\\\\}"; s="${s//\"/\\\"}"; printf '"%s"' "$s"; }
keystore="$(json_str "$root/trust/oj-keystore.p12")"
test_root="$(json_str "$fixtures/pki/root-ca.pem")"
if [[ "${1:-}" == "--online" ]]; then
  # tl_verify_tls: downloads must validate against the CA bundle embedded in the library at build time.
  cat > "$work/config.json" <<JSON
{"oj_keystore":{"path":$keystore},"countries":["IT"],"http":{"tl_verify_tls":true},
 "extra_trusted_certificates":[$test_root],"revocation":"offline","aia":false}
JSON
  # Run-time override: a trust store holding only the synthetic test root, so every real server must be rejected.
  "$JAVA_HOME/bin/keytool" -importcert -noprompt -storetype PKCS12 -keystore "$work/foreign-ca.p12" \
    -storepass changeit -alias test-root -file "$fixtures/pki/root-ca.pem" >/dev/null
  cat > "$work/bad-tls-config.json" <<JSON
{"oj_keystore":{"path":$keystore},"countries":["IT"],
 "http":{"tl_verify_tls":true,"trust_store":{"path":$(json_str "$work/foreign-ca.p12"),"password":"changeit"}},
 "extra_trusted_certificates":[$test_root],"revocation":"offline","aia":false}
JSON
  cache="$work/cache"
  mode=(--online "$work/bad-tls-config.json")
else
  # exec.args is split again by exec-maven-plugin, on whitespace outside quotes: the path is quoted.
  (cd "$root/java" && ./mvnw -q -B test-compile exec:java -Dexec.classpathScope=test \
    -Dexec.mainClass=it.codingduck.dssnative.testsupport.SyntheticCacheSeeder \
    -Dexec.args="\"$work/synthetic\"" -Ddssnative.repoRoot="$root")
  cp "$work/synthetic/config.json" "$work/config.json"
  cache="$work/synthetic/cache"
  mode=()
fi
cd "$work"
# ${mode[@]+...}: an empty array is "unbound" under set -u in bash 3.2 (macOS's /bin/bash).
./smoke "$cache" "$work/config.json" "$fixtures" ${mode[@]+"${mode[@]}"}
