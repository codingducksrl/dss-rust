#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Coding Duck
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Regression tests for the build, CI and packaging scripts that can run without a native build, a JDK or the
# network: version stamping, the GraalVM installer's trust in its cache, the CI setup step's exit status, the
# licence collector's output-directory guard, Markdown links (also in the package's layout), reproducible
# tarballs, the seed-cache health gate, the toolchain check, source archive URLs, the fixture generator's JVM and
# the repository rules (the licence texts in LICENSES/ included).
#
#   scripts/ci/test-scripts.sh
#
# CI runs it on every push and pull request (.github/workflows/checks.yml). Exit status 1 if any test fails.
set -uo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
failures=0
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1" >&2; failures=$((failures + 1)); }
check() { local name="$1"; shift; if "$@"; then pass "$name"; else fail "$name"; fi; }

# --- set-version.sh: semver.org versions only, and Cargo.lock stamped with the manifests
copy="$tmp/sv"
mkdir -p "$copy/scripts/ci" "$copy/java" "$copy/rust"
cp "$root/scripts/ci/set-version.sh" "$copy/scripts/ci/"
for v in 01.2.3 1.02.3 1.2.03 1.2.3-rc..1 1.2.3- 1.2.3-01 1.2.3+ 1.2 v1.2.3 1.2.3-rc.1+; do
  cp "$root/java/pom.xml" "$copy/java/"; cp "$root/rust/Cargo.toml" "$root/rust/Cargo.lock" "$copy/rust/"
  check "set-version rejects $v" bash -c '! "$1" "$2" >/dev/null 2>&1' _ "$copy/scripts/ci/set-version.sh" "$v"
done
for v in 1.2.3 0.0.0-dev 1.2.3-rc.1 1.2.3-0.alpha.10 1.2.3+build.5 1.2.3-x-y.7+sha.1f2e; do
  cp "$root/java/pom.xml" "$copy/java/"; cp "$root/rust/Cargo.toml" "$root/rust/Cargo.lock" "$copy/rust/"
  check "set-version accepts $v" bash -c '"$1" "$2" >/dev/null 2>&1' _ "$copy/scripts/ci/set-version.sh" "$v"
done
cp "$root/java/pom.xml" "$copy/java/"; cp "$root/rust/Cargo.toml" "$root/rust/Cargo.lock" "$copy/rust/"
"$copy/scripts/ci/set-version.sh" 7.8.9 >/dev/null
members="$(sed -n '/^members/s/[^"]*"\([^"]*\)"[^"]*/\1 /gp' "$root/rust/Cargo.toml")"
stamped="$(awk '/^\[\[package\]\]/{p=1} p && /^version = "7.8.9"$/{n++} END{print n+0}' "$copy/rust/Cargo.lock")"
check "set-version stamps every workspace member in Cargo.lock" test "$stamped" -eq "$(echo $members | wc -w)"
check "set-version keeps the lock file format version" grep -qx 'version = 4' "$copy/rust/Cargo.lock"
check "set-version leaves third-party crates alone" \
  test "$(diff "$root/rust/Cargo.lock" "$copy/rust/Cargo.lock" | grep -c '^>')" -eq "$(echo $members | wc -w)"

# --- install-graalvm.sh: neither an unverified install nor a tampered tarball in the cache is used
stubs="$tmp/stubs"
mkdir -p "$stubs"
printf '#!/bin/sh\necho "curl stub: no network in this test" >&2\nexit 22\n' > "$stubs/curl"
chmod +x "$stubs/curl"
dest="$tmp/graalvm"
fake="$dest/graalvm-community-openjdk-99.9.9+0.0"
mkdir -p "$fake/bin" "$fake/Contents/Home/bin"
printf '#!/bin/sh\nexit 0\n' > "$fake/bin/native-image"; cp "$fake/bin/native-image" "$fake/Contents/Home/bin/"
chmod +x "$fake/bin/native-image" "$fake/Contents/Home/bin/native-image"
out="$(PATH="$stubs:$PATH" "$root/scripts/ci/install-graalvm.sh" "$dest" 2>/dev/null)"; status=$?
check "install-graalvm does not trust an existing graalvm-community-* folder" test "$status" -ne 0 -a -z "$out"
mkdir -p "$dest/download"
release="$(sed -n 's/^release="\(.*\)"$/\1/p' "$root/scripts/ci/install-graalvm.sh")"
asset="$(sed -n 's/^asset_version="\(.*\)"$/\1/p' "$root/scripts/ci/install-graalvm.sh")"
for p in linux-x64 linux-aarch64 macos-aarch64; do
  echo tampered > "$dest/download/graalvm-community-jdk-${asset}_${p}_bin.tar.gz"
done
out="$(PATH="$stubs:$PATH" "$root/scripts/ci/install-graalvm.sh" "$dest" 2>/dev/null)"; status=$?
check "install-graalvm refuses a cached tarball with the wrong SHA-256" test "$status" -ne 0 -a -z "$out"
check "install-graalvm deletes the tampered tarball" test -z "$(find "$dest/download" -name '*.tar.gz' -size -1k)"
check "install-graalvm's cache key hashes the script" \
  grep -q "hashFiles('scripts/ci/install-graalvm.sh')" "$root/.github/actions/setup/action.yml"
check "install-graalvm pins the release java/pom.xml compiles against" \
  grep -q "<graalvm.sdk.version>${release#graal-}</graalvm.sdk.version>" "$root/java/pom.xml"

# --- the setup action's install step fails when the installer fails (no empty JAVA_HOME)
step="$(awk '/- name: Install GraalVM CE/{f=1; next} f && /run: \|/{r=1; next} r && /^    - name:/{exit} r && NF{sub(/^        /, ""); print}' \
  "$root/.github/actions/setup/action.yml")"
mkdir -p "$tmp/action/scripts/ci"
printf '#!/bin/sh\necho "SHA-256 mismatch" >&2\nexit 1\n' > "$tmp/action/scripts/ci/install-graalvm.sh"
chmod +x "$tmp/action/scripts/ci/install-graalvm.sh"
: > "$tmp/action/env"
(cd "$tmp/action" && GITHUB_ENV="$tmp/action/env" HOME="$tmp/action" bash --noprofile --norc -eo pipefail -c "$step" >/dev/null 2>&1)
status=$?
check "setup action: a failing installer fails the step" test "$status" -ne 0
check "setup action: no JAVA_HOME written after a failure" bash -c '! grep -q JAVA_HOME "$1"' _ "$tmp/action/env"

# --- collect-rust-licenses.py: never empties a directory it was not given empty
mkdir -p "$tmp/licenses/keep"; echo work > "$tmp/licenses/keep/work.txt"
python3 -I "$root/scripts/collect-rust-licenses.py" "$tmp/licenses" >/dev/null 2>&1; status=$?
check "collect-rust-licenses refuses a non-empty directory" test "$status" -ne 0 -a -f "$tmp/licenses/keep/work.txt"
for d in "$root" "$root/rust" "$root/dist" /; do
  python3 -I "$root/scripts/collect-rust-licenses.py" "$d" --force >/dev/null 2>&1; status=$?
  check "collect-rust-licenses refuses $d even with --force" test "$status" -ne 0
done

# --- collect-native-licenses.sh: fresh licences/ every time, the right extra notices, one folder per artifact
nt="$tmp/native-target"; nh="$tmp/native-home"; nout="$tmp/native-out"
for a in stax2-api-4.2.1 woodstox-core-6.5.1 httpclient5-5.6.5 commons-io-2.22.0; do
  mkdir -p "$nt/third-party-licenses/$a/META-INF"; echo "$a licence" > "$nt/third-party-licenses/$a/META-INF/LICENSE"
done
echo '{"bomFormat":"CycloneDX"}' > "$nt/dss-native.cdx.json"
mkdir -p "$nh/legal/java.base"; echo gpl > "$nh/LICENSE.txt"; echo tp > "$nh/THIRD_PARTY_LICENSE.txt"
echo 'IMPLEMENTOR="GraalVM Community"' > "$nh/release"; echo n > "$nh/legal/java.base/x.md"
mkdir -p "$nout/licenses/java/commons-io-2.21.0"
"$root/scripts/ci/collect-native-licenses.sh" "$nt" "$nout" "$nh" >/dev/null 2>&1; status=$?
check "collect-native-licenses succeeds" test "$status" -eq 0
check "collect-native-licenses drops an earlier build's folders" test ! -e "$nout/licenses/java/commons-io-2.21.0"
check "collect-native-licenses adds the Woodstox notice" cmp -s "$root/third-party/woodstox.txt" "$nout/licenses/java/woodstox-core-6.5.1/woodstox.txt"
check "collect-native-licenses adds the Public Suffix List notice" test -f "$nout/licenses/java/httpclient5-5.6.5/public-suffix-list.txt"
check "collect-native-licenses adds the W3C notice" test -f "$nout/licenses/xmldsig-core-schema.txt"
check "collect-native-licenses adds the GraalVM SDK's UPL" test -f "$nout/licenses/graalvm/graalvm-sdk.txt"
check "collect-native-licenses ships the SBOM" test -f "$nout/sbom/java.cdx.json"
mkdir -p "$nt/third-party-licenses/stax2-api-4.2.2/META-INF"; echo new > "$nt/third-party-licenses/stax2-api-4.2.2/META-INF/LICENSE"
"$root/scripts/ci/collect-native-licenses.sh" "$nt" "$nout" "$nh" >/dev/null 2>&1; status=$?
check "collect-native-licenses refuses two versions of one artifact" test "$status" -ne 0

# --- check-md-links.py
mkdir -p "$tmp/md/docs"
printf '[a](docs/x.md) [b](https://example.com) [c](#top) `[d](missing.md)`\n' > "$tmp/md/README.md"
printf '[back](../README.md#api)\n' > "$tmp/md/docs/x.md"
check "check-md-links accepts working links" python3 -I "$root/scripts/ci/check-md-links.py" "$tmp/md"
printf '[gone](docs/native-library.md)\n' >> "$tmp/md/README.md"
check "check-md-links finds a broken link" bash -c '! python3 -I "$1" "$2" 2>/dev/null' _ "$root/scripts/ci/check-md-links.py" "$tmp/md"
# The documentation as scripts/package.sh ships it: every relative link must resolve inside the package.
"$root/scripts/ci/copy-package-docs.sh" "$tmp/package-docs"; status=$?
check "copy-package-docs succeeds" test "$status" -eq 0
check "no broken link in the package's documentation" python3 -I "$root/scripts/ci/check-md-links.py" "$tmp/package-docs"
check "package.sh ships the documentation with copy-package-docs.sh" grep -q 'scripts/ci/copy-package-docs.sh" "$out"' "$root/scripts/package.sh"

# --- deterministic-tar.sh: same files, different mtimes and permissions -> same bytes
for side in a b; do
  mkdir -p "$tmp/tar-$side/pkg/sub"; echo one > "$tmp/tar-$side/pkg/sub/f"; echo two > "$tmp/tar-$side/pkg/g"
done
chmod 600 "$tmp/tar-b/pkg/g"; touch -t 202001010000 "$tmp/tar-b/pkg/sub/f"
SOURCE_DATE_EPOCH=1700000000 "$root/scripts/ci/deterministic-tar.sh" "$tmp/tar-a" pkg "$tmp/a.tar.gz"
sleep 1
SOURCE_DATE_EPOCH=1700000000 "$root/scripts/ci/deterministic-tar.sh" "$tmp/tar-b" pkg "$tmp/b.tar.gz"
check "deterministic-tar gives identical archives" cmp -s "$tmp/a.tar.gz" "$tmp/b.tar.gz"
check "deterministic-tar records owner 0:0, no names, one mtime" python3 -I -c '
import sys, tarfile
members = tarfile.open(sys.argv[1]).getmembers()
sys.exit(not all(m.uid == 0 and m.gid == 0 and not m.uname and not m.gname and m.mtime == 1700000000 for m in members))
' "$tmp/a.tar.gz"

# --- check-tl-status.py
tl() { printf '{"url":"https://tl/%s","territory":"%s","expired":%s,"used_for_trust":true,"download":{"error":%s},"validation":{"indication":"%s"}}' "$@"; }
good="$(tl IT IT false null TOTAL_PASSED)"
lotl="$(tl EU EU false null TOTAL_PASSED)"
printf '{"loaded":true,"trusted_certificates":9,"lotls":[%s],"tls":[%s],"alerts":[]}' "$lotl" "$good" > "$tmp/ok.json"
printf '{"loaded":true,"trusted_certificates":9,"lotls":[%s],"tls":[%s,%s],"alerts":[]}' "$lotl" "$good" \
  "$(tl FR FR false '"404"' INDETERMINATE)" > "$tmp/download.json"
printf '{"loaded":true,"trusted_certificates":9,"lotls":[%s],"tls":[%s,%s],"alerts":[]}' "$lotl" "$good" \
  "$(tl DE DE true null TOTAL_PASSED)" > "$tmp/expired.json"
printf '{"loaded":false,"trusted_certificates":0,"lotls":[],"tls":[],"alerts":[]}' > "$tmp/empty.json"
check "check-tl-status accepts healthy lists" python3 -I "$root/scripts/ci/check-tl-status.py" "$tmp/ok.json"
for bad in download expired empty; do
  check "check-tl-status rejects $bad" bash -c '! python3 -I "$1" "$2" >/dev/null 2>&1' _ "$root/scripts/ci/check-tl-status.py" "$tmp/$bad.json"
done
check "check-tl-status --max-problems 1 tolerates one" \
  python3 -I "$root/scripts/ci/check-tl-status.py" "$tmp/expired.json" --max-problems 1

# --- check-graalvm.sh
pinned="$(sed -n 's#^ *<graalvm.sdk.version>\(.*\)</graalvm.sdk.version>#\1#p' "$root/java/pom.xml")"
jdk() { mkdir -p "$tmp/jdk-$1"; printf 'IMPLEMENTOR="%s"\nGRAALVM_VERSION="%s"\n' "$2" "$3" > "$tmp/jdk-$1/release"; echo "$tmp/jdk-$1"; }
check "check-graalvm accepts the pinned CE" env -u CI "$root/scripts/ci/check-graalvm.sh" "$(jdk ce "GraalVM Community" "$pinned")"
check "check-graalvm refuses Oracle GraalVM" \
  bash -c '! "$1" "$2" 2>/dev/null' _ "$root/scripts/ci/check-graalvm.sh" "$(jdk oracle "Oracle Corporation" "$pinned")"
check "check-graalvm refuses a JDK that is not GraalVM" \
  bash -c '! "$1" "$2" 2>/dev/null' _ "$root/scripts/ci/check-graalvm.sh" "$(jdk other "Eclipse Adoptium" "")"
old_ce="$(jdk old "GraalVM Community" "1.0.0.0.0")"
check "check-graalvm warns about another CE release locally" env -u CI DSS_STRICT_GRAALVM= "$root/scripts/ci/check-graalvm.sh" "$old_ce"
check "check-graalvm refuses another CE release in CI" \
  bash -c '! CI=true "$1" "$2" 2>/dev/null' _ "$root/scripts/ci/check-graalvm.sh" "$old_ce"

# --- fetch-sources.sh --print-urls
printf 'IMPLEMENTOR="GraalVM Community"\nJAVA_RUNTIME_VERSION="25.0.5.0.3+1-jvmci-25.5-b26"\nSOURCE=".:git:abc labsjdk-builder:%s compiler:%s substratevm:%s"\n' \
  "$(printf 'a%.0s' {1..40})" "$(printf 'b%.0s' {1..40})" "$(printf 'c%.0s' {1..40})" > "$tmp/release"
urls="$("$root/scripts/ci/fetch-sources.sh" "$tmp/release" "$tmp/src" --print-urls)"
dss="$(sed -n 's#^ *<dss.version>\(.*\)</dss.version>#\1#p' "$root/java/pom.xml")"
check "fetch-sources names the DSS tag" grep -qx "dss-$dss-source.tar.gz https://github.com/esig/dss/archive/refs/tags/$dss.tar.gz" <<<"$urls"
check "fetch-sources names the Substrate VM commit" grep -q "oracle/graal/archive/$(printf 'c%.0s' {1..40}).tar.gz" <<<"$urls"
check "fetch-sources names the labs-openjdk jvmci tag" grep -q "labs-openjdk/archive/refs/tags/jvmci-25.5-b26.tar.gz" <<<"$urls"

# --- generate-fixtures.sh: the generator runs in its own JVM with the flags that make it reproducible
gf="$tmp/gen fixtures"
mkdir -p "$gf/scripts" "$gf/java" "$gf/caller dir"
cp "$root/scripts/generate-fixtures.sh" "$gf/scripts/"
printf '#!/bin/sh\nfor a in "$@"; do printf "%%s\\n" "$a"; done > "$(dirname "$0")/mvnw.args"\n' > "$gf/java/mvnw"
chmod +x "$gf/java/mvnw"
(cd "$gf/caller dir" && JAVA_HOME="/opt/jdk" "$gf/scripts/generate-fixtures.sh" --out=check --time=2027-01-01T00:00:00Z \
  >/dev/null 2>&1); status=$?
gf_args="$(sed -n 's/^-Dexec\.args=//p' "$gf/java/mvnw.args" 2>/dev/null)"
check "generate-fixtures succeeds with a stub Maven" test "$status" -eq 0
check "generate-fixtures uses exec:exec, not Maven's own JVM" grep -qx 'exec:exec' "$gf/java/mvnw.args"
check "generate-fixtures puts the test classpath on the command line" grep -qx -- '-Dexec.classpathScope=test' "$gf/java/mvnw.args"
check "generate-fixtures runs \$JAVA_HOME/bin/java" grep -qx -- '-Dexec.executable=/opt/jdk/bin/java' "$gf/java/mvnw.args"
check "generate-fixtures starts the JVM with FixtureGenerator.JVM_OPTIONS" \
  grep -q -- '^-XX:+UnlockExperimentalVMOptions -XX:hashCode=2 ' <<<"$gf_args"
check "the flags in generate-fixtures match FixtureGenerator.JVM_OPTIONS" grep -q \
  'JVM_OPTIONS = List.of("-XX:+UnlockExperimentalVMOptions", "-XX:hashCode=2")' \
  "$root/java/src/test/java/it/codingduck/dssnative/testsupport/FixtureGenerator.java"
check "generate-fixtures runs FixtureGenerator with the repository root" grep -qF -- \
  "-Ddssnative.repoRoot=\"$gf\" -classpath %classpath it.codingduck.dssnative.testsupport.FixtureGenerator " <<<"$gf_args"
check "generate-fixtures resolves a relative --out against the caller's directory" \
  grep -qF "FixtureGenerator \"--out=$gf/caller dir/check\" \"--time=2027-01-01T00:00:00Z\"" <<<"$gf_args"
(cd "$gf/caller dir" && "$gf/scripts/generate-fixtures.sh" '--out=a"b' >/dev/null 2>&1); status=$?
check "generate-fixtures refuses an argument exec.args cannot quote" test "$status" -eq 2

# --- the native OCSP/CRL/AIA path: covered by RevocationLoopbackTest in the native JUnit image, not by smoke.c
rlt="$root/java/src/test/java/it/codingduck/dssnative/engine/RevocationLoopbackTest.java"
check "RevocationLoopbackTest exists" test -f "$rlt"
check "RevocationLoopbackTest also runs in the native test image" \
  bash -c '! grep -qE "@(DisabledInNativeImage|EnabledInNativeImage)" "$1"' _ "$rlt"
check "CI runs the native test image with missing registrations fatal" \
  grep -q 'scripts/run-native-tests.sh -XX:MissingRegistrationReportingMode=Exit' "$root/.github/workflows/ci.yml"

# --- repository rules and ignores
check "check-repo passes" python3 -I "$root/scripts/ci/check-repo.py"
# LICENSES/ in a throw-away repository: exactly the licences the headers and REUSE.toml use. The fake headers are
# not this file's licence: `reuse lint` skips them between the markers.
# REUSE-IgnoreStart
cr="$tmp/check-repo"
mkdir -p "$cr/scripts/ci" "$cr/java" "$cr/LICENSES"
cp "$root/scripts/ci/check-repo.py" "$cr/scripts/ci/"
printf '# SPDX-License-Identifier: LGPL-2.1-or-later\nrelease="graal-1.2.3"\n' > "$cr/scripts/ci/install-graalvm.sh"
printf '<!-- SPDX-License-Identifier: LGPL-2.1-or-later -->\n<graalvm.sdk.version>1.2.3</graalvm.sdk.version>\n' > "$cr/java/pom.xml"
printf '/* SPDX-License-Identifier: (MPL-2.0 OR BSD-2-Clause) */\n' > "$cr/dual.c"
printf 'data\n' > "$cr/font.dat"
printf '# SPDX-License-Identifier: LGPL-2.1-or-later\nversion = 1\n[[annotations]]\npath = "font.dat"\nSPDX-FileCopyrightText = "x"\nSPDX-License-Identifier = "OFL-1.1"\n' > "$cr/REUSE.toml"
printf 'lgpl\n' > "$cr/LICENSE"
cp "$cr/LICENSE" "$cr/LICENSES/LGPL-2.1-or-later.txt"
for id in MPL-2.0 BSD-2-Clause OFL-1.1; do echo "$id" > "$cr/LICENSES/$id.txt"; done
git -C "$cr" init -q && git -C "$cr" add -A
check "check-repo accepts a complete LICENSES/" python3 -I "$cr/scripts/ci/check-repo.py"
rm "$cr/LICENSES/OFL-1.1.txt"
check "check-repo wants the text of a licence REUSE.toml uses" \
  bash -c 'python3 -I "$1" 2>&1 | grep -q "LICENSES/OFL-1.1.txt: missing"' _ "$cr/scripts/ci/check-repo.py"
check "check-repo fails without it" bash -c '! python3 -I "$1" >/dev/null 2>&1' _ "$cr/scripts/ci/check-repo.py"
echo OFL-1.1 > "$cr/LICENSES/OFL-1.1.txt"; rm "$cr/LICENSES/BSD-2-Clause.txt"
check "check-repo wants each licence of an expression" \
  bash -c 'python3 -I "$1" 2>&1 | grep -q "LICENSES/BSD-2-Clause.txt: missing"' _ "$cr/scripts/ci/check-repo.py"
echo BSD > "$cr/LICENSES/BSD-2-Clause.txt"; echo MIT > "$cr/LICENSES/MIT.txt"
check "check-repo refuses an unused licence text" \
  bash -c 'python3 -I "$1" 2>&1 | grep -q "LICENSES/MIT.txt: no file uses"' _ "$cr/scripts/ci/check-repo.py"
rm "$cr/LICENSES/MIT.txt"; echo changed > "$cr/LICENSES/LGPL-2.1-or-later.txt"
check "check-repo wants LICENSES/LGPL-2.1-or-later.txt to be LICENSE" \
  bash -c 'python3 -I "$1" 2>&1 | grep -q "byte-for-byte copy of LICENSE"' _ "$cr/scripts/ci/check-repo.py"
# REUSE-IgnoreEnd
cmp -s "$root/LICENSE" "$root/LICENSES/LGPL-2.1-or-later.txt" || fail "LICENSES/LGPL-2.1-or-later.txt is not LICENSE"
check ".gitignore covers dss-server's default cache" git -C "$root" check-ignore -q dss-cache/tl/x.xml

if [[ $failures -gt 0 ]]; then
  echo "$failures test(s) failed" >&2
  exit 1
fi
echo "all script tests passed"
