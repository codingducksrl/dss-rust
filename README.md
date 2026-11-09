# dss-native

The [EU Digital Signature Service (DSS)](https://github.com/esig/dss) validation engine for native applications.
A thin Java wrapper around DSS is compiled with GraalVM Native Image (Community Edition) into a shared library
with a C API, plus Rust crates on top. No JVM is needed at runtime.

dss-native is an independent project by Coding Duck. It is not affiliated with, endorsed by or supported by the
European Commission or the DSS project; it uses DSS, unmodified, under DSS's licence.

- Validates **CAdES** (`.p7m`, `.p7s`, Italian `.p7m.p7m`, BER, base64) and **PAdES** signatures and returns DSS's
  own reports.
- **Extends PAdES** signatures to BASELINE-T, -LT or -LTA, e.g. a PAdES-T to PAdES-LT by embedding the
  certificates and revocation data it needs.
- **Signs with a key held elsewhere** (a remote signing service, an HSM), as CAdES or PAdES, BASELINE-B to -LTA.
  DSS builds the document; the external signer only sees a digest and returns a CMS or a bare signature value.
- Owns the **EU trusted lists** (LOTL + national TLs): loads them from an on-disk cache at startup (offline),
  refreshes them online when the host asks, and reports their status. It can also export them as a
  **trusted-list snapshot**, from which another engine starts in a fraction of a second.
- Runs as an **HTTP sidecar** (`dss-server`) for applications in other languages, with a Laravel client.

> **Status:** all six phases of the initial plan are done:
> - the engine runs on the JVM and as a native image;
> - it is built as a shared library with a C API;
> - Rust crates (`dss-sys`, `dss`, `dss-cli`, `dss-server`) wrap it;
> - a differential test checks the native path against plain DSS on the JVM;
> - GitHub Actions builds, tests and packages it for linux-x64, linux-aarch64 and macos-aarch64.
>
> Decisions and versions: [`docs/DECISIONS.md`](docs/DECISIONS.md). Licensing: [`LICENSING.md`](LICENSING.md).
> Changes to the contract: `CHANGELOG.md`; reporting a vulnerability: `SECURITY.md`; contributing:
> `CONTRIBUTING.md` (all three in the repository).

### Not supported

- **Formats:** XAdES, JAdES and ASiC containers are neither validated nor signed; an XML, JSON or ZIP document is
  `UNSUPPORTED_DOCUMENT`. Only PDF (PAdES) and CMS (CAdES) are.
- **Extension** takes PDFs only: a CAdES signature reaches T, LT or LTA when it is signed, not afterwards. A PDF
  whose only "signature" is a document timestamp cannot be extended or renewed (DSS: "No signatures found to be
  extended!"); there is no timestamp-only operation.
- **Signing:** no co-signatures or counter-signatures of CMS (a `.p7m` given to CAdES becomes a `.p7m.p7m`), no
  RSASSA-PSS signature values, no XAdES/JAdES/ASiC.
- **Validation policy:** DSS's default `constraint.xml` only; no custom policy, and a signature policy a document
  names is never downloaded.
- **Encrypted PDFs** that need a user password to open (owner-password-only PDFs are fine). There is no password
  option.
- **Visible signatures:** no preview rendering, no CMYK JPEG, no interlaced PNG, no right-to-left or
  complex-script text shaping, no PDF/A conformance check of the result.
- **Platforms:** linux-x64, linux-aarch64 (glibc 2.34+) and macos-aarch64 (macOS 14+). No Windows, no macOS x64,
  no musl.
- **`dss-server`** has no trusted-list snapshot export: make snapshots with `dss-cli tl snapshot` or
  `dss_tl_export_snapshot`, and start the server from one with `--tl-snapshot`.

## Layout

```
java/        Maven project: engine/ (pure Java), visible/ (visible signature appearance, AWT-free),
             ffi/ (DssLib: the C entry points), nativeimage/ (DssFeature), src/test/c/ (C smoke test)
rust/        Cargo workspace: dss-sys (bindgen), dss (safe Engine, tokio scheduler), dss-cli (demo),
             dss-server (HTTP sidecar)
php/         DssClient.php, DssException.php: Laravel client for dss-server
docker/      dss-server/Dockerfile: the sidecar's image, from a Linux release package
testdata/    fixtures/ (synthetic, committed) and private/ (your real documents, gitignored)
trust/       OJ keystore with the LOTL signing certificates
third-party/ notices of components compiled into the library (DSS, PT Serif, Stax2 API, Woodstox, …), shipped
             in packages
scripts/     build-native.sh, smoke-test-c.sh, test-rust.sh, diff-vs-jvm.sh, package.sh, collect-rust-licenses.py,
             generate-fixtures.sh, seed-tl-cache.sh, run-agent.sh, agent/caller-filter.json, merge-metadata.py,
             run-native-tests.sh, audit-reflection.sh; ci/: install-graalvm.sh, set-version.sh, check-*.py/.sh,
             fetch-sources.sh, deterministic-tar.sh, package-smoke.sh, docker-smoke.sh, test-scripts.sh, …
docs/        DECISIONS.md, native-library.md, server.md, openapi.yaml, reflection-audit.md
.github/     workflows/ci.yml (release), checks.yml (push/PR), security.yml (weekly), dependabot.yml,
             actions/setup (GraalVM CE, Rust, libclang, caches)
REUSE.toml   licensing of the files that cannot carry an SPDX header
LICENSES/    the text of every licence used in the repository (REUSE)
build/       native/<os>-<arch>/: the built library and headers; diff/: differential test reports (not committed)
dist/        release packages written by scripts/package.sh (not committed)
```

## Building and testing (JVM)

Requires JDK 21+. GraalVM CE 25 is what the project pins: see `docs/DECISIONS.md`.

```bash
cd java && ./mvnw test
```

That runs the unit suite: no network, everything served in memory. Tests that hit the real EU LOTL are tagged
`online` and run only with the `integration` profile, which runs nothing else:

```bash
cd java && ./mvnw test -Pintegration
```

Native: requires GraalVM CE 25 as `JAVA_HOME`. This runs the same suite as a native executable, built with
`--exact-reachability-metadata`:

```bash
cd java && ./mvnw -Pnative test
```

Re-run the built native tests with a different reporting mode or locale, without rebuilding:

```bash
scripts/run-native-tests.sh -XX:MissingRegistrationReportingMode=Exit
```

Refresh the reachability metadata after changing code or dependencies (see
[`docs/reflection-audit.md`](docs/reflection-audit.md)):

```bash
scripts/run-agent.sh
```

```bash
python3 -I scripts/merge-metadata.py
```

Build the shared library into `build/native/<os>-<arch>/` and smoke-test it from C. `build-native.sh` skips the
test suites unless given `--with-tests`, and refuses a `JAVA_HOME` that is not GraalVM CE. Add `--online` to the
smoke test to run it against the real EU LOTL:

```bash
scripts/build-native.sh
```

```bash
scripts/smoke-test-c.sh
```

### Rust

Needs the native library (above) and libclang for bindgen. `dss-sys` finds the library in
`build/native/<os>-<arch>/`, or in the directory `DSS_NATIVE_LIB_DIR` names, which must hold the library and its
headers (`libdssnative.h`, `graal_isolate.h`) side by side. A release package keeps them in `lib/` and
`include/`: copy the headers next to the library, or point the variable at a directory with both. Applications
set their own rpath (or `LD_LIBRARY_PATH`/`DYLD_LIBRARY_PATH`) to find the library at run time.

```bash
cd rust && cargo test --workspace --all-features
```

`scripts/test-rust.sh` also runs the tests that need a seeded synthetic TL cache; add `--online` for the real
EU LOTL. The demo CLI:

```bash
cd rust && cargo build --release -p dss-cli
```

```bash
rust/target/release/dss-cli tl refresh
```

```bash
rust/target/release/dss-cli validate contract.pdf.p7m --report detailed --out-dir reports/
```

```bash
rust/target/release/dss-cli extend signed-t.pdf --level lt -o signed-lt.pdf
```

Signing in two steps, with the external signer in between (`--cert signer.pem` is needed with
`--mode signature-value`):

```bash
rust/target/release/dss-cli sign prepare contract.pdf --mode cms --level lt --request request.json
```

```bash
rust/target/release/dss-cli sign complete contract.pdf --request request.json --signature signer-output.p7s -o contract-signed.pdf
```

`extend --level t|lta` needs a TSA, and so does `extend --level lt` for a signature that has no timestamp yet
(B level); `sign` at T, LT and LTA needs one unless the signer's CMS carries a signature timestamp:
`--tsa-url <url>`, and `--tsa-user <name>` (only with `--tsa-url`) if it asks for HTTP Basic credentials, with
the password in the file `--tsa-password-file` (or `DSS_TSA_PASSWORD_FILE`; needs `--tsa-user`, trailing whitespace
ignored) names, else in `DSS_TSA_PASSWORD`. These pairs are checked after parsing, so a flag and the other's
`DSS_*` variable combine freely (`DSS_TSA_USER` with `--tsa-url`). An empty `DSS_*` variable counts as unset, as
in `dss-server`. A TSA (or TL mirror, CRL or OCSP responder) on a loopback or private address is refused by the
outbound policy unless a `--config` file sets `"http": {"block_private_addresses": false}`: `dss-cli` has no flag
for it (`dss-server` has `--allow-private-addresses`).

A trusted-list snapshot of what the cache holds, then any command started from it instead of the cache (see
"Trusted-list snapshots" below):

```bash
rust/target/release/dss-cli --country IT tl snapshot -o it.tlsnap
```

```bash
rust/target/release/dss-cli --country IT --tl-snapshot it.tlsnap validate contract.pdf.p7m
```

`tl status` prints what is loaded, from the cache and without network. `--country IT` limits the lists.
`--cache-dir` (or `DSS_CACHE_DIR`) defaults to `dss-native` in the user cache directory (`$XDG_CACHE_HOME` or
`~/.cache`, `~/Library/Caches` on macOS), never to the current directory. The OJ keystore, the root of trust of
the trusted lists, comes from `--oj-keystore`/`DSS_OJ_KEYSTORE`, else `oj-keystore.p12` next to the executable or
in `../share/dss-native/` relative to it (the package layout). A development build of the repository also falls
back to the repository's `trust/oj-keystore.p12` by absolute path. The current directory is never searched.
`dss-server` finds its keystore and cache the same way and logs both at start-up ([`docs/server.md`](docs/server.md)).
`dss-cli version` and `tl status` print the keystore in use; `tl status` adds its SHA-256 once the library reports
`oj_keystore`, lists each LOTL's pivots under it, shows per list the sequence number published for it (`published
<n>`, the rollback floor), and for a `tl_rollback` alert the refused and published sequence numbers and issue
dates; that line reads `OJ keystore: <path> (sha256 <hex>)`, the digest a trusted-list snapshot records as
`oj_keystore_sha256`. `dss-cli version` asks the library through `dss::library_version()`, without an engine, and
prints the keystore path only; after the runtime line it prints `API version <n> (dss-cli expects <n>)`, or `API
version not reported (…)` with a library that predates the field.

`--config <file>` takes a full `config_json`. It cannot be combined with the flags it replaces (`--tl-snapshot`,
`--oj-keystore`, `--country`, `--offline-revocation`, `--trust`, `--allow-without-trusted-lists`, `--tsa-url`,
`--tsa-user`, `--tsa-password-file`, `--tl-threads`) or their `DSS_*` variables, wherever the flag is placed
(also after the subcommand): that is a usage error. `--log-level` overrides its `log_level`; `--cache-dir` and
`--max-heap` apply. `tsa.require_trusted` and `tsa.max_clock_skew_ms` have no flags, here or in `dss-server`:
set them through `--config`. Output files (`-o`, `--request`, `--out-dir` reports, `tl snapshot -o`) that are regular files
are written atomically: a temporary file next to the target, renamed over it once complete. `-o` may therefore
name the input, and an unwritable destination is reported before any work or TSA request. An existing
write-protected file is refused (exit 2, `<path>: Permission denied`), not replaced. A FIFO, `/dev/stdout`, a
process substitution (`-o >(gzip > out.gz)`) or any other path under `/dev` or `/proc` is opened before the
engine runs, truncated and written directly, not atomically.
`--cert`/`--chain` accept PEM bundles (a `--cert` bundle is the signer followed by its issuers). `--report` needs
`--out-dir`.

Exit status: `0` success (`validate`: every signature `TOTAL_PASSED`; `tl status`/`tl refresh`: trusted lists
loaded); `1` `validate`: a signature is not `TOTAL_PASSED` or there is none, `tl status`/`tl refresh`: no
trusted list loaded, `extend`/`sign`: DSS refused (`EXTENSION_FAILED`, `SIGNING_FAILED`); `2` error: bad
arguments, unreadable or unwritable files, any other library error (`TSA_FAILED` included). `validate-batch`
exits 0 once the batch ran: per-document failures are in their JSON line, with `error.code` the library's wire
name (e.g. `INVALID_ARGUMENT`); an invalid `--validation-time` exits 2. Output into a closed pipe (stdout or
stderr) is dropped and the exit status is kept. `dss-cli --help` prints the same contract.

In Rust:

```rust
let engine = dss::Engine::builder("dss-cache", &dss::Config::new("trust/oj-keystore.p12")).workers(4).build()?;
let reports = engine.validate(&std::fs::read("contract.pdf.p7m")?, &dss::Options::default())?;
let lt = engine.extend(&std::fs::read("signed-t.pdf")?, &dss::ExtendOptions::new(dss::Level::Lt))?;
std::fs::write("signed-lt.pdf", &lt.document)?;

// A detached signature, with its content from memory (DetachedContent::file(path) for a file):
let options = dss::Options {
    detached_contents: vec![dss::DetachedContent::bytes("document.txt", std::fs::read("document.txt")?)],
    ..Default::default()
};
let detached = engine.validate(&std::fs::read("document.txt.p7s")?, &options)?;
// The same with bytes the caller holds, borrowed for the call:
let content = std::fs::read("document.txt")?;
let detached = engine.validate_with_contents(
    &std::fs::read("document.txt.p7s")?,
    &dss::Options::default(),
    &[dss::DetachedBytes::named("document.txt", &content)],
)?;

let pdf = std::fs::read("contract.pdf")?;
let mut options = dss::SignOptions::new(dss::SigningMode::Cms, dss::Level::Lt);
let prepared = engine.prepare_signature(&pdf, &options)?;
let cms = my_signer(&prepared.digest_base64())?; // the external signer: a detached CMS for this digest
options.signing_time = Some(prepared.signing_time);
std::fs::write("contract-signed.pdf", engine.complete_signature(&pdf, &options, &cms)?.document)?;
```

**Detached contents.** `Engine::validate_with_contents(document, &options, &[DetachedBytes])` passes the signed
content of a detached signature as bytes the caller holds, through `dss_validate_with_contents`: no base64, and
the buffers are read only during the call. `DetachedBytes::named(name, bytes)` or `DetachedBytes::unnamed(bytes)`;
the contents come before the options' own `detached_contents`. `validate_with_contents_json` is the raw-JSON
variant, for hosts that build the options JSON themselves (dss-server's `detached` parts). `DetachedContent::bytes`
inside `Options::detached_contents` takes the same binary route from `Engine::validate`; only a serialised
`Options` (the `*_json` calls) carries it as base64. An empty content, more than 1024 contents or a name the
library cannot read is `INVALID_ARGUMENT`; a name with an embedded NUL is `Error::Nul`. DSS uses the detached
content of a CMS signature only when exactly one is given: with several candidates the verdict is
`SIGNED_DATA_NOT_FOUND`, so send the one the signature covers.

**Cancelling queued calls.** `Engine::cancellable(&token)` gives the document calls (`validate`,
`validate_with_contents`, `extend`, the signing calls and their `*_json` variants) bound to a `dss::CancelToken`.
Once `token.cancel()` was called, a call still queued for a worker is skipped and fails with `Error::Cancelled`;
a call a worker already runs cannot be interrupted and completes. dss-server cancels a request's token when its
`--request-timeout` deadline fires or the client goes away.

**Versions.** `dss::library_version()` reads `dss_version` without an engine (an isolate is created for the call
and torn down). `dss::API_VERSION` (1) is checked against the library's `api_version` by `build()`, which refuses
another version with `Error::Protocol`; a library reporting none predates the field and is accepted.

**Trust and status types.** `InitInfo.oj_keystore` and `TrustedListStatus.oj_keystore` are
`Option<OjKeystoreInfo { path, sha256 }>` (None only for libraries that predate them): the root of trust in use,
`sha256` being the value snapshots record as `settings.oj_keystore_sha256` (see "Trusted-list status").
`ListStatus.last_published_sequence_number` is the rollback floor; a `tl_rollback` `Alert` carries
`previous_sequence_number`, `previous_issue_date`, `sequence_number` and `issue_date`. `RefreshRecord.duration_ms`
is measured on a monotonic clock and never negative, while `started_at`/`finished_at` are wall-clock and may appear
out of order after a clock step. `Changes.pages_differ` lists the pages (from 1) added or removed after the signed
revision.

**Refresh schedule** (feature `tokio`): `schedule::RefreshScheduler` refreshes every period and on demand.
`stop()` ends it at once; a refresh in flight finishes in the background and its outcome is not published.
Dropping the handle instead lets a refresh in flight finish and publishes its outcome, then the schedule ends and
the outcome channel closes: a shutdown that must wait for a running refresh subscribes, drops the handle and awaits
`changed()` until it fails.

Errors print as `CODE: message` with the library's code (`INVALID_ARGUMENT: ...`); a code the crate does not
know is `ErrorCode::Unknown(name)` and keeps its name. A process keeps at most 256 distinct unknown names; further
ones decode to `Unknown("UNKNOWN")`, with the real name at the start of the `Error::Api` message.
`EngineBuilder::max_heap` takes digits and a unit (`512m`, `2g`); a size without a unit, an isolate option not
starting with `-X`/`-XX:`/`-D`, or a path that is not valid UTF-8 is refused by `build()` with `Error::Argument`
before the library is touched. Every result struct is `#[non_exhaustive]`; `cargo doc -p dss --open` has the
field-level reference.

### HTTP sidecar

`dss-server` serves one engine over HTTP, for PHP and other languages: multipart requests in, the library's JSON
out. The trusted lists are loaded once and refreshed every 6 hours. The server admits at most `--max-in-flight`
document requests at a time (503 `SERVER_BUSY` beyond that), bounds each request with `--request-timeout` (504
`TIMEOUT`), and its `/health` answers 200 only once the trusted lists are loaded (unless
`--allow-without-trusted-lists`). A request abandoned before its engine call ran (deadline fired, client
disconnected) is skipped, not run for nobody; a call already running completes and keeps its slot. Detached
contents arrive as `detached` parts and go to the library as binary buffers (`dss_validate_with_contents`), never
as base64, before any `detached_contents` entry of the options. A CAdES detached signature covers one content:
send exactly that one, since with two DSS finds no signed data (`SIGNED_DATA_NOT_FOUND`). A TSA, LOTL/TL mirror,
CRL or OCSP responder on a loopback or private address (a Compose service, this host) needs
`--allow-private-addresses` (`DSS_ALLOW_PRIVATE_ADDRESSES`, off by default), which cannot be combined with
`--config`. The PHP client
(`php/DssClient.php`) needs `guzzlehttp/guzzle` ^7.2 and `guzzlehttp/psr7` ^2.0, which a Laravel application
already has. API, options, Laravel client and Docker image:
[`docs/server.md`](docs/server.md); OpenAPI 3.1 description: [`docs/openapi.yaml`](docs/openapi.yaml), also served
at `/openapi.yaml`.

```bash
rust/target/release/dss-server --country IT
```

```bash
curl -F document=@contract.pdf.p7m http://127.0.0.1:8484/validate
```

### CI and packages

`.github/workflows/ci.yml` runs the whole chain:
- JVM tests, native tests and the shared library;
- the C smoke test;
- Rust lints and tests;
- the differential test;
- packaging.

It runs when a version tag is pushed (`git tag v1.2.0 && git push origin v1.2.0`), on all three platforms, or by
hand with `gh workflow run ci.yml` (add `-f online=true` for the online suites and the seed cache). Besides the
chain above it runs each package on the oldest supported systems (AlmaLinux 9 = glibc 2.34, Ubuntu 22.04,
macOS 14) and on Fedora (zlib-ng), builds the Docker image and waits for its health check. Only when every job
passed does it create the GitHub release for the tag (as a draft, filled, then published) with the packages, the
seed cache, the OJ keystore, the source archives (dss-native, DSS, GraalVM CE, labs-openjdk), `SHA256SUMS` and,
once the repository is public, signed build provenance. The tag is the version: `v1.2.0` (or `v1.2.0-rc.1`)
builds 1.2.0 everywhere, from the library to the package names. The repository itself carries only the
placeholder `0.0.0-dev`, which local and non-release builds report.

Every push to main and every pull request runs `.github/workflows/checks.yml` (repository rules, `reuse lint`,
script tests, syntax checks, cargo fmt, JVM tests, the PHP client's tests on PHP 8.1, 8.2 and 8.4: a few minutes
on Linux). `.github/workflows/security.yml` runs cargo-deny and
osv-scanner every Monday and when dependency manifests change, and fails when a newer GraalVM CE release than the
pinned one is out; Dependabot proposes version bumps.

A package (`scripts/package.sh [--out-dir DIR]` → `dist/dss-native-<version>-<platform>.tar.gz`, with a
`.sha256` beside it; reproducible: packaging the same built library twice on the same commit gives the same
bytes, though native-image's own determinism is not guaranteed, see `docs/DECISIONS.md`, "Reproducible
packages") contains:
- `lib/libdssnative.*` and `include/*.h`;
- `bin/dss-cli` and `bin/dss-server`, which run from the unpacked folder;
- `share/dss-native/oj-keystore.p12` and its `README.md` (from `trust/`);
- `README.md`, `LICENSE`, `LICENSING.md`, and `docs/`, `trust/README.md`, `php/`, `docker/` in the repository
  layout (links work);
- `sbom/java.cdx.json`, `sbom/rust.cdx.json` (CycloneDX);
- the third-party licences and notices in `licenses/`;
- `SOURCE`: repository URL, commit and the source archives attached to the release.

It needs glibc 2.34 or later and zlib on Linux (Ubuntu 22.04+, Debian 12+, RHEL 9+), or macOS 14 or later.
macOS: binaries are not notarized. A package downloaded with a browser is quarantined and Gatekeeper refuses to
run it; remove the attribute once: `xattr -dr com.apple.quarantine dss-native-<version>-macos-aarch64/` (curl and
gh downloads are not quarantined).

To use the seed cache, extract `dss-native-tl-cache-<date>.tar.gz` into your `cache_dir`: it contains the
`tl/` folder.

### Differential test

Every fixture, and your own documents in `testdata/private/`, go through plain DSS on the JVM and through
Rust → libdssnative. Per signature it compares indication, sub-indication, level, qualification, signing time
and signer DN. Any difference fails it; reports go to `build/diff/`.

```bash
scripts/diff-vs-jvm.sh
```

Regenerate the synthetic fixtures; options `[--new-pki] [--signing-only] [--out=<dir>] [--time=<ISO-8601
instant>]` (`--new-pki` also replaces the test PKI). The generator runs in its own JVM (`$JAVA_HOME/bin/java`,
with `-XX:+UnlockExperimentalVMOptions -XX:hashCode=2`) and is reproducible: see `testdata/fixtures/README.md`
in the repository.

```bash
scripts/generate-fixtures.sh
```

Fill a trusted-list cache (`<dir>/tl/`) on the JVM, as a seed cache to ship with an application. This is a copy
of the cache, not a trusted-list snapshot (see "Trusted-list snapshots" below). The optional second argument is a
`config_json` file; write paths inside it as absolute paths (they resolve against `java/`, where the seeder runs):

```bash
scripts/seed-tl-cache.sh ./tl-cache
```

## API

The C API (`java/.../ffi/DssLib.java`, header `libdssnative.h`) is a thin layer over `DssJsonApi`. Every string
is UTF-8 JSON. Every call returns an object with `ok: bool`; on failure it is
`{"ok": false, "error": {"code": "...", "message": "..."}}`. No exception crosses the boundary.

String arguments must be well-formed UTF-8: a malformed byte is refused with `INVALID_ARGUMENT` (`"cache_dir is
not valid UTF-8 (byte 11)"`), never repaired. `config_json` and `options_json` are parsed strictly: duplicate
keys, numbers with leading zeros or a dangling `.`/exponent, numbers beyond double range and malformed `\u`
escapes are errors (`INVALID_CONFIG`, `INVALID_ARGUMENT`). An error the engine could not report itself (for
instance an `OutOfMemoryError` while decoding an argument or copying a result) comes back as `INTERNAL_ERROR`
with the Java message; `NULL` is returned only if not even that small result could be malloc'd. A heap exhausted
while DSS is processing a document can abort the process instead: see
[`docs/native-library.md`](docs/native-library.md), "Heap size", before sizing `-Xmx`. Passing a `NULL`,
detached, torn-down or another thread's `graal_isolatethread_t*` is fatal (Native Image checks it at entry); see
the "Threads" rule there.

Every function takes the calling thread's `graal_isolatethread_t*` first. Isolates, threads, memory ownership,
heap size and TLS trust are covered in [`docs/native-library.md`](docs/native-library.md).

| C function | Java (`DssJsonApi`) | Does |
|---|---|---|
| `dss_init(cache_dir, config_json)` | `init` | Builds the engine; loads TLs from `<cache_dir>/tl/` (offline), or from the snapshot `tl_snapshot` names. Result: `trusted_lists_loaded` (bool), `log_level` (the level in force: a re-init cannot change it), `initial_load` (a refresh record, see "Trusted-list status") and `oj_keystore` (`path` and `sha256` of the root of trust in use, as in `dss_tl_status`; libraries before it omit the key). |
| `dss_tl_refresh_online()` | `refreshTrustedListsOnline` | Downloads and validates LOTL + TLs. Blocking. Result: `refresh` (a refresh record). `REFRESH_IN_PROGRESS` if one is running; `TL_REFRESH_FAILED` when the refresh published nothing (the previous lists are kept; per-list problems are in the status). |
| `dss_tl_status()` | `trustedListStatus` | Freshness and per-list status. Never blocks on a running refresh. |
| `dss_tl_export_snapshot(&out_snapshot, &out_len)` | `exportTlSnapshot` | The loaded TLs as a snapshot file, for `tl_snapshot`. It comes back like `dss_extend`'s document; the result JSON describes it. |
| `dss_validate(bytes, len, options_json)` | `validate` | Validates a PDF or CMS document. |
| `dss_validate_with_contents(bytes, len, count, names, contents, lens, options_json)` | `validate` | As `dss_validate`, with the signed content of a detached signature as `count` binary buffers (`contents[i]` of `lens[i]` bytes, named `names[i]`; `names` or an entry may be `NULL`) instead of base64 inside `options_json`. They are added to `detached_contents` before any entry the JSON carries. `count` is at most 1024; a `NULL` or empty content, a content over 2^31-9 bytes and a malformed name are `INVALID_ARGUMENT`. The buffers are only read during the call, and binary end to end: the engine copies each one once, never as base64, and a content too large for the heap is `INTERNAL_ERROR`. |
| `dss_extend(bytes, len, options_json, &out_document, &out_len)` | `extend` | Extends the signatures of a PDF to PAdES-BASELINE-T, -LT or -LTA. On success the extended PDF comes back in `*out_document` (`*out_len` bytes), otherwise `NULL`. |
| `dss_sign_prepare(bytes, len, options_json)` | `prepareSignature` | Signing, step 1: the digest the external signer must sign. No network. |
| `dss_sign_complete(bytes, len, options_json, signature, signature_len, &out_document, &out_len)` | `completeSignature` | Step 2: the signed document, from what the external signer returned. It comes back like `dss_extend`'s. |
| `dss_version()` | `version` | `library`, `dss` and `runtime` (the GraalVM runtime) versions, and `api_version`: the integer version of the C/JSON contract, bumped only on an incompatible change (a removed or renamed field, a changed verdict or error-code meaning, a changed C signature), never on an additive one. A caller built for another API version should refuse the library; one that omits the field predates the check and counts as version 1. Works before `dss_init`. |
| `dss_shutdown()` | `shutdown` | Stops the engine's background threads; call before `graal_tear_down_isolate`, and not while a refresh runs. Result: `trusted_list_threads_stopped` (bool). |
| `dss_free(ptr)` | n/a | Frees any string or document the library returned. `NULL` is ignored. |

Validation, extension and signing keep working, against the previous lists, while an online refresh runs.

### `config_json`

Only `oj_keystore.path` is required.

```jsonc
{
  "oj_keystore": { "path": "trust/oj-keystore.p12", "type": "PKCS12", "password": "dss-password" },
  "oj_url": "https://eur-lex.europa.eu/eli/C/2026/1944/oj", // OJ publication announcing the LOTL signers
  "lotl_url": "https://ec.europa.eu/tools/lotl/eu-lotl.xml",
  "countries": [],                    // e.g. ["IT"]; empty = every TL in the LOTL (default). See below
  "tl_versions": [6],                 // TSL versions accepted without a structure warning; [] = DSS's default
                                      // [5, 6]; other versions are still used unless accept_structure_errors is false
  "pivot_support": true,              // follow the LOTL's pivots (earlier LOTLs), which bridge signer rotations
  "use_sunset_date": true,            // trust a CA only for the periods its service was granted. See below
  "tl_sync": {
    "accept_invalid_signature": false, // never trust lists whose signature does not validate
    "accept_expired": true,            // keep using lists past NextUpdate (qualification flags it)
    "accept_structure_errors": true    // false: lists DSS flags for their structure (TSL version outside
                                       // tl_versions, schema deviations) are not trusted
  },
  "tl_threads": 8,                    // list download/validation threads: 1-64, default min(CPUs, 16)
  "online_cache_expiration_ms": 0,    // 0 = re-download on every online refresh; must not be negative
  "http": {
    "connect_timeout_ms": 30000, "response_timeout_ms": 60000, // each 1 to 2147483647
    "tl_verify_tls": false,           // LOTL/TL downloads skip TLS server checks; their XML signature is verified
    "trust_store": null,              // {path, type, password}: replaces the CA bundle built into the library
    "allowed_schemes": ["http", "https"], // URL schemes the engine may fetch (CRL, OCSP, AIA, TSA, trusted
                                      // lists); add "ldap" for LDAP CRL distribution points
    "block_private_addresses": true,  // refuse loopback, private, link-local (cloud metadata), CGNAT and
                                      // multicast addresses, literal or resolved
    "max_response_bytes": 67108864,   // larger bodies fail the request
    "request_deadline_ms": 120000,    // wall-clock bound per request, redirects and retries included; 0 = none
    "follow_redirects": true,         // false: a 3xx answer fails the request
    "proxy": null,                    // {host, port, scheme ("http"|"https"), username, password,
                                      // no_proxy: ["host", …]}: one forward proxy for every request
    "use_system_proxy": false,        // take the proxy from the http(s).proxyHost properties instead (not with proxy)
    "cache_ms": 3600000               // how long CRL and AIA (GET) responses are reused across calls; 0 disables
  },
  "limits": {                         // structural bounds checked before DSS runs (see below)
    "max_pdf_pages": 5000, "max_pdf_signatures": 100, "max_pdf_annotations_per_page": 5000,
    "max_cms_certificates": 500
  },
  "revocation": "online",             // "offline": only revocation data embedded in the signature
  "aia": true,                        // fetch missing intermediate certificates (default: revocation == online)
  "reports": [],                      // extra default reports: "detailed", "etsi", "diagnostic"
  "require_trusted_lists": true,      // false: validate even with no TL loaded (private PKI)
  "extra_trusted_certificates": [],   // PEM/DER files trusted in addition to the TLs
  "tsa": {                            // RFC 3161 TSA for T and LTA (extension, signing); default: none
    "url": "https://tsa.example.com/tsr", // http(s); must not contain user:password@
    "username": "…", "password": "…", // optional HTTP Basic credentials, both or neither; need an https url
    "require_trusted": true,          // refuse tokens whose TSA certificate does not chain to the trusted lists or
                                      // extra_trusted_certificates (see "Timestamps" below)
    "max_clock_skew_ms": 300000       // refuse tokens dated further than this from the host's clock
  },
  "log_level": "warn",                // off, error, warn, info, debug or trace (slf4j-simple), logs go to stderr
  "tl_snapshot": null                 // a trusted-list snapshot file to start from instead of <cache_dir>/tl
}
```

Unknown keys are rejected (`INVALID_CONFIG`), and so is any value out of its range. Other rules:

- **`countries`** uses the LOTL's scheme territory codes: Greece is `"EL"`, not `"GR"` (refused). Codes that
  match no list in the LOTL are reported in the status (`countries_unmatched`, and an alert). Limiting the lists
  limits the trust anchors: a signature anchored in another member state's list (a German qualified signature
  with `["IT"]`) then validates `INDETERMINATE` with `NO_CERTIFICATE_CHAIN_FOUND`, and nothing in the validation
  result says the scope is the reason (the status lists what is loaded). Load every list wherever cross-border
  signatures may arrive.
- **`use_sunset_date`** (DSS's `GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate`): with `true`, the
  default, a CA certificate is a trust anchor only for the periods its trust service was granted (or recognised
  at national level) in the list's service history. A CA withdrawn after a signature was made therefore turns a
  B or LT signature `INDETERMINATE` (`NO_CERTIFICATE_CHAIN_FOUND_NO_POE`) once validated after the withdrawal,
  while an LTA signature, whose archive timestamp proves the signature existed before it, still passes. A
  signature timestamp alone is not enough: a T (or LT) signature turns `INDETERMINATE` too; only the LTA archive
  timestamp keeps it valid past the withdrawal. A signature made after the withdrawal is `INDETERMINATE`
  (`NO_CERTIFICATE_CHAIN_FOUND_NO_POE`, not `NO_CERTIFICATE_CHAIN_FOUND`) at every level, LTA included. With
  `false` every certificate in a list is a trust anchor at all times, also after its service was withdrawn: a CA
  withdrawn years ago, even before the signature was made, still yields `TOTAL_PASSED` at every level. Keep the
  default.
- **`limits`** bound what drives DSS's super-linear costs (pages, signature revisions and annotations per page
  of a PDF, certificates in a CMS). They are checked with one parse before DSS runs, for validation (every
  nesting level), extension and signing; a document above one is refused with the operation's failure code
  (`VALIDATION_FAILED`, `EXTENSION_FAILED`, `SIGNING_FAILED`) and a message naming the limit. A document that
  cannot be parsed at all is let through, so that DSS reports its own error.
- **Outbound requests.** Every HTTP client the engine builds (trusted lists, CRL/OCSP/AIA, TSA) runs behind one
  policy: `allowed_schemes`, `block_private_addresses`, `max_response_bytes`, `request_deadline_ms`.
  `block_private_addresses` defaults to `true`, so a TSA, LOTL/TL mirror or CRL/OCSP/AIA server on 127.0.0.1 or a
  private address is refused (`outbound request to … refused by policy: 127.0.0.1 is a loopback address (…)`)
  unless the configuration sets it to `false` (or `dss-server` runs with `--allow-private-addresses`; `dss-cli`
  takes it from `--config` only), as air-gapped deployments with internal mirrors and responders, and the test
  suites with their local servers, do. The address check covers
  names as resolved when the request starts; it is a first layer, not a defence against DNS rebinding. Redirects
  are not followed by the HTTP client but by the policy: each `Location` is checked like the first URL (scheme
  allow-list, private-address blocking, no credentials), at most 10 hops, within the same
  `request_deadline_ms`; a POST (OCSP, TSA) follows only 307/308. `follow_redirects: false` disables redirects
  altogether. AIA (caIssuers) URLs are fetched over http(s) only. Validation never fetches a signature policy
  named by the document.
- **`http.cache_ms`** is an upper bound; how long a response is kept depends on what it is. A CRL is never reused
  past its own `nextUpdate`, and bodies that are not a CRL, certificate or CMS bundle (an error page answered with
  200) are kept for only a few seconds. Lower `cache_ms` only when a CA re-issues CRLs more often than hourly
  before `nextUpdate`. OCSP and TSA requests (POSTs) are never cached.
- **`log_level`** is fixed by the first `dss_init` in an isolate (on the JVM, in the process): a later init with
  another level keeps the first one (its result's `log_level` says which, and a warning is logged). Each Rust
  `Engine` has an isolate of its own. HttpClient's header and wire loggers never go
  below `info`, whatever the level (at debug they would print the TSA's credentials).
- **`tl_snapshot`**: `cache_dir` is still required. With a snapshot it need not be writable: a `<cache_dir>/tl`
  that cannot be created is only a warning (read-only deployments), and online refreshes then keep their lists in
  memory and report `cache_write_error`. Without a snapshot an unusable cache directory is `INVALID_CONFIG`.

**The cache.** `<cache_dir>/tl/` holds one file per list, named after its URL. Downloads are staged under
`<cache_dir>/tl-staging/` and only lists whose signature validated (and, for national lists, whose LOTL did) are
copied into the cache, each written whole and renamed into place, so a bad download (an error page, a truncated
transfer, a forged list) never replaces a good cached list and a restart never sees a half-written one. One
process should own a cache directory: a `dss-cli tl refresh` next to a running `dss-server` writes safely but does
not update the server's trust pool (use `POST /tl/refresh`). Every list, downloaded or cached, is pre-checked
before DSS parses it: it must be XML with a `TrustServiceStatusList` root whose signatures use only the
enveloped-signature and canonicalization transforms, as every EU list does.

**Rollback protection.** `<cache_dir>/tl-sequence-numbers.json` records, per list URL, the highest sequence
number (and its issue date) the engine has published; it is written atomically after each publication and after
a snapshot import, and never lowered. A list older than that, downloaded or read from the cache, is refused: an
on-path attacker cannot replay an older, validly signed list in which a since-withdrawn service still appears.
The refusal shows as the list's `download.status` `ERROR` ("rollback refused: …") and a `tl_rollback` alert. A
cache directory restored from an older backup, or a snapshot older than what this `cache_dir` once published,
therefore fails closed: delete `tl-sequence-numbers.json` to accept the older lists deliberately, or run an online
refresh of current ones.

### `options_json` (per validation, optional)

```jsonc
{
  "reports": ["detailed", "etsi"],         // simple report is always included
  // C hosts can pass the bytes directly with dss_validate_with_contents, Rust hosts with
  // validate_with_contents or DetachedContent::bytes; with several contents for one CMS, DSS finds none
  // (SIGNED_DATA_NOT_FOUND)
  "detached_contents": [{ "name": "contract.pdf", "path": "/tmp/contract.pdf" }], // or "base64": "..."
  "validation_time": "2026-01-31T12:00:00Z",
  "filename": "contract.pdf.p7m",          // name shown in the reports
  "unwrap_nested": true                    // also validate signed content inside CAdES (.p7m.p7m, .pdf.p7m)
}
```

Input may be the document itself or up to three nested transport encodings of it (base64, including MIME line
breaks and URL-safe, and PEM armour); `transformations` lists what was removed. Bytes that are neither a PDF nor
a CMS structure are `UNSUPPORTED_DOCUMENT`.

### Validation result

```jsonc
{
  "ok": true,
  "container": "CMS",                  // or "PDF"
  "transformations": ["base64"],       // encodings removed before validation
  "all_passed": true,                  // at least one signature, at every level, and all TOTAL_PASSED; false for an
                                       // unsigned document. Ignores warnings and modified_after_signing: check those
  "signatures": [{
    "id": "S-…", "indication": "TOTAL_PASSED", // "sub_indication": "…" when not TOTAL_PASSED
    "format": "CAdES-BASELINE-B", "qualification": "QESIG",
    "signing_time": "…Z", "best_signature_time": "…Z", "signed_by": "…",
    "signer_dn": "CN=…,O=…,C=IT",       // signing certificate subject (RFC 2253)
    "trust_anchor": "trusted_list",     // or "extra_trusted_certificates" (a private PKI: qualification is NA and
                                        // qualification_errors says no trusted list was reached) or "none"
    "errors": [], "warnings": [],       // AdES validation messages: why the indication is what it is
    "qualification_errors": [], "qualification_warnings": [], // why the signature is not qualified; a
                                        // TOTAL_PASSED signature may have these
    "info": [],                         // e.g. a signature policy that could not be resolved (never fetched)
    "policy": { "id": "…", "url": "…", "identified": false }, // only when the signature claims a policy
    "modified_after_signing": false,    // PDF only: annotation or undefined changes, or page differences, after
                                        // this signature's revision. DSS's default policy reports them as
                                        // warnings and keeps TOTAL_PASSED: a host accepting documents from third
                                        // parties must check this flag
    "changes_after_signing": {          // PDF only
      "extension": 2, "signature_or_form_fill": 0, "annotation": 0, "undefined": 0,
      "pages_differ": [],               // pages (from 1) added or removed after this signature's revision
      "annotations_overlap": [],        // page numbers
      "active_content": []              // added /OpenAction, /AA, /JavaScript, /Launch, /EmbeddedFiles, … objects
    },
    "timestamps": [{ "id": "T-…", "type": "SIGNATURE_TIMESTAMP", "indication": "PASSED", "production_time": "…Z",
                     "produced_by": "…", "qualification": "QTSA", "errors": [], "warnings": [] }]
  }],
  "timestamps": [],                    // standalone document timestamps (a timestamp-only PDF has signatures: []
                                       // and one entry here)
  "simple_report_xml": "<…>",
  "detailed_report_xml": "<…>",        // when requested
  "etsi_report_xml": "<…>",            // when requested
  "diagnostic_data_xml": "<…>",        // when requested
  "nested": [ { /* same shape */ } ]   // only when there is signed content inside, see below
}
```

A key with no value is left out rather than set to `null`, in this result and every other one: read optional keys
(`sub_indication`, `policy`, `modified_after_signing`, `nested`, …) as possibly absent.

**Nested:** the signed content of an attached CAdES signature is validated too when it is itself CMS
(`.p7m.p7m`, up to 8 levels) or a PDF carrying signatures or a document timestamp (`.pdf.p7m`); an unsigned PDF
inside adds nothing, and without inner signed content there is no `nested` key. `all_passed` counts the inner
signatures. **Visual comparison** of PDF pages is off; under DSS's default policy it would only add a warning
anyway, so it changes no verdict.

### Extension (`dss_extend`)

```jsonc
// options_json
{
  "level": "LT",                       // required: "T", "LT" or "LTA" (any case)
  "filename": "contract.pdf"           // name used in DSS's messages
}
// result_json; the extended PDF itself comes back in *out_document
{ "ok": true, "container": "PDF", "transformations": [], "level": "PAdES-BASELINE-LT" }
```

DSS's `PAdESService` extends **every** signature in the PDF. The result is the input PDF (base64/PEM decoded, if
it was) followed by an incremental update, so the original signatures stay valid:
- **LT** adds a DSS dictionary with the certificates, CRLs and OCSP responses of the signatures and timestamps.
  They are fetched online, unless `revocation` is `"offline"`: then only data already in the document counts.
- **T** adds a document timestamp from `tsa` (another one, if the signatures already have one). **LTA** does LT,
  then adds a document timestamp over everything. A B-level signature extended to LT gets a timestamp first, so
  it needs a `tsa` too.

DSS checks the signatures first. It refuses (`EXTENSION_FAILED`, with DSS's reason in the message) when:
- a signature or timestamp does not verify;
- a certificate is revoked, expired or not yet valid;
- revocation data is missing;
- every signature is already at a higher level than the target (a signature above the target among others below
  it is left as it is, with a log warning, while the others are raised: a B signature added to an LTA document
  can be extended; the document timestamp this adds may lift an earlier LT signature to LTA);
- the PDF has no signature: a PDF whose only signature-like revision is a document timestamp counts as unsigned
  ("No signatures found to be extended!"), so a timestamp-only archive cannot be renewed;
- a timestamp is needed and no `tsa` is configured;
- the PDF is over one of the `limits`.

With `revocation: "offline"` a signature below LT cannot reach LT or LTA (there is no revocation data to embed);
this is refused before the TSA is contacted, so no timestamp is spent. A TSA that cannot be reached or returns an
unacceptable token is `TSA_FAILED`, not `EXTENSION_FAILED`. A PDF encrypted with a user password is
`UNSUPPORTED_DOCUMENT`, here and for every other operation.

**Timestamps** are checked before they are embedded (here and when signing): the token must be over the digest
sent and carry a nonce matching the request; its TSA certificate must have signed it, be valid at the token's
time, have the id-kp-timeStamping extended key usage and (`tsa.require_trusted`) chain to the trusted lists or
`extra_trusted_certificates`; MD2/MD5/SHA-1 signatures and RSA keys under 2048 bits are refused; the token's time
must be within `tsa.max_clock_skew_ms` of this host's clock. The trust check is skipped, with a warning in the
log, while the engine has no trust anchor at all. That includes an engine with `require_trusted_lists: true`
before its first successful refresh: extension refuses there with `TRUSTED_LISTS_NOT_LOADED`, but signing at T
embeds the token unchecked. To have the check from the first call, seed the TL cache or list the TSA's chain in
`extra_trusted_certificates`.

Only PDFs are extended: CMS/CAdES input is `UNSUPPORTED_DOCUMENT`. The TSA's HTTPS server is trusted like the
CRL/OCSP servers (see [native-library.md](docs/native-library.md#tls-which-cas-are-trusted)).

Known DSS issue: on a PDF with a signed field whose `/Lock` restricts all fields (FieldMDP `Action=All`), DSS
6.5.1 reports the document timestamp its own LTA extension adds as a change the lock forbids (a `FieldMDP` /
`SigFieldLock` warning in the reports). The verdict is unaffected, and `modified_after_signing` does not count
extension changes as modifications.

### Signing with an external signer (`dss_sign_prepare`, `dss_sign_complete`)

The key stays with the external signer (a remote signing service, an HSM, a smart card); the document never
leaves the caller. Two steps, with nothing kept in between, so they may run minutes or processes apart:

1. `dss_sign_prepare(document, options_json)` returns the `digest` to send to the signer, and the
   `signing_time` the signature will claim.
2. The signer signs it. Then `dss_sign_complete(document, options_json + signing_time, signer output)` checks
   what came back against this document, builds the signed document with DSS and adds the level asked for.

Both calls take the **same document and options**; `complete` also needs `signing_time` as `prepare` returned
it. The prepared PDF depends on them: a different signing time, filename or `pades` entry gives another digest,
and `complete` then refuses the signature (`SIGNING_FAILED`, "not this document's digest").

Two modes, by what the external signer returns:

| `mode` | The signer receives | It returns | DSS builds |
|---|---|---|---|
| `"cms"` | The content's digest (PAdES: the PDF's signed byte ranges') | A detached CMS SignedData: signed attributes around that digest, its certificate, maybe its own signature timestamp | The PDF around the CMS (PAdES), or the `.p7s`/`.p7m` (CAdES), then the levels above |
| `"signature_value"` | The digest of the signed attributes DSS built (RSA signers wrap it in a DigestInfo) | The bare signature value: RSA PKCS#1 v1.5, or ECDSA as DER or `r‖s` | The whole CMS and document, at the requested level |

```jsonc
// options_json, for both calls
{
  "mode": "cms",                        // required: "cms" or "signature_value"
  "level": "LT",                        // required: "B", "T", "LT" or "LTA"
  "format": "PAdES",                    // default: "PAdES" for a PDF, "CAdES" otherwise
  "digest_algorithm": "SHA256",         // "SHA256" (default), "SHA384", "SHA512"
  "signing_time": "2026-10-28T10:15:30Z", // whole seconds; prepare: default now; complete: required (except
                                        // CAdES in "cms" mode, where the CMS carries its own)
  "signing_certificate": "MIIG…",       // base64 DER or PEM. Required for "signature_value"; with "cms", the
                                        // CMS must be signed with it
  "certificate_chain": ["MIIF…"],       // issuers: put into the CMS DSS builds, and used for LT/LTA
  "packaging": "detached",              // CAdES only: "detached" (.p7s, default) or "enveloping" (.p7m)
  "filename": "contract.pdf",           // the document's name (it enters the prepared PDF)
  "pades": {                            // PAdES only: signature dictionary entries
    "reason": "…", "location": "…", "contact_info": "…", "signer_name": "…",
    "content_size": 32768,              // bytes reserved for the CMS; default 32768 ("cms"), 9472 ("signature_value")
    "visible": { … }                    // a visible appearance, see "Visible signatures" below; default invisible
  }
}
// dss_sign_prepare result
{ "ok": true, "format": "PAdES", "digest_algorithm": "SHA256", "digest": "<base64>",
  "data_to_sign": "<base64>",           // "signature_value" only: the DER signed attributes, for signers that hash
  "signing_time": "2026-10-28T10:15:30Z" }
// dss_sign_complete result; the signed document comes back in *out_document
{ "ok": true, "format": "PAdES", "level": "PAdES-BASELINE-LT", "packaging": "ENVELOPED" } // or DETACHED, ENVELOPING
```

Levels. **B** is what the signer delivers; **T** adds a timestamp from `tsa` unless an external CMS already has a
(verified) signature timestamp: for CAdES a signature timestamp; for PAdES in `"cms"` mode a document timestamp
(which also covers the PDF's other signatures), in `"signature_value"` mode a signature timestamp inside the new
CMS (no document timestamp; the other signatures keep their level). **LT** adds the certificates and revocation
data like `dss_extend`, **LTA** both. A CMS with its own timestamp asked for at B comes back as T, and `level`
says so. TSA problems at T, LT and LTA are `TSA_FAILED`; timestamps are checked as for extension.

What `complete` checks in `"cms"` mode, before building anything (each failure is `SIGNING_FAILED` with the
reason): one signer; detached; the SignerInfo digest algorithm equal to `digest_algorithm`, and the signature
algorithm hashing with it (SHA-1 and MD5 signatures are refused) and matching the signer's key; content-type
`id-data`; a message-digest equal to this document's digest; a signing-certificate-v2 (or signing-certificate)
attribute that references the certificate the CMS is signed with (certificate hash, and issuer/serial when
given); signing-time **absent for PAdES** (the time is the PDF's `/M`) and present for CAdES; the signer's
certificate inside, equal to `signing_certificate` when given, valid at the signing time (for CAdES: at the time
its signing-time attribute claims) and meant for signing documents (see below); the signature verifying with it;
every attribute with exactly one value; and no unsigned attribute other than at most one signature-time-stamp,
whose token must be over this signature value and verify with its TSA certificate (certificate-values,
revocation-values, archive timestamps, counter-signatures and unknown attributes are refused: the engine adds
what the level needs). The CMS may be DER, BER (it is re-encoded as DER), base64 or PEM, and must fit
`pades.content_size`. In `"signature_value"` mode the value must verify with `signing_certificate` over the data
DSS rebuilt; base64 text is decoded.

Other rules:
- When `signing_certificate` is given (required in `"signature_value"` mode), `prepare` refuses
  (`SIGNING_FAILED`) a certificate that is expired or not yet valid at the signing time, a CA certificate
  (basicConstraints cA=true), one whose key usage allows neither digitalSignature nor nonRepudiation, or one whose
  extended key usage is limited to timeStamping, serverAuth or OCSP signing, before any external signature is
  spent. In `"cms"` mode without `signing_certificate` the same is checked at `complete` on the certificate in the
  CMS.
- PAdES at LT/LTA (both modes) and at T in `"cms"` mode: DSS re-checks the PDF's existing signatures when it
  extends the document after embedding the new one. `prepare` checks them whenever the requested level may extend
  the document, so the external signature is not spent on a PDF `complete` would refuse. When the PDF still needs
  a document timestamp (in `"cms"` mode always, the new signature being at B when DSS extends; in
  `"signature_value"` mode when an existing signature has no timestamp) it refuses (`SIGNING_FAILED`, naming the
  signature) a signature that does not verify, one whose certificate had expired without a timestamp, or one
  already at a higher level; when every existing signature already has its timestamp (`"signature_value"` mode at
  LT/LTA) it only refuses signatures that do not verify or are above LT, as DSS does. Chain validity with
  revocation data is checked at `complete` only. At T in `"cms"` mode this runs even when the signer's CMS turns
  out to carry its own timestamp (then `complete` does not extend at all): the one case where `prepare` is
  stricter than `complete`. At B, and at T in `"signature_value"` mode, nothing is extended and the other
  signatures are left as they are. A second signature at LT/LTA on a PDF whose other signatures are already
  LT/LTA is possible: the higher-level ones are left alone.
- In `"signature_value"` mode `prepare` refuses (`INVALID_ARGUMENT`) a `pades.content_size` smaller than the CMS
  DSS will build: the signed attributes, the signature value and the certificates DSS embeds (the chain from the
  signing certificate up to, and excluding, the trust anchor; certificates off that path are neither embedded
  nor counted). The level-T signature timestamp is not part of the estimate. `complete` runs the same check, so
  with options `prepare` accepted only the timestamp can still make the CMS too large (`SIGNING_FAILED`).
- For CAdES in `"cms"` mode the time the signature claims is the signing-time attribute the signer puts in the
  CMS; `prepare`'s `signing_time` is not part of the digest, and `complete` neither requires nor compares it.
- `prepare` also refuses a PDF encrypted with a user password (`UNSUPPORTED_DOCUMENT`) and a document over the
  structural `limits` (`SIGNING_FAILED`).
- B and T need no trusted lists; LT and LTA need them like validation does (`require_trusted_lists`).
- CAdES signs the given bytes as content, also when they are a `.p7m` (giving a `.p7m.p7m`); it never adds a
  co-signer.

### Visible signatures (`pades.visible`)

A visible signature is a box on a page showing text, an image (a logo, a scanned handwritten signature), or both.
It goes in the `pades` object of the options and, like everything there, must be the same in both calls.

```jsonc
"visible": {
  // Where: an empty signature field of the PDF, by name…
  "field": "Firma1",
  // …or a new field: page from 1, then points (1/72 inch) from the top-left corner of the page as displayed
  // (on a page turned by /Rotate, as the reader sees it; the content is turned to read upright); x, y, width
  // and height are at most 14400 points (the largest PDF page side), width and height more than 0
  "page": 1, "x": 360, "y": 700, "width": 200, "height": 60,

  "text": "Firmato digitalmente da {signer_name}\n{signing_time}", // at most 10,000 characters, also once the
                                        // placeholders are filled in
  "font": "<base64 TTF>",               // default PT Serif; embedded as a subset (only the glyphs used); TTF or
                                        // OTF with TrueType outlines, at most 32 MB
  "font_size": 10,                      // the largest size, 4-200: the text shrinks and wraps at spaces to fit
  "text_color": "#000000",              // #RRGGBB
  "text_align": "left",                 // left | center | right; vertically centred
  "background_color": "#FFFFFF",        // default none (transparent)
  "image": "<base64 PNG or JPEG>",
  "image_position": "left",             // left | right | top | bottom | behind (under the text, filling the box)
  "time_zone": "Europe/Rome",           // for {signing_time}; default UTC
  "date_format": "dd/MM/yyyy HH:mm z"   // java.time pattern (English names); default "yyyy-MM-dd HH:mm:ss xxx"
}
```

- **Text placeholders**: `{signer_name}` is `pades.signer_name`, else the common name of `signing_certificate`
  (else an error: in `"cms"` mode without a certificate the signer is not known at `prepare`); `{signing_time}`
  is the signing time of the signature (the one `prepare` picked, if not given), so it always matches the
  signature; `{reason}` and `{location}` need those entries. `{{` and `}}` are literal braces.
- **Layout**: a 3-point margin. An image beside the text keeps its aspect ratio and takes at most half the
  width (`left`/`right`) or height (`top`/`bottom`); the text gets the rest. `behind` fits the image in the
  whole box and puts the text over it.
- **Images**: PNG (any colour type and bit depth, with transparency; not interlaced) or JPEG (baseline or
  progressive, gray or RGB; not CMYK), up to 25 megapixels and 16384 pixels a side. A JPEG goes into the PDF as
  it is; a JPEG whose Exif orientation is not 1 (stored rotated or mirrored) is refused, because PDF viewers
  ignore the tag: save it with the rotation applied first. A PNG is decoded row by row, so a large image costs a
  few MB of memory whatever it declares, and the decoded image is cached (at most 16 images and a sixteenth of
  the heap, 64 MB at most) so that `complete` does not decode it again; an opaque PNG gets no soft mask. Colour
  profiles inside the image are ignored (the colours are taken as sRGB).
- **Fonts**: TrueType outlines (`.ttf`, or `.otf` with TrueType outlines), at most 32 MB, embedded as a subset.
  The font is checked, loaded and subset at `prepare`, so an unusable font is `INVALID_ARGUMENT`: a TrueType
  collection, a CFF (OTTO) font, a licence that forbids subsetting (OS/2 fsType bit 8), inconsistent loca/glyf
  tables, or an hmtx shorter than the horizontal metrics hhea announces (a short left-side-bearing array is read
  as zeros, as FontBox does), or a cmap with more than 16 encoding records, a format-13 subtable, or more than
  1,000,000 mapped characters in all. A character the font has no glyph for is an error, not a blank (a font
  with no space glyph can still show a single word).
- **PDF/A**: fonts are embedded and a PDF without an output intent gets an sRGB one (as DSS does); a PDF whose
  output intents are all for another colour space (a CMYK print profile) keeps them, and the appearance's
  resources get a DefaultRGB colour space (sRGB ICC), which ISO 19005-2 accepts for DeviceRGB text and images.
  No conformance checker runs on the result. A transparent PNG becomes a soft mask, which PDF/A-1 forbids: use an
  opaque image for PDF/A-1 documents.
- **Rotated pages and fields**: a field flagged NoRotate is drawn upright, as viewers display it, whatever the
  page's `/Rotate`.
- **Encrypted PDFs**: a PDF that needs a user password to open is refused with `UNSUPPORTED_DOCUMENT`; there is
  no password option (owner-password-only PDFs are fine).
- **Refused with `INVALID_ARGUMENT`**, at `prepare`: malformed options; a page that does not exist; a page the
  page tree announces but that does not exist, or one its `/Count` does not reach (a damaged tree: repair the PDF
  first); a box not inside the page, or overlapping another annotation (a form field, a link, another
  signature); a field that does not exist, is not a signature field, is already signed, or whose widget is
  flagged Hidden or NoView (its appearance would never be displayed); text longer than 10,000 characters, or blank
  once its placeholders are filled in (an empty `pades.reason` with `{reason}`) when there is no image to show
  instead (with an image, the blank text is left out and the image alone is drawn); text that does not fit even
  at 3 points.

The appearance is drawn without AWT (DECISIONS.md, "Visible signatures"), the same bytes on every platform and
in both calls, provided `prepare` and `complete` run the same build of the library on hosts with the same zlib
implementation: the Flate streams of the appearance (image samples, ICC profile, content and font streams) are
compressed by the host's libz, and zlib-ng (the default on Fedora 40+ and RHEL 10) deflates to different bytes
than classic zlib. Running `prepare` on one and `complete` on the other is detected cleanly: `complete` fails
with `SIGNING_FAILED` ("not this document's digest") before anything is written, but the external signature is
wasted. Deploy one image for both steps.

### Trusted-list snapshots (`dss_tl_export_snapshot`, `tl_snapshot`)

Loading the lists from the cache parses every list and validates its XAdES signature again, at every start.
A snapshot is the result of that work, the trust pool the engine built, written to one file. An engine whose
`config_json` names it in `tl_snapshot` loads that instead and validates nothing. Measured natively on macOS
aarch64 (docs/native-library.md, "Performance"):

| | From the cache | From a snapshot | Snapshot size |
|---|---|---|---|
| Full EU list (4,910 certificates) | 6.5 s (15 threads), 32 s (1 thread) | 0.63 s | 14 MB |
| IT only (468 certificates) | 3.8 s | 0.10 s | 1.5 MB |

Make one from an engine that has lists loaded (from the cache, or after an online refresh), and store it
wherever the next engine will find it. The result JSON describes the file:

```jsonc
{ "ok": true, "format": 1, "library": "1.2.0", "dss": "6.5.1",
  "created_at": "2026-11-06T10:49:45Z",
  "lists_loaded": { "mode": "offline", "finished_at": "…", … }, // the load that validated the lists
  "trusted_certificates": 4910,
  "settings": { "lotl_url": "…", "oj_url": "…", "oj_keystore_sha256": "…", "countries": [], "tl_versions": [6],
                "pivot_support": true, "use_sunset_date": true, "tl_sync": { … } },
  "size": 14583987 }
```

When it loads a snapshot, `dss_init` fails with `TL_SNAPSHOT_REJECTED` if the file:
- cannot be read, is not a snapshot, or is damaged (CRC-32C);
- was written by another snapshot format or DSS version;
- was written with other trusted-list settings: those under `settings` above, the OJ keystore by its
  certificates. Countries and TL versions are compared as sets, and `tl_versions: []` is recorded as `[5, 6]`;
- trusts a list that `tl_sync` no longer allows. A list past its next update is refused when `accept_expired` is
  false, exactly as a load from the cache would refuse it now;
- has trust anchors that reference lists missing from its summary.

**The library does not decide whether a snapshot can be trusted.** It holds trust anchors, and nothing in it is
checked against the EU's signatures when it loads. Whoever can write the file can make any certificate trusted.
The application that stores and hands over snapshots must make sure they are its own, e.g. by shipping them in
its read-only deployment, or by checking a hash or signature of its own before naming the file in `tl_snapshot`.
What the library does guard against is a hostile file attacking the process: deserialization only accepts the
classes a snapshot contains (DECISIONS.md, "Trusted-list snapshots").

After it starts from a snapshot, the engine behaves as usual:
- `dss_tl_status` reports the snapshot under `tl_snapshot`, and `last_offline_refresh.mode` is `"snapshot"`.
- An online refresh replaces the snapshot's lists with what it downloads, as a refresh into an empty cache would.
  An online refresh whose LOTL cannot be downloaded, or whose national lists all fail, is not published: the
  snapshot stays in use (the status keeps `tl_snapshot`), `dss_tl_refresh_online` returns `TL_REFRESH_FAILED`,
  `last_online_refresh.completed` is false and its `error` says why, and a `refresh_not_published` alert is
  raised. When the LOTL downloads but one list fails, that list stays missing until a later refresh succeeds; a
  `cache_dir` holding the lists is the fallback.
- Exporting again is allowed, and keeps the original `lists_loaded`.

### Trusted-list status

`dss_tl_status` returns:
- `loaded` (bool), `trusted_certificates` (the trust pool's size), `extra_trusted_certificates` (how many anchors
  `extra_trusted_certificates` loaded; they validate as `TOTAL_PASSED` with qualification `NA` and `trust_anchor`
  `"extra_trusted_certificates"`), `oj_keystore` (the root of trust in use: `path`, the configured
  `oj_keystore.path`, and `sha256`, the SHA-256 over the sorted SHA-256 digests of its certificates; trusted-list
  snapshots record the same value as `settings.oj_keystore_sha256`, so a snapshot's provenance can be checked
  against a running engine; the engine also logs it at INFO when it starts: `OJ keystore <path>: <n> LOTL
  signing certificate(s), sha256 <hex>`), and `snapshot_published_at` (when the trust pool in use was
  published);
- `refresh_in_progress` and `refresh_started_at` (while one runs);
- `last_offline_refresh` and `last_online_refresh`: refresh records, the same shape as `initial_load` and
  `refresh` above: `mode` (`offline`, `online` or `snapshot`), `started_at`, `finished_at`, `duration_ms`,
  `completed`, `error`, `trusted_certificates`. `duration_ms` is measured on a monotonic clock and is never
  negative, even if the system clock steps backwards during the refresh; `started_at`/`finished_at` are
  wall-clock times and may then appear out of order. `completed` is false only when the refresh produced nothing
  publishable (DSS could not run; or the LOTL could not be downloaded after a snapshot start, was badly signed,
  or no national list could be downloaded while lists were loaded): the previously loaded lists stay in use and
  `error` says why. Problems of single lists are in `lotls[]`/`tls[]`;
- `tl_snapshot` (the snapshot's description, its `path` and `size`, when the lists came from one);
- `countries_unmatched`: configured `countries` that match no list in the LOTL;
- `lotls[]` and `tls[]`, each with:
  - `url`, `territory`, `sequence_number`, `version`, `issue_date`, `next_update`, `expired`;
  - `last_published_sequence_number` (the floor the rollback protection enforces for that URL; absent when
    nothing has been published for it);
  - `tsp_count`, `service_count`, `certificate_count`, `structure_messages` (DSS's structure validation
    messages, usually empty);
  - `used_for_trust`;
  - `download` / `parsing` / `validation`: `status`, `last_state_transition`, `last_success_synchronization`, and
    on error `error`, `error_first_seen`, `error_last_seen`; `validation` also has `indication`,
    `sub_indication`, `signing_time` and `signed_by`;
  - for a LOTL, `pivots[]`, each described like a list;
- `alerts`, keyed by type and URL, each with `type`, `url`, `message`, `first_seen`, `last_seen`, `count` and `at`
  (= `last_seen`); at most 100 keys, oldest evicted:
  - from DSS's detections: `oj_url_changed` (the signal to update the OJ keystore), `lotl_location_changed`,
    `lotl_signature_error`, `lotl_expired`, `lotl_structure_error`, `tl_signature_error`, `tl_expired`,
    `tl_structure_error`;
  - the library's own: `countries_unmatched`, `refresh_not_published` (a refresh that produced no usable trust
    pool; the previous lists were kept; the message says why), `cache_write_error` (a usable list could not be
    stored in `<cache_dir>/tl`; one per list, `url` = the list), and `tl_rollback` (a list older than the one
    published was refused; it also carries `previous_sequence_number`, `previous_issue_date`, `sequence_number`
    and `issue_date`).

### Error codes

| Code | Meaning | Rust (`dss::ErrorCode`) |
|---|---|---|
| `INVALID_ARGUMENT` | Malformed options, arguments or C strings | `InvalidArgument` |
| `INVALID_CONFIG` | Malformed or out-of-range `config_json`; unusable keystore or cache directory | `InvalidConfig` |
| `NOT_INITIALIZED` | No successful `dss_init` yet | `NotInitialized` |
| `TRUSTED_LISTS_NOT_LOADED` | No trusted list loaded and `require_trusted_lists` is true | `TrustedListsNotLoaded` |
| `REFRESH_IN_PROGRESS` | An online refresh is already running | `RefreshInProgress` |
| `TL_REFRESH_FAILED` | The online refresh published no lists; the previous ones are kept (see `dss_tl_status`) | `TlRefreshFailed` |
| `UNSUPPORTED_DOCUMENT` | Neither a PDF nor a CMS; CMS given to `dss_extend`; a PDF that needs a user password | `UnsupportedDocument` |
| `VALIDATION_FAILED` | DSS could not validate the document (unparseable, over a `limits` bound) | `ValidationFailed` |
| `EXTENSION_FAILED` | DSS refused to extend the signatures (see "Extension") | `ExtensionFailed` |
| `SIGNING_FAILED` | The signature cannot be completed as asked (see "Signing") | `SigningFailed` |
| `TSA_FAILED` | The TSA could not be reached, answered an error (retrying may help), or returned a token the engine refuses | `TsaFailed` |
| `INTERNAL_ERROR` | Anything unexpected, including an `OutOfMemoryError` the engine could catch | `InternalError` |
| `TL_SNAPSHOT_REJECTED` | The `tl_snapshot` file cannot be used (see "Trusted-list snapshots") | `TlSnapshotRejected` |

Codes are stable and only ever added; treat an unknown code like `INTERNAL_ERROR`.

## The OJ keystore

`trust/oj-keystore.p12` comes from the DSS 6.5.1 demonstrations and holds the public certificates allowed to sign
the LOTL. Watch for the `oj_url_changed` alert. [`trust/README.md`](trust/README.md) explains where it comes from
and how to update it.

## Licence

Copyright (C) 2026 Coding Duck. Licensed under the GNU Lesser General Public License, version 2.1 or (at your
option) any later version ([`LICENSE`](LICENSE)).

DSS is LGPL-2.1-or-later too, and the native image bundles it into one library, so this repository's source and
build scripts are what let users rebuild against a modified DSS. [`LICENSING.md`](LICENSING.md) explains that,
lists the licences of every component in the library and the executables, and describes the notices that
release packages ship in `licenses/`. The text of every licence used in the repository is in `LICENSES/`, as the
[REUSE specification](https://reuse.software) requires; CI runs `reuse lint`.

"DSS" and "Digital Signature Service" name the European Commission's project, used here only to say what this
library wraps. dss-native is not an official EU artifact; for the official DSS, see
[github.com/esig/dss](https://github.com/esig/dss).
