# dss-native

The [EU Digital Signature Service (DSS)](https://github.com/esig/dss) validation engine for native applications.
A thin Java wrapper around DSS is compiled with GraalVM Native Image (Community Edition) into a shared library
with a C API, plus Rust crates on top. No JVM is needed at runtime.

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
> - Rust crates (`dss-sys`, `dss`, `dss-cli`) wrap it;
> - a differential test checks the native path against plain DSS on the JVM;
> - GitHub Actions builds, tests and packages it for linux-x64, linux-aarch64 and macos-aarch64.
>
> Decisions and versions: [`docs/DECISIONS.md`](docs/DECISIONS.md). Licensing: [`LICENSING.md`](LICENSING.md).

## Layout

```
java/        Maven project: engine/ (pure Java), ffi/ (DssLib: the C entry points), nativeimage/ (DssFeature),
             src/test/c/ (C smoke test)
rust/        Cargo workspace: dss-sys (bindgen), dss (safe Engine, tokio scheduler), dss-cli (demo),
             dss-server (HTTP sidecar)
php/         DssClient.php, DssException.php: Laravel client for dss-server
docker/      dss-server/Dockerfile: the sidecar's image, from a Linux release package
testdata/    fixtures/ (synthetic, committed) and private/ (your real documents, gitignored)
trust/       OJ keystore with the LOTL signing certificates
scripts/     build-native.sh, smoke-test-c.sh, test-rust.sh, diff-vs-jvm.sh, package.sh, ci/install-graalvm.sh,
             ci/set-version.sh, generate-fixtures.sh, seed-tl-cache.sh, run-agent.sh, merge-metadata.py,
             run-native-tests.sh, audit-reflection.sh
docs/        DECISIONS.md, native-library.md, server.md, openapi.yaml, reflection-audit.md
.github/     workflows/ci.yml, actions/setup (GraalVM CE, Rust, libclang, caches)
build/       native/<os>-<arch>/: the built library and headers (not committed)
```

## Building and testing (JVM)

Requires JDK 21+. GraalVM CE 25 is what the project pins: see `docs/DECISIONS.md`.

```bash
cd java && ./mvnw test
```

That runs the unit suite: no network, everything served in memory. Tests that hit the real EU LOTL are tagged
`online`:

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

Build the shared library into `build/native/<os>-<arch>/` and smoke-test it from C. Add `--online` to the smoke
test to run it against the real EU LOTL:

```bash
scripts/build-native.sh
```

```bash
scripts/smoke-test-c.sh
```

### Rust

Needs the native library (above) and libclang for bindgen.

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

`extend --level t|lta` also needs a TSA: `--tsa-url <url>`, and `--tsa-user <name>` with the password in
`DSS_TSA_PASSWORD` if it asks for HTTP Basic credentials.

A trusted-list snapshot of what the cache holds, then any command started from it instead of the cache (see
"Trusted-list snapshots" below):

```bash
rust/target/release/dss-cli --country IT tl snapshot -o it.tlsnap
```

```bash
rust/target/release/dss-cli --country IT --tl-snapshot it.tlsnap validate contract.pdf.p7m
```

`tl status` prints what is loaded, from the cache and without network. `--country IT` limits the lists;
`--cache-dir` defaults to `./dss-cache`. In Rust:

```rust
let engine = dss::Engine::builder("dss-cache", &dss::Config::new("trust/oj-keystore.p12")).workers(4).build()?;
let reports = engine.validate(&std::fs::read("contract.pdf.p7m")?, &dss::Options::default())?;
let lt = engine.extend(&std::fs::read("signed-t.pdf")?, &dss::ExtendOptions::new(dss::Level::Lt))?;
std::fs::write("signed-lt.pdf", &lt.document)?;

let pdf = std::fs::read("contract.pdf")?;
let mut options = dss::SignOptions::new(dss::SigningMode::Cms, dss::Level::Lt);
let prepared = engine.prepare_signature(&pdf, &options)?;
let cms = my_signer(&prepared.digest_base64())?; // the external signer: a detached CMS for this digest
options.signing_time = Some(prepared.signing_time);
std::fs::write("contract-signed.pdf", engine.complete_signature(&pdf, &options, &cms)?.document)?;
```

### HTTP sidecar

`dss-server` serves one engine over HTTP, for PHP and other languages: multipart requests in, the library's JSON
out. The trusted lists are loaded once and refreshed every 6 hours. API, options, Laravel client and Docker image:
[`docs/server.md`](docs/server.md); OpenAPI 3.1 description: [`docs/openapi.yaml`](docs/openapi.yaml), also served at
`/openapi.yaml`.

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

It runs only when a GitHub release is published, on all three platforms, or when started by hand with
`gh workflow run ci.yml` (add `-f online=true` for the online suites and the seed trusted-list cache). Pushes
and pull requests run nothing.

Publishing a GitHub release builds everything and uploads the packages, the seed cache and the OJ keystore to
it. The tag is the version: `v1.2.0` (or `v1.2.0-rc.1`) builds 1.2.0 everywhere, from the library to the
package names. The repository itself carries only the placeholder `0.0.0-dev`, which local and non-release
builds report.

A package (`scripts/package.sh` → `dist/dss-native-<version>-<platform>.tar.gz`) contains:
- `lib/libdssnative.*` and `include/*.h`;
- `bin/dss-cli` and `bin/dss-server`, which run from the unpacked folder;
- `share/dss-native/oj-keystore.p12`;
- `LICENSE`, `LICENSING.md`, the third-party licences and notices in `licenses/`, and the `SOURCE` reference.

It needs glibc 2.34 or later and zlib on Linux (Ubuntu 22.04+, Debian 12+, RHEL 9+), or macOS 14 or later.

To use the seed cache, extract `dss-native-tl-cache-<date>.tar.gz` into your `cache_dir`: it contains the
`tl/` folder.

### Differential test

Every fixture, and your own documents in `testdata/private/`, go through plain DSS on the JVM and through
Rust → libdssnative. Per signature it compares indication, sub-indication, level, qualification, signing time
and signer DN. Any difference fails it; reports go to `build/diff/`.

```bash
scripts/diff-vs-jvm.sh
```

Regenerate the synthetic fixtures (`--new-pki` also replaces the test PKI):

```bash
scripts/generate-fixtures.sh
```

Build a trusted-list cache snapshot to ship with an application:

```bash
scripts/seed-tl-cache.sh ./tl-cache
```

## API

The C API (`java/.../ffi/DssLib.java`, header `libdssnative.h`) is a thin layer over `DssJsonApi`. Every string
is UTF-8 JSON. Every call returns an object with `ok: bool`; on failure it is
`{"ok": false, "error": {"code": "...", "message": "..."}}`. No exception crosses the boundary.

Every function takes the calling thread's `graal_isolatethread_t*` first. Isolates, threads, memory ownership,
heap size and TLS trust are covered in [`docs/native-library.md`](docs/native-library.md).

| C function | Java (`DssJsonApi`) | Does |
|---|---|---|
| `dss_init(cache_dir, config_json)` | `init` | Builds the engine; loads TLs from `<cache_dir>/tl/` (offline), or from the snapshot `tl_snapshot` names. |
| `dss_tl_refresh_online()` | `refreshTrustedListsOnline` | Downloads and validates LOTL + TLs. Blocking. `REFRESH_IN_PROGRESS` if one is running. |
| `dss_tl_status()` | `trustedListStatus` | Freshness and per-list status. Never blocks on a running refresh. |
| `dss_tl_export_snapshot(&out_snapshot, &out_len)` | `exportTlSnapshot` | The loaded TLs as a snapshot file, for `tl_snapshot`. It comes back like `dss_extend`'s document; the result JSON describes it. |
| `dss_validate(bytes, len, options_json)` | `validate` | Validates a PDF or CMS document. |
| `dss_extend(bytes, len, options_json, &out_document, &out_len)` | `extend` | Extends the signatures of a PDF to PAdES-BASELINE-T, -LT or -LTA. On success the extended PDF comes back in `*out_document` (`*out_len` bytes), otherwise `NULL`. |
| `dss_sign_prepare(bytes, len, options_json)` | `prepareSignature` | Signing, step 1: the digest the external signer must sign. No network. |
| `dss_sign_complete(bytes, len, options_json, signature, signature_len, &out_document, &out_len)` | `completeSignature` | Step 2: the signed document, from what the external signer returned. It comes back like `dss_extend`'s. |
| `dss_version()` | `version` | Library and DSS versions. Works before `dss_init`. |
| `dss_shutdown()` | `shutdown` | Stops the engine's background threads; call before `graal_tear_down_isolate`. |
| `dss_free(ptr)` | n/a | Frees any string or document the library returned. `NULL` is ignored. |

Validation, extension and signing keep working, against the previous lists, while an online refresh runs.

### `config_json`

Only `oj_keystore.path` is required.

```jsonc
{
  "oj_keystore": { "path": "trust/oj-keystore.p12", "type": "PKCS12", "password": "dss-password" },
  "oj_url": "https://eur-lex.europa.eu/eli/C/2026/1944/oj", // OJ publication announcing the LOTL signers
  "lotl_url": "https://ec.europa.eu/tools/lotl/eu-lotl.xml",
  "countries": [],                    // e.g. ["IT"]; empty = every TL in the LOTL (default)
  "tl_versions": [6],
  "pivot_support": true,
  "use_sunset_date": true,
  "tl_sync": {
    "accept_invalid_signature": false, // never trust lists whose signature does not validate
    "accept_expired": true             // keep using lists past NextUpdate (qualification flags it)
  },
  "tl_threads": 8,                    // list download/validation threads (default: CPUs, max 16)
  "online_cache_expiration_ms": 0,    // 0 = re-download on every online refresh
  "http": {
    "connect_timeout_ms": 30000, "response_timeout_ms": 60000,
    "tl_verify_tls": false,           // LOTL/TL downloads skip TLS server checks; their XML signature is verified
    "trust_store": null               // {path, type, password}: replaces the CA bundle built into the library
  },
  "revocation": "online",             // "offline": only revocation data embedded in the signature
  "aia": true,                        // fetch missing intermediate certificates (default: revocation == online)
  "reports": [],                      // extra default reports: "detailed", "etsi", "diagnostic"
  "require_trusted_lists": true,      // false: validate even with no TL loaded (private PKI)
  "extra_trusted_certificates": [],   // PEM/DER files trusted in addition to the TLs
  "tsa": {                            // RFC 3161 TSA for T and LTA (extension, signing); default: none
    "url": "https://tsa.example.com/tsr",
    "username": "…", "password": "…"  // optional HTTP Basic credentials, both or neither
  },
  "log_level": "warn",                // slf4j-simple level, logs go to stderr
  "tl_snapshot": null                 // a trusted-list snapshot file to start from instead of <cache_dir>/tl
}
```

Unknown keys are rejected (`INVALID_CONFIG`).

### `options_json` (per validation, optional)

```jsonc
{
  "reports": ["detailed", "etsi"],         // simple report is always included
  "detached_contents": [{ "name": "contract.pdf", "path": "/tmp/contract.pdf" }], // or "base64": "..."
  "validation_time": "2026-01-31T12:00:00Z",
  "filename": "contract.pdf.p7m",          // name shown in the reports
  "unwrap_nested": true                    // also validate CAdES nested in CAdES (.p7m.p7m)
}
```

### Validation result

```jsonc
{
  "ok": true,
  "container": "CMS",                  // or "PDF"
  "transformations": ["base64"],       // encodings removed before validation
  "signatures": [{
    "id": "S-…", "indication": "TOTAL_PASSED", "sub_indication": null,
    "format": "CAdES-BASELINE-B", "qualification": "QESIG",
    "signing_time": "…Z", "best_signature_time": "…Z", "signed_by": "…",
    "signer_dn": "CN=…,O=…,C=IT",       // signing certificate subject (RFC 2253)
    "errors": [], "warnings": []
  }],
  "simple_report_xml": "<…>",
  "detailed_report_xml": "<…>",        // when requested
  "etsi_report_xml": "<…>",            // when requested
  "diagnostic_data_xml": "<…>",        // when requested
  "nested": [ { /* same shape, for the envelope inside */ } ]
}
```

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
  then adds a document timestamp over everything. A B-level signature extended to LT gets a timestamp first.

DSS checks the signatures first. It refuses (`EXTENSION_FAILED`, with DSS's reason in the message) when:
- a signature or timestamp does not verify;
- a certificate is revoked, expired or not yet valid;
- revocation data is missing;
- a signature is already at a higher level than the target, or the PDF has no signature;
- a timestamp is needed and no `tsa` is configured, or the TSA fails.

Only PDFs are extended: CMS/CAdES input is `UNSUPPORTED_DOCUMENT`. The TSA's HTTPS server is trusted like the
CRL/OCSP servers (see [native-library.md](docs/native-library.md#tls-which-cas-are-trusted)).

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
  "signing_time": "2026-10-28T10:15:30Z", // whole seconds; prepare: default now; complete: required
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

Levels. **B** is what the signer delivers; **T** adds a timestamp from `tsa` (PAdES: a document timestamp;
CAdES: a signature timestamp), unless an external CMS already has a signature timestamp. **LT** adds the
certificates and revocation data like `dss_extend`, **LTA** both. A CMS with its own timestamp asked for at B
comes back as T, and `level` says so.

What `complete` checks in `"cms"` mode, before building anything (each failure is `SIGNING_FAILED` with the
reason): one signer; detached; the digest algorithm of the options; content-type `id-data`, signing-certificate-v2
and a message-digest equal to this document's digest; signing-time **absent for PAdES** (the time is the PDF's
`/M`) and present for CAdES; the signer's certificate inside, and equal to `signing_certificate` when given; the
signature verifying with it. The CMS may be DER, BER (it is re-encoded as DER), base64 or PEM, and must fit
`pades.content_size`. In `"signature_value"` mode the value must verify with `signing_certificate` over the data
DSS rebuilt; base64 text is decoded.

Other rules:
- `prepare` refuses a signing certificate that is expired or not yet valid at the signing time, before any
  external signature is spent.
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
  // (on a page turned by /Rotate, as the reader sees it; the content is turned to read upright)
  "page": 1, "x": 360, "y": 700, "width": 200, "height": 60,

  "text": "Firmato digitalmente da {signer_name}\n{signing_time}",
  "font": "<base64 TTF>",               // default PT Serif; embedded as a subset (only the glyphs used)
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
  progressive, gray or RGB; not CMYK), up to 25 megapixels. A JPEG goes into the PDF as it is. Colour profiles
  inside the image are ignored (the colours are taken as sRGB).
- **Fonts**: TrueType outlines (`.ttf`, or `.otf` with TrueType outlines). A character the font has no glyph
  for is an error, not a blank.
- **PDF/A**: fonts are embedded and a PDF without an output intent gets an sRGB one (as DSS does), so the
  appearance itself keeps PDF/A-2 and later. A transparent PNG becomes a soft mask, which PDF/A-1 forbids:
  use an opaque image for PDF/A-1 documents.
- **Refused with `INVALID_ARGUMENT`**, at `prepare`: malformed options; a page that does not exist; a box not
  inside the page, or overlapping another annotation (a form field, a link, another signature); a field that
  does not exist, is not a signature field or is already signed; text that does not fit even at 3 points.

The appearance is drawn without AWT (DECISIONS.md, "Visible signatures"), the same bytes on every platform and
in both calls.

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
  certificates. Countries are compared as a set;
- trusts a list that `tl_sync` no longer allows. A list past its next update is refused when `accept_expired` is
  false, exactly as a load from the cache would refuse it now.

**The library does not decide whether a snapshot can be trusted.** It holds trust anchors, and nothing in it is
checked against the EU's signatures when it loads. Whoever can write the file can make any certificate trusted.
The application that stores and hands over snapshots must make sure they are its own, e.g. by shipping them in
its read-only deployment, or by checking a hash or signature of its own before naming the file in `tl_snapshot`.
What the library does guard against is a hostile file attacking the process: deserialization only accepts the
classes a snapshot contains (DECISIONS.md, "Trusted-list snapshots").

After it starts from a snapshot, the engine behaves as usual:
- `dss_tl_status` reports the snapshot under `tl_snapshot`, and `last_offline_refresh.mode` is `"snapshot"`.
- An online refresh replaces the snapshot's lists with what it downloads, as a refresh into an empty cache would.
  A list that fails to download stays missing until a later refresh succeeds. To fall back to cached copies, use
  a `cache_dir` that holds them.
- Exporting again is allowed, and keeps the original `lists_loaded`.

### Trusted-list status

`loaded`, `trusted_certificates`, `refresh_in_progress`, `last_offline_refresh` and `last_online_refresh` (times,
duration, outcome, `mode`: `offline`, `online` or `snapshot`), `tl_snapshot` (the snapshot's description, its
`path` and `size`, when the lists came from one) and `alerts` (`oj_url_changed`, `lotl_location_changed`,
`tl_signature_error`, `tl_expired`). Then `lotls[]` and `tls[]`, each with:
- `url`, `territory`, `sequence_number`, `issue_date`, `next_update`, `expired`;
- `used_for_trust`;
- `download` / `parsing` / `validation` (status, last change, error, signature indication).

### Error codes

`INVALID_ARGUMENT`, `INVALID_CONFIG`, `NOT_INITIALIZED`, `TRUSTED_LISTS_NOT_LOADED`, `REFRESH_IN_PROGRESS`,
`TL_REFRESH_FAILED`, `UNSUPPORTED_DOCUMENT`, `VALIDATION_FAILED`, `EXTENSION_FAILED`, `SIGNING_FAILED`,
`INTERNAL_ERROR`, `TL_SNAPSHOT_REJECTED`.

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
release packages ship in `licenses/`.
