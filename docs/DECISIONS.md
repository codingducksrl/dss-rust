# Decisions

Decisions taken while building dss-native: what was chosen, why, and what was found to differ from the
original project brief. Newest phase last. Versions were looked up on 2026-10-28; none were taken from memory.

## Phase 0: toolchain and versions

| Component | Pinned | Source checked | Why this one |
|---|---|---|---|
| EU DSS | **6.5.1** | `maven-metadata.xml` on Maven Central (`<release>6.5.1</release>`, published 2026-10-14) | Latest release. |
| GraalVM | **GraalVM Community 25.4.4.1.1** ("25 Innovation 4", OpenJDK 25.0.4.1.1) | `graalvm/graalvm-ce-builds` GitHub releases, 2026-09-22 | Latest Community Edition release. GPLv2 + Classpath Exception. Oracle GraalVM (GFTC) is deliberately not used, nor Homebrew's `graalvm-jdk` cask, which installs Oracle GraalVM. |
| Java language level | `--release 21` | | The Native Image JDK is 25, but nothing here needs >21. Developers can still run the JVM tests on any 21+ JDK. |
| Rust | **1.99.1** stable | `static.rust-lang.org/dist/channel-rust-stable.toml` (2026-10-15) | Current stable; already installed locally. Used from Phase 4. |
| Maven | **3.10.0** through the Maven Wrapper 3.3.4 (`java/mvnw`), with `distributionSha256Sum` pinned | Maven Central metadata | Latest stable 3.x. 4.0 is still at RC (`4.0.0-rc-7`). The SHA-512 of the zip was checked against Apache's published `.sha512`. |
| Native Build Tools (Maven plugin) | 1.1.17 (to be added in Phase 2) | Maven Central | Latest. |
| JUnit | 6.1.3 | Maven Central | Latest. `junit-bom` is imported **before** `dss-bom`, because `dss-bom` also manages JUnit (5.14.x) and the first import wins. |
| Maven plugins | compiler 3.16.0, surefire 3.6.1, resources 3.5.0, jar 3.5.1, clean 3.5.0, install 3.2.0, dependency 3.11.0, enforcer 3.6.3, exec 3.6.4 | Maven Central | Latest **stable** of each. The `<release>` tag points at 4.0.0 betas for several plugins; those were skipped. |
| SLF4J | 2.0.20 (`slf4j-simple`) | DSS 6.5.1 parent POM | Same version DSS builds against. 2.1.0 is still alpha. |

GraalVM CE is installed locally under `~/Library/Java/JavaVirtualMachines/graalvm-community-25.4.4.1.1+1.1`. The
download's SHA-256 was checked against the published `.sha256`.

### Target platforms (asked; answered)

**linux-x64, linux-aarch64, macos-aarch64.** GraalVM CE publishes builds only for linux-x64, linux-aarch64,
macos-aarch64 and windows-x64. There is no macOS x64 or Windows arm64 build, and Native Image does not
cross-compile. Windows was not selected. This sets the Phase 6 CI matrix:
`ubuntu-24.04` (x64), `ubuntu-24.04-arm` and `macos-14`+ runners.

### Default trusted-list scope (asked; answered)

**Full LOTL.** With no `countries` in `config_json`, every national TL the LOTL points to is loaded.
`"countries": ["IT"]` limits it.

## Phase 1: Java engine on the JVM

### Corrections to the brief for DSS 6.5.1

API names were checked against the DSS 6.5.1 sources (cookbook `TLValidationJobSnippets`,
`EuropeanLOTLSnippets`, the `dss-demonstrations` 6.5.1 `DSSBeanConfig`) and with `javap` against the jars.

- `TLValidationJob`, `LOTLSource`, `FileCacheDataLoader`, `SignedDocumentValidator`,
  `OfficialJournalSchemeInformationURI` and `TrustedListsCertificateSource` exist with the names in the brief.
- Several packages changed. The info records are now `eu.europa.esig.dss.model.job.*`
  (`DownloadInfoRecord`, `ParsingInfoRecord`, `ValidationInfoRecord`). `TLInfo`, `LOTLInfo` and
  `TLValidationJobSummary` are in `eu.europa.esig.dss.model.tsl`. `CommonCertificateVerifier` is in
  `eu.europa.esig.dss.spi.validation`.
- In DSS 6, **`dss-validation` is an optional dependency** of `dss-cades`/`dss-pades` and must be declared
  explicitly. Otherwise `SignedDocumentValidator` is missing.
- The default validation policy and cryptographic suite moved into **`dss-policy-jaxb`** (`policy/constraint.xml`)
  and **`dss-policy-crypto-xml`**. Both must be on the runtime classpath.
- `dss-cms` needs an implementation module. **`dss-cms-object`** (in-memory BouncyCastle `CMSSignedData`) was
  chosen, matching the DSS demo; `dss-cms-stream` is described as experimental in 6.5.1. Without either, signing
  and CMS validation fail with "No implementation found for CMSGenerator".
- `dss-utils` needs an implementation: `dss-utils-apache-commons`. `dss-crl-parser` needs one too:
  `dss-crl-parser-stream`, as in the demo.
- `DSSUtils.loadPotentialIssuerCertificates` no longer exists. Extra trusted certificates are read with
  `DSSUtils.loadCertificate` / `loadCertificateFromBase64EncodedString`.
- The DSS 6.5.1 demo uses TL **version 6** only (`tl.loader.lotl.tl.versions=6`) plus the "sunset date" trust-anchor
  predicate (`GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate`). Both are adopted as defaults.
- Current OJ URL (from the 6.5.1 demo `dss.properties`): `https://eur-lex.europa.eu/eli/C/2026/1944/oj`. This is the
  `oj_url` default. The cookbook's 2019 URL is outdated.
- DSS throws `eu.europa.esig.dss.spi.exception.IllegalInputException` for unparseable CMS. It extends
  `RuntimeException`, not `DSSException`, so it is caught explicitly and mapped to `VALIDATION_FAILED`.

### Trusted lists

- **Cache layout:** `<cache_dir>/tl/` holds DSS's file cache. Other caches (AIA, revocation) can sit next to it
  later.
- **Loaders**, per the brief: offline `FileCacheDataLoader` (expiry `-1` = never, backed by
  `IgnoreDataLoader`) used at `init`; online `FileCacheDataLoader` with expiry `online_cache_expiration_ms`, default
  `0` (always refetch). The DSS demo's `Sha2FileCacheDataLoader` daily-update trick was not used, because the host
  application owns the refresh schedule.
- **Concurrency.** `ValidationJob.offlineRefresh/onlineRefresh/getSummary` are `synchronized`. DSS's
  `TrustedListCertificateSourceSynchronizer` calls `reset()` on the certificate source and refills it. It then
  sets trust times in a separate call. A validation running during that window can see an empty or
  inconsistent trust pool. The engine therefore:
  1. gives the job a private *staging* `TrustedListsCertificateSource`;
  2. after each refresh, under the refresh lock, copies staging into a new source;
  3. publishes the copy as an immutable snapshot through a `volatile` field.

  Validators only read snapshots. A plain "new source per refresh" does not work, because DSS skips the
  certificate sync when nothing changed, which would publish an empty source.
- **Status never blocks.** `tl_status` reads the last snapshot's summary, not `job.getSummary()`. The latter
  is `synchronized` and would wait for a running refresh.
- **One online refresh at a time.** A second concurrent `dss_tl_refresh_online` returns `REFRESH_IN_PROGRESS`
  immediately instead of queueing.
- **Synchronization strategy: deviation from DSS defaults.** DSS's default `AcceptAllStrategy` turns every TL
  into trust anchors even when the LOTL or TL signature does not validate. The qualification checks later flag
  it, but the AdES verdict can still be `TOTAL_PASSED` on injected anchors. A test showed this: an LOTL signed
  by a key outside the OJ keystore still yielded 3 trusted certificates. The engine uses
  `ExpirationAndSignatureCheckStrategy`:
  - invalid or indeterminate signatures are **rejected**;
  - expired lists are **accepted** (`tl_sync.accept_expired`, default `true`), so a country that is late
    re-publishing does not break validation, and qualification still flags it.

  Configurable through `tl_sync`. The status reports `used_for_trust` per list.
- **Empty cache:** `validate` returns `TRUSTED_LISTS_NOT_LOADED` when the snapshot has no certificates.
  `require_trusted_lists: false` turns that off, for private PKIs used with `extra_trusted_certificates`.
- **Alerts:** DSS's OJ-URL-change, LOTL-location-change, TL-signature-error and TL-expired detections are
  collected (last 100) into the status as `alerts` and logged. `oj_url_changed` is the signal to update
  `trust/oj-keystore.p12` and `oj_url`.
- The TL job runs on its own 4-thread **daemon** pool (DSS's default is a non-daemon cached pool), shut down
  on `close`. Non-daemon threads would hold up host-process exit and isolate teardown.

### Validation

- **Validators are instantiated directly:** `PDFDocumentValidator` for PDF and `CMSDocumentValidator` for CMS,
  chosen by sniffing the bytes. `SignedDocumentValidator.fromDocument` (a `ServiceLoader` over every format) is
  not used. This keeps the reachable set small for Native Image, and anything else is reported as
  `UNSUPPORTED_DOCUMENT`. XAdES/JAdES/ASiC are out of scope for now.
- **PDF visual comparison is off**: `DefaultPdfDifferencesFinder.setMaximalPagesAmountForVisualComparison(0)`
  on a directly constructed `PdfBoxNativeObjectFactory`. Object-level modification detection between revisions
  stays on (it does not render).
- **Input normalisation** before DSS sees the bytes:
  - base64, including MIME line breaks and URL-safe;
  - PEM armour;
  - up to 3 rounds.

  Each step is reported in `transformations`. A PDF header anywhere in the first 1024 bytes is accepted
  (PDF 1.7 §7.5.2).
- **Nested `.p7m.p7m`:** when an attached CAdES signature's content is itself CMS, it is validated too, up to 8
  levels. The inner results appear under `nested`. `unwrap_nested: false` disables this. DSS itself validates
  only the outer envelope.
- **Revocation:** `revocation: "online"` (default) uses `OnlineCRLSource` / `OnlineOCSPSource` (with DSS's
  `OCSPDataLoader` for the OCSP content type) and AIA fetching. `"offline"` uses only data embedded in the
  signature.
- Reports use `Locale.ENGLISH` so messages do not depend on the host's locale.
- **Loaders:** three separate DSS data loaders:
  - TL downloads (`tlLoader`, TLS not verified, see below);
  - CRL/AIA (`CommonsDataLoader`);
  - OCSP (`OCSPDataLoader`).

  All share the `http` timeouts.

### JSON contract

- **Reflection-free JSON:** `engine/Json.java`, about 300 lines, needs no Native Image registration. Reports
  stay DSS XML.
- **`DssJsonApi`** holds the whole contract, catching `Throwable`, as plain Java. The future `@CEntryPoint`
  layer (Phase 3) will only convert C strings, and the contract is tested on the JVM.
- **Additions to the brief's `result_json`**, all additive:
  - `container` (`"PDF"`/`"CMS"`);
  - `transformations`;
  - `signatures`: per-signature `indication`, `sub_indication`, `format`, `qualification`, `signing_time`,
    `best_signature_time`, `signed_by`, `errors`, `warnings`, taken from the simple report so Rust does not
    need an XML parser for the common case;
  - `nested`;
  - optional `diagnostic_data_xml`.
- Error codes (stable, additive only): `INVALID_ARGUMENT`, `INVALID_CONFIG`, `NOT_INITIALIZED`,
  `TRUSTED_LISTS_NOT_LOADED`, `REFRESH_IN_PROGRESS`, `TL_REFRESH_FAILED`, `UNSUPPORTED_DOCUMENT`,
  `VALIDATION_FAILED`, `INTERNAL_ERROR`.
- **Unknown keys** in `config_json` / `options_json` are errors, so typos fail loudly.
- **Re-init.** Calling `dss_init` again replaces the engine; validations already in flight finish on the old
  one.

### Tests and fixtures

- **Synthetic PKI** (`testdata/fixtures/pki/test-pki.p12`, password `dss-native-test`). It contains:
  - an RSA-3072 root;
  - an RSA signer and an EC P-256 signer;
  - a TSA;
  - LOTL/TL signers;
  - a second CA for the "DE" list.

  Everything is valid for 20 years from 2026-01-01. All names and URLs are fictitious, using the `.test` TLD.
  It is committed so the committed fixtures remain verifiable.
- **Synthetic trusted lists.** A signed TSL-v6 LOTL plus "IT" and "DE" TLs is generated at **test time** with
  DSS's `TrustedListV6SignatureParametersBuilder`. It is served through an in-memory `DataLoader` (`FakeHttp`),
  so the unit suite exercises the real path: LOTL signature against an OJ keystore, TL pointers, country filter,
  file cache, offline reload, concurrent refresh. It never opens a socket or ships lists that expire. CRLs are
  also generated per request.
- **Online suite.** Tests that hit the real EU LOTL are tagged `online`. They are excluded by default and run
  with `./mvnw test -Pintegration`.
- **Signing in tests** uses plain JCA keys (`Signing.sign`), so `dss-token` is not needed.
- **Fixture construction.** BER fixtures re-encode the outer CMS layers with indefinite lengths and chunk the
  content (64-byte segments), as streaming signers do. Nested fixtures are produced by signing a
  `DigestDocument` of the inner envelope and re-attaching the content: given CMS bytes, DSS would add a
  *parallel* signer instead.

### Naming

- Maven coordinates `it.codingduck.dssnative:dss-native`, Java packages `it.codingduck.dssnative.*`. Purely
  cosmetic and easy to change before the first release.

## Resolved after the Phase 1 report (2026-10-28)

The user answered the four open questions:

1. **TL sync: strict, as implemented.** Lists with an invalid or indeterminate signature are never used;
   expired lists are (`tl_sync.accept_expired: true`).
2. **TLS for trusted-list downloads: not verified.** The ES (`tsl.digital.gob.es`) and HU (`www.nmhh.hu`) TL
   hosts failed with `PKIX path building failed` against the JDK trust store. The LOTL/TL loader now uses
   `TrustAllStrategy`, as the DSS demo's `tl.loader.trust.all` option does. TL integrity comes from the XML
   signature, checked against the OJ keystore (for the LOTL) and the LOTL's pointers (for TLs). Combined with
   the strict sync, a man-in-the-middle can block a list but cannot inject one. Hostname verification is
   unchanged. CRL, OCSP and AIA downloads keep normal TLS verification. `http.tl_verify_tls: true` turns
   checking back on.
3. **Result JSON:** the extended shape (`container`, `transformations`, `signatures`, `nested` on top of the
   XML reports) is the contract the Rust side relies on.
4. **Validation policy:** DSS's default `constraint.xml` only. No custom policy support for now.

Naming (`it.codingduck.dssnative`) was not raised again; it stays.

## Phase 2: reachability metadata

Details per library are in [`reflection-audit.md`](reflection-audit.md). Decisions:

- **Native Build Tools 1.1.17**, `native` Maven profile: `./mvnw -Pnative test` runs the JUnit suite on the JVM,
  then builds it as a native executable and runs it again.
  - Build args: `--exact-reachability-metadata` (global, all packages) and
    `-H:MissingRegistrationReportingMode=${native.missingRegistrationMode}` (default `Throw`; `-D…=Warn`/`Exit`
    while iterating). In GraalVM 25.4 this option is experimental and needs `-H:+UnlockExperimentalVMOptions`.
  - The same mode can be set at run time on the built binary: `-XX:MissingRegistrationReportingMode=…`, see
    `scripts/run-native-tests.sh`.
- **Metadata repository:** the one bundled with NBT 1.1.17 (release 1.0.20). The Maven artifact
  `org.graalvm.buildtools:graalvm-reachability-metadata` carries NBT's version numbers, not the repository's,
  so it is left at the plugin default.
  - `check-library-support.sh` results at the time:
    - **exact:** PDFBox 3.0.8, bcpkix 1.86, JAXB 3.0.2, Activation, istack, Commons;
    - **nearest version only:** HttpClient 5.6.5 (5.3), HttpCore 5.4.4, SLF4J 2.0.20, stax2-api, xmlsec 3.0.6 (4.0.4);
    - **none:** bcprov, bcutil, Woodstox, every DSS module.
- **`DssFeature` without ClassGraph.** ClassGraph 6 (Oct 2026) requires JDK 25 and has a new, incompatible API;
  4.x is end-of-life. The scan the Feature needs (list class-path entries, match package patterns) is a few
  lines over `FeatureAccess.getApplicationClassPath()`, so no build dependency was added. JAXB classes are
  selected by package (`eu.europa.esig..jaxb..`, 802 classes) rather than by annotation: every class in those
  packages is JAXB model or adapter code.
- **Families registered by `DssFeature`.** Each one exists because its names come from data the tests don't
  vary:
  - JAXB models;
  - JAXB annotations (members + `Locatable` proxies) and the helper classes they name;
  - every BouncyCastle provider service (1,452) and `$Mappings` class (130);
  - xmlsec algorithm/c14n/transform/resolver implementations (90);
  - PDFBox security handlers;
  - resources: XSDs, policies, crypto suite, `dss-messages`, PDFBox AFM/glyph lists (~1.1 MB), FontBox CMaps
    (~3.2 MB).
- **Agent output is filtered, not copied.** `scripts/run-agent.sh` runs twice:
  - with a caller filter excluding JUnit, Surefire and our own code, giving library metadata;
  - unfiltered, giving test metadata.

  `scripts/merge-metadata.py` drops entries a Feature family covers, plus the JDK's own JCA provider classes
  (registered automatically, and platform-specific: `AppleProvider`, `NativePRNG`). It writes the rest to
  `src/main/...` (69 types / 47 resources) and test-only entries to `src/test/...`. It merges as a union, so
  hand edits survive.
- **`--enable-url-protocols` dropped:** deprecated in GraalVM 25 ("use reachability metadata instead"). The
  `http`/`https` handlers are in the JSON.
- **Locale: pinned, not bundled.** A native run under `LANG=it_IT` failed (`FormatData_it` missing).
  `-H:+IncludeAllLocales` fixes it at +53 MB and twice the build time. Instead:
  - the builder locale is fixed to en-US (`-Duser.language=en -Duser.country=US` in `native-image.properties`;
    `-H:DefaultLocale` is deprecated and ignored);
  - `RuntimeDefaults.apply()` sets `Locale.US` when the isolate starts. Phase 3's entry points must call it; the
    native tests call it through a JUnit `LauncherSessionListener`.

  Verified under it_IT, fr_FR, ja_JP and foreign time zones, and when building with `LANG=it_IT`.
- **New regression test:** national TLs signed with ECDSA and RSASSA-PSS. It guards the xmlsec family in the
  native run; before it, the tests only ever used RSA-SHA512.

Result (macOS aarch64, GraalVM CE 25.4.4.1.1):
- 53/53 JUnit tests pass on the JVM and as a native executable;
- `Throw` at build time and `Exit` at run time, with no missing registrations;
- native test image 91 MB, built in ~45–50 s;
- the native suite runs in ~3 s.

## Phase 3: native shared library

Details and usage: [`native-library.md`](native-library.md).

- **C API in `ffi/DssLib`**: `@CEntryPoint` methods that only convert C strings and call `DssJsonApi`.
  - Functions: `dss_init`, `dss_tl_refresh_online`, `dss_tl_status`, `dss_validate`, `dss_free` as in the brief,
    plus `dss_version` (library/DSS versions, from a Maven-filtered `version.properties`) and `dss_shutdown`
    (stops the TL worker threads before `graal_tear_down_isolate`).
  - Parameters use `@CConst` and `@CTypedef(name = "size_t")`, so the header reads
    `char* dss_validate(graal_isolatethread_t*, const char*, size_t, const char*)`.
- **No exception reaches C.** Each entry point has its own `try/catch (Throwable)` returning `NULL`.
  `CEntryPoint.exceptionHandler` was the first choice, but GraalVM 25 requires the handler method to be
  annotated with the internal `com.oracle.svm.core.Uninterruptible`, which is not in the public SDK.
- **OutOfMemoryError.** A test with `-Xmx16m` and a 48 MB document aborted the process. Native Image unwinds an
  allocation's `OutOfMemoryError` to the caller of the allocating compiled frame, past that frame's own
  `catch`; here the caller was the C entry stub. The fix keeps every large allocation out of the entry frames:
  - `dss_validate` passes a read-only `ByteBuffer` view of the C buffer to
    `DssJsonApi.validate(ByteBuffer, String)`, which copies it inside its own error handling;
  - results are UTF-8-encoded straight into malloc'd memory, with no `byte[]`.

  Now a 128 MB document on a 64 MB heap returns `INTERNAL_ERROR` and the isolate keeps working; this is in the
  C smoke test.
- **Build.** Native Build Tools `compile-no-fork` with `sharedLibrary`, in the `native` profile (`package`
  phase).
  - The image name is `libdssnative`, because native-image adds no `lib` prefix.
  - `-march=compatibility`, for portable binaries.
  - A relocatable install name (`@rpath/libdssnative.dylib`, macOS) and soname (`libdssnative.so`, Linux), set
    at link time through `-H:NativeLinkerOption` from OS-activated Maven profiles. Rewriting with
    `install_name_tool` afterwards would invalidate the arm64 code signature.
  - `scripts/build-native.sh` copies only the library and the four headers to `build/native/<os>-<arch>/`. The
    JDK AWT libraries that native-image also emits are not shipped. The C smoke test runs without them. Phase 6
    confirmed this on Linux the hard way, see "PDFBox and the JDK's libawt".
- **Heap.** Not fixed at build time: hosts pass `-Xmx…` through `graal_create_isolate_params_t.argc/argv`.
  Verified: `-Xmx16m` gives a 16 MB max heap.
- **TLS CA bundle.**
  - Build-time capture of GraalVM CE's `cacerts`. A different bundle can be embedded with
    `-Djavax.net.ssl.trustStore` at build time.
  - Per-engine runtime override through the new `http.trust_store` config. It goes through DSS's
    `CommonsDataLoader.setSslTruststore` rather than the process-wide `javax.net.ssl.*` properties, and
    **replaces** the embedded set.
  - TL downloads stay unverified by default, as decided after Phase 1.
- **Security providers.** Nothing extra is registered at build time. DSS adds BouncyCastle at run time; Phase 2's
  `DssFeature` makes all of its services reflectively instantiable. The JDK's providers are automatic.
- **Coverage of the real HTTP stack.** The first online C smoke run failed because HttpClient's
  `org/apache/hc/client5/version.properties` (loaded by computed name) was not registered. Every earlier test
  used the in-memory loader, so neither the native tests nor the agent had ever run real HTTP. Two additions
  close this:
  - **`HttpsLoopbackTest`**: real `CommonsDataLoader`, HttpClient and JSSE against an HTTPS server on
    127.0.0.1, certificate from the test PKI, including a redirect. It runs in the default suite and the native
    suite. Loopback only: no external network, consistent with the "no network in unit tests" rule.
  - **`run-agent.sh --online`**, together with the loopback test, added 14 types and 8 resources: HttpClient
    version and public-suffix files, content-decoder probes, DNS/IDN data, X.509 extensions, time-zone names.
- The **concurrency test** now delays each synthetic download (100 ms), so validations really overlap refreshes.
  It requires at least 4 × 6 overlapping validations; native runs see ~35.

Result (macOS aarch64):
- 58/58 tests on the JVM and natively (`Exit` mode);
- library ~85 MB, built in ~45 s;
- C smoke test passes offline and online: real LOTL refresh over verified TLS, concurrent with 160 validations
  on 4 attached threads, plus the trust-store override and small-heap checks.

## Phase 4: Rust crates

Workspace in `rust/`, edition 2024, toolchain pinned to **1.99.1** (`rust/rust-toolchain.toml`).

Crate versions (crates.io `max_stable_version`, looked up 2026-10-28):

| Crate | Version |
|---|---|
| bindgen | 0.73.2 |
| serde | 1.0.229 |
| serde_json | 1.0.154 |
| thiserror | 2.0.21 |
| clap | 4.6.7 |
| tokio | 1.54.1 (optional) |

- **`dss-sys`: bindgen at build time** over `libdssnative.h` from `build/native/<os>-<arch>/`, or from
  `DSS_NATIVE_LIB_DIR`. This keeps the bindings in step with the library they link. It needs libclang (Xcode
  Command Line Tools on macOS; `libclang-dev` on Linux).
  - `links = "dssnative"` publishes the directory as `DEP_DSSNATIVE_LIB_DIR`.
  - rpath: `dss-sys` and `dss` add the build directory to their own test binaries. `dss-cli` adds
    `@executable_path` / `$ORIGIN`, `…/../lib` and, for development, the build directory. Applications choose
    their own rpath.
- **Header bug found by bindgen:** `libdssnative.h` used `size_t` without including `<stddef.h>`. It only
  compiled after another header, which the C smoke test happened to have. `DssLib` now declares a custom
  `@CHeader` whose preamble includes `<stddef.h>` and `<graal_isolate.h>`; a custom header loses the
  generator's own include of the latter. `smoke-test-c.sh` now compiles a file that includes the header
  first.
- **`dss::Engine` thread model.** User threads never attach to the isolate, so there are no attachments to
  leak and teardown never blocks on a user thread.
  - A *control* thread creates the isolate, runs `dss_init`, serves status/version and finally tears down.
  - *N validation workers* (default 1, `EngineBuilder::workers`), each attached once, share a job queue.
  - A *refresh* thread runs online refreshes, so a refresh never takes a validation worker.
  - Calls are blocking, with a reply channel per call. Documents are copied into the job; that copy is
    negligible next to validation.
  - `refresh_trusted_lists` returns `RefreshInProgress` immediately if one is running, mirroring the library.
  - `Drop` closes the queues, joins workers and the refresh thread (so it waits for a running refresh), then the
    control thread calls `dss_shutdown` and `graal_tear_down_isolate`.
- **GraalVM CE 25.4 isolate bug (workaround in `dss`).** If the *first* `graal_create_isolate` of a process
  fails, every later `graal_create_isolate` in that process hangs, spinning inside the library. The trigger
  here was an invalid runtime option such as `-Xmx-nonsense`. Reproduced in plain C
  (`docs/native-library.md`); a later failure after a successful creation is harmless.
  - Workaround: before the first engine, `dss` creates and tears down one isolate without options (`OnceLock`,
    once per process).
  - Found because the Rust suite hung when the invalid-option test ran in parallel with the others.
  - Worth reporting upstream (not done: it would be a public post).
- **Typed results.** Results deserialize into structs (`Reports`, `SignatureSummary`, `TrustedListStatus`, …).
  Unknown enum values map to `Unknown` and unknown fields are ignored, so newer libraries stay readable.
  `Engine::validate_json` gives the raw JSON.
- **`schedule::RefreshScheduler`** (feature `tokio`): an interval plus `refresh_now()` and a `watch` channel of
  outcomes. Refreshes run through `spawn_blocking` on the engine's refresh thread. A manual refresh restarts
  the period. The core API stays runtime-agnostic.
- **`dss-cli`.**
  - Commands: `validate`, `tl refresh`, `tl status`, `version`. Global flags build `config_json`, or `--config`
    takes a full one.
  - Exit codes: 0 = everything `TOTAL_PASSED` / lists loaded, 1 = not, 2 = error.
  - The OJ keystore is taken from `--oj-keystore`, `DSS_OJ_KEYSTORE`, next to the executable, or
    `trust/oj-keystore.p12`.
- **Tests** (`rust/dss/tests/`), against the real library. The default set needs only the committed fixtures:
  no trusted lists, the synthetic root as `extra_trusted_certificates`, embedded revocation.
  - **Refresh concurrency:** a TCP server on 127.0.0.1 accepts and never answers, so a refresh lasts until the
    response timeout. Validations run during it, and a second refresh gets `RefreshInProgress`.
  - Also covered: heap limit (64 MB heap, 128 MB document → `InternalError`, engine still usable), invalid
    isolate option, several engines at once, repeated create/drop, the scheduler.
  - `synthetic_*` (a seeded synthetic TL cache) and `online_*` (real LOTL) tests are `#[ignore]`d and run by
    `scripts/test-rust.sh [--online]`.
- **Trusted-list thread pool:** new `tl_threads` config, default = number of CPUs, at most 16. Loading from the
  cache re-validates every list's signature. With the earlier fixed pool of 4, a full-LOTL cold start took
  ~11 s; with 15 threads it takes ~7.6 s.

### Cold-start measurements (macOS aarch64, release `dss-cli`, native library at `-O2`)

| | Native (`dss-cli tl status`, cold process) | JVM, same engine (HotSpot) |
|---|---|---|
| Full LOTL (32 lists, 4,904 certificates) from cache | **7.6 s** | 6.5 s cold, 3.8–4.4 s warm |
| IT only (LOTL + IT) from cache | **4.1 s** | — |
| One validation (PAdES B-LTA) | ~30 ms | — |
| Online refresh, full LOTL | ~15 s | ~15 s |

Notes on these numbers:
- Most of the time is the LOTL and its pivots, validated sequentially, plus the largest national list (DE,
  5.4 MB), which bounds the parallel phase.
- GC is about 12% of the cold start.
- `-O3` was tried: about 10% faster, but the library grows from 85 MB to 145 MB. Not adopted.
- Acceptance ("cache-loaded TLs within seconds of a cold start"): met. It is single-digit seconds, comparable to
  a cold JVM.

## Phase 5: differential testing

`scripts/diff-vs-jvm.sh` runs every fixture, and every document in `testdata/private/`, through **plain DSS on
the JVM** and through **Rust → libdssnative**. Per signature, at every nesting level, it compares:
- indication and sub-indication;
- signature level and qualification;
- claimed signing time;
- signer DN.

Any difference, or any native-only failure in the native log, exits 1. Reports go to `build/diff/<set>.md`.

- **The reference is plain DSS, not the engine.** `diff/PlainDssReference` (test scope) uses DSS as the
  cookbook does:
  - `SignedDocumentValidator.fromDocument` and `ServiceLoaderPdfObjFactory`;
  - its own `TLValidationJob` reading the same cache directory;
  - its own `CommonCertificateVerifier`;
  - certificates read with `CertificateFactory`.

  Only `EngineConfig` (to read the same `config_json`) is shared. dss-native's deliberate behaviours are
  re-implemented independently, so a difference means a bug, not a design choice: signature-checked TL sync,
  visual comparison off, base64/PEM decoding, nested `.p7m` unwrapping.
- **Same inputs on both sides:** the same config, the same cache, and the same `validation_time` (the run's
  start), so time-dependent checks agree.
- **Two sets of documents:**
  - Fixtures: a cache seeded from the synthetic trusted lists (`SyntheticCacheSeeder`), embedded revocation
    only, so there is no network. B/T fixtures are therefore INDETERMINATE on both sides, which is still
    compared.
  - Private documents: `testdata/private/config.json` if present, otherwise the real EU LOTL with online
    revocation, cached in `build/diff/real-cache` (filled online once). Detached signatures follow the
    `X` + `X.p7s` convention.
- **New result field `signer_dn`** (signing-certificate subject, RFC 2253, from DSS's diagnostic data) in Java,
  JSON and Rust, because the brief asks to compare the signer DN. The simple report's `SignedBy` is only a
  display name.
- **New `dss-cli validate-batch --cases F [--validation-time T]`:** one engine, documents validated in parallel,
  one JSON line per case in input order.
- **Cases are matched by position**, with a file-name check. The first run reported "differences" on the
  detached signature: the same file appears in three cases (no content, content, tampered content), and keying
  by file name had mixed them up. A harness bug, fixed.
- **The native log is checked too.** The first clean run still printed an `UnsupportedCharsetException`:
  PDFBox's parser asks for `Windows-1252`, which Native Image does not include by default, and silently falls
  back to ISO-8859-1. The verdicts agreed, but PDF name decoding differs from the JVM for some bytes.
  - Fixed with **`-H:+AddAllCharsets`** in `native-image.properties`: +5.4 MB, not experimental.
  - The script now fails on native-only failure signatures in the native run's stderr
    (`Missing*RegistrationError`, `UnsupportedCharsetException`, `UnsupportedFeatureError`,
    `UnsatisfiedLinkError`, `NoClassDefFoundError`). Libraries catch and log these, so verdicts alone can
    hide them.
- **Checks of the checker:**
  - `OutcomeTest`: every compared field, the signature set, nesting and rejections each produce a difference;
  - `PlainDssParityTest`: plain DSS against the engine on the JVM, 22 cases, in the normal test run;
  - a negative control: one corrupted native verdict was reported, and the tool exited 1;
  - the private-documents path was exercised with temporary copies of fixtures.
- **Metadata.** Running the parity test in the native test image needed DSS's `fromDocument` lookups:
  `DocumentValidatorFactory`, `EvidenceRecordAnalyzerFactory` (absent), the `IPdfObjFactory` services. They
  are now in the library metadata, so the library also works if DSS takes that path internally.

Result: fixtures, 24 documents / 25 signatures, **0 different**, with a clean native log. There are no real
documents in the repository; `testdata/private/` is for local runs.

Limitations:
- Synthetic fixtures do not exercise QES qualification (the test certificates are not qualified), and the
  fixtures set uses offline revocation. Real-world coverage comes from `testdata/private/`.
- With online revocation, each side fetches CRL/OCSP itself. The same validation time is used, but a responder
  could answer differently between the two fetches.

## Phase 6: CI and packaging

`.github/workflows/ci.yml` and the composite `.github/actions/setup`.

CI runs only when a GitHub release is published, or when started by hand. Pushes and pull requests run nothing.

| Trigger | Jobs |
|---|---|
| Published release, manual | `build` on **linux-x64** (`ubuntu-24.04`), **linux-aarch64** (`ubuntu-24.04-arm`), **macos-aarch64** (`macos-15`). Full chain: JVM tests → native tests (exact metadata, then `Exit` mode) → shared library → C smoke → Rust fmt/clippy/tests → differential test → package |
| Manual with `online=true`, published release | `online` on linux-x64: JVM `-Pintegration`, `smoke-test-c.sh --online`, `test-rust.sh --online`, and the **seed TL cache snapshot** (full LOTL via `dss-cli tl refresh`, tarred `tl/` + status JSON) |
| Published release | `release-assets`: `gh release upload --clobber` of every platform package, the seed cache and the OJ keystore to that release (only `GITHUB_TOKEN`, no third-party action). |

- **Version: the release tag.** `v1.2.3` makes 1.2.3 the version of the library (`dss_version`), the crates,
  `dss-cli` and the package names. `plan` rejects a tag that is not `v` + a semantic version, before any
  build. Each building job then stamps the version into `java/pom.xml` and `rust/Cargo.toml` with
  `scripts/ci/set-version.sh`, after the setup step, whose Maven cache key hashes the committed pom. The
  committed files only hold the placeholder `0.0.0-dev`, which every non-release build reports.
- **Cost on a private repository.** `gsguglielmo/dss-rust` is private. GitHub-hosted minutes beyond the plan's
  free allowance are billed, and macOS minutes count 10×. Arm64 Linux standard runners became available to
  private repositories on 2026-01-29 (2 vCPU / 8 GB, counted against the free minutes). A run takes about
  25 minutes per platform, mostly the two native-image builds, so a 3-platform run uses roughly 300 included
  minutes. Hence CI runs on releases only (and by hand), never on pushes or pull requests. With a spending
  limit of $0 (GitHub's default), jobs stop instead of incurring charges. The build itself uses only free
  tools.
- **Runner sizes.** Private-repository standard runners: Linux x64 and arm64 2 vCPU / 8 GB, macOS arm64
  3 vCPU (M1) / 7 GB (GitHub's runner reference, checked 2026-10-28). native-image peaks at ~4.4 GiB RSS per
  image and uses ~10 CPU-minutes for both images, so they suffice, without much headroom on macOS.
- **Pinned inputs.**
  - GraalVM CE `graal-25.4.4.1.1` is downloaded by `scripts/ci/install-graalvm.sh` and checked against SHA-256
    values written in the script (bash 3.2 compatible for macOS).
  - The Maven wrapper distribution has its checksum in the wrapper properties.
  - The Rust toolchain comes from `rust/rust-toolchain.toml` (1.99.1, with clippy and rustfmt).
  - GitHub actions are pinned to commit SHAs: checkout v7.0.1, cache v6.1.0, upload-artifact v7.0.2,
    download-artifact v8.0.2.
  - `libclang-dev` is installed for bindgen on Linux; macOS uses the Command Line Tools.
- **`scripts/package.sh`** produces `dist/dss-native-<version>-<platform>.tar.gz` (+ `.sha256`):
  - `lib/`, `include/`, `bin/dss-cli`, `share/dss-native/oj-keystore.p12`;
  - licences, README, `native-library.md`;
  - a `SOURCE` file with repository and commit, for the LGPL rebuild path.

  The CLI is rebuilt with `DSS_RELEASE_RPATH_ONLY=1`, so its rpath is only `@executable_path` / `$ORIGIN` and
  `…/../lib`, with no build-machine path. The script runs the packaged CLI once to prove the package works on
  its own.
- **Reports:** `build/diff/*.md`, surefire and native test reports are uploaded on every run, failed or not.
- **Verification before any push** (nothing was pushed: commits and pushes are left to the owner):
  `actionlint` 1.7.12 (built from source) reports no problems. The Linux jobs were rehearsed in containers and
  the macOS job on the development machine (below). The workflow itself has not run on GitHub yet.

### Rehearsal (2026-10-28)

The build job's commands, unchanged, in `ubuntu:24.04` containers (Docker on the development Mac, 4 CPUs),
with GraalVM downloaded fresh and checked against the pinned SHA-256. linux-aarch64 ran natively, linux-x64
under emulation (Rosetta). macos-aarch64 ran on the development machine (macOS 27).

The Docker VM has 8 GB, shared with other containers. Emulated x64 native-image, sizing its heap to 85 % of
the container, was killed twice for lack of memory. The final x64 run therefore used `--memory 5g` and
`NATIVE_IMAGE_OPTIONS=-J-Xmx3500m`. That is tighter than a GitHub runner (8 GB, nothing else running), so it
says nothing bad about CI.

What it found, all fixed:

| Finding | Fix |
|---|---|
| Without `unzip`, the Maven wrapper downloads the `.tar.gz` distribution, whose checksum differs from the pinned `.zip` one, and fails | `unzip` in the setup action |
| native-image links with `-lz` | `zlib1g-dev`, a documented native-image prerequisite |
| **Linux: opening a PDF aborted, then crashed, the process** (the JDK's libawt) | Ship no AWT library on any platform, see "PDFBox and the JDK's libawt" |
| The packaged CLI's rpath contained the build machine's library directory | `DSS_RELEASE_RPATH_ONLY=1` in `package.sh` |
| **macOS: the library required the build machine's macOS** (`minos 27.0`) | `-mmacosx-version-min=14.0`, see "Binary compatibility" |

Final runs, after every fix:

| | linux-aarch64 | linux-x64 (emulated) | macos-aarch64 |
|---|---|---|---|
| `build-native.sh --with-tests` | 4:12 min | 7:32 min | 2:00 min (15 cores) |
| native-image, test image / library | 2 min 14 s, 4.40 GiB / 1 min 30 s, 3.86 GiB | 3 min 30 s, 4.20 GiB / 3 min 21 s, 3.79 GiB | 51 s, 4.39 GiB / 52 s, 4.15 GiB |
| Native tests, exact metadata and `Exit` mode | 83/83, 83/83 | 83/83, 83/83 | 83/83, 83/83 |
| C smoke (Linux with `DISPLAY=:0`): 4 isolates at once, then 80 validations on 4 threads | 0 failures | 0 failures | 0 failures |
| Rust fmt, clippy, tests (engines in parallel) | clean, 17 passed | clean, 17 passed | clean, 17 passed |
| Differential, fixtures | 24 documents, 25 signatures, 0 different | same | same |
| Differential, private documents | none in containers (never copied) | none | 3 documents, 3 signatures, 0 different |
| glibc / macOS floor (`package.sh` check) | 2.34 | 2.34 | 14.0 |
| `libdssnative` | 91.9 MB | 92.9 MB | 91.4 MB |
| Package (`.tar.gz`) | 35.1 MB | 35.3 MB | 35.3 MB |

### PDFBox and the JDK's libawt

- Opening a PDF runs PDFBox's `PDDocument` static initializer. It starts with
  `Raster.createBandedRaster(…)` inside `try … catch (IOException | UnsatisfiedLinkError)`, a workaround for an
  old JIT bug. `Raster`'s own initializer loads the JDK's `libawt`.
- On macOS that load had always failed quietly: libawt is not linked into the image, nor shipped next to it.
  PDFBox caught the `UnsatisfiedLinkError`, and nothing in validation needs AWT. The differential test, which
  includes the real documents, gives the same verdicts as plain DSS.
- On Linux, the first rehearsal ran the native **test** executable from `java/target`, where native-image had
  written `libawt.so`. libawt's `JNI_OnLoad` called `GraphicsEnvironment.isHeadless()` through JNI. The agent
  had only run on macOS, so the image had no JNI registration for it. `FindClass` failed, libawt called JNI
  `FatalError`, and the process aborted. No `catch` stops a JNI fatal error.
- The first fix shipped the JDK libraries next to `libdssnative.so` on Linux. The linux-x64 rehearsal then
  segfaulted in the Rust tests, where several engines (isolates) open their first PDF at the same time.
  - libawt is written for one JVM per process. It keeps process-wide state (`JNIEXPORT JavaVM *jvm`, a static
    `awtHandle`). `AWT_OnLoad` stores the loading isolate's VM in `jvm`, then gets the thread's `JNIEnv` through
    it. A concurrent first load by another isolate swaps `jvm` in between: `GetEnv` returns NULL, and
    `AWTIsHeadless` dereferences it.
  - Reproduced in C with 4 isolates each validating a PDF: a crash in 3 runs out of 3 under emulation, and 0
    out of 3 after one PDF has been validated first. Natively on arm64, 8 isolates did not hit the window in 5
    runs. The race is real, just narrow.
  - A process-wide mutex around the first load (a small C object linked into the image) was prototyped and
    dropped: not loading libawt at all removes the hazard with less machinery.
- **Decision: no AWT library is shipped on any platform**, as on macOS from the start. Kept as defence in depth:
  - `RuntimeDefaults` sets `java.awt.headless=true`, so a libawt found anyway never selects X11 because of a
    `DISPLAY`;
  - the `isHeadless` JNI registration, recorded by running the agent on Linux (`ubuntu:24.04` arm64
    container); the union merge added that single entry. The native test executable still finds libawt next
    to itself. The shipped library looks for it next to itself, then on Linux in `/usr/lib64`, `/lib64` and
    `/usr/lib` (seen with `LD_DEBUG`), where distributions do not put the JDK's copy.
- Guards:
  - the C smoke test starts by validating PDFs from 4 isolates at once, before anything else in the process;
  - the Rust suite runs engines in parallel;
  - the rehearsal runs the C smoke test with `DISPLAY=:0`;
  - `LD_DEBUG=files` on the packaged linux-aarch64 CLI: validating a PDF loads `libdssnative`, `libc`, `libz`
    and `libgcc_s`, nothing else.

### Binary compatibility

| Platform | Requires | Why |
|---|---|---|
| Linux | glibc ≥ 2.34; `libz.so.1`; `libgcc_s.so.1` (CLI) | Linking against glibc ≥ 2.34 binds `pthread_*`, `dlsym` and `__libc_start_main` to their `GLIBC_2.34` versions (libpthread was merged into libc). Building on ubuntu-22.04 (glibc 2.35) would not lower the floor, so 24.04 stays. Ubuntu 22.04+, Debian 12+ and RHEL/Alma/Rocky 9+ qualify |
| macOS | 14.0, Apple silicon | The deployment target of GraalVM CE's own C libraries (`lib/svm/clibraries`), set with `-mmacosx-version-min` in the `native-os-mac` profile. Without it, the linker recorded the build machine's version. The CLI keeps Rust's default (11.0) but needs the library anyway |

`package.sh` fails if a build raises either floor (`objdump -T` / `otool -l`).

The linux-aarch64 package ran in bare `ubuntu:24.04` (glibc 2.39) and `almalinux:9` (glibc 2.34, the floor)
containers: no Java, `--network none`, `DISPLAY=:0`, `LANG=it_IT.UTF-8`. It ran `dss-cli version` and three
validations with the same verdicts as plain DSS: PAdES LTA passed; CAdES B indeterminate, as expected without
trusted lists or revocation data; tampered PAdES failed with `HASH_FAILURE`. macOS 14 itself was not tested.

### `dss-cli` into a closed pipe

`dss-cli validate doc.pdf | head` panicked ("failed printing to stdout: Broken pipe"), because `println!` panics
on any write error and Rust ignores `SIGPIPE`. The CLI now writes through an `out!` macro. Output into a closed
pipe is dropped, and the exit status still reports the verdict (0 passed, 1 not). Other write errors exit
with 2. Restoring the default `SIGPIPE` action instead could let a reset TLS connection in the library's
downloads kill the process. `rust/dss-cli/tests/cli.rs` runs `validate` with stdout closed: exit 0 for a
passing document, 1 for a tampered one, no panic.

## After Phase 6: PAdES signature extension (2026-10-28)

`dss_extend` (Java `DssEngine.extend`, Rust `Engine::extend`, `dss-cli extend`) raises every signature of a
PDF to PAdES-BASELINE-T, -LT or -LTA with DSS's `PAdESService.extendDocument`. The output is the input PDF
followed by an incremental update.

- **The document comes back through out-parameters, not as base64 in the JSON.** It is the one large output.
  Base64 would make it a third larger and add a second copy inside the JSON string. `*out_document` is
  malloc'd, released with `dss_free`, and set to `NULL` (and `*out_len` to 0) unless the result is
  `"ok":true`. The entry point copies it from the Java array into malloc'd memory, so the rule "allocate
  nothing large on the Java heap in the entry point" still holds. The smoke test checks a 128 MB input on a
  64 MB heap.
- **`options_json` names a level, not a format.** `"level": "T" | "LT" | "LTA"`, and the format follows the
  document. CAdES could be added later without changing the contract. For now CMS input is
  `UNSUPPORTED_DOCUMENT`: detached content and `.p7m.p7m` nesting would need their own design.
- **DSS's default `CertificateVerifier` alerts are kept.** DSS throws on an invalid signature or timestamp; a
  revoked, expired or not-yet-valid certificate; missing revocation data; and a signature already above the
  target level. It only logs when there is no revocation data after the best signature time, or uncovered
  POE. Everything it throws maps to the new code **`EXTENSION_FAILED`**, with DSS's message.
- **`revocation: "offline"` applies to extension too.** Then only data already in the document counts
  (LT→LT and LT→LTA work, T→LT is refused), in line with "never contact CRL/OCSP servers".
- **The TSA is engine configuration** (`tsa.url`), not a per-call option, like the other servers. It uses
  DSS's `TimestampDataLoader` with the same timeouts and trust store as CRL/OCSP. Optional HTTP Basic
  credentials (`tsa.username`/`tsa.password`, both or neither) are sent **preemptively**: one POST instead of
  401 and a retry. Many qualified TSAs require credentials.
- **No TSA means a clear error, decided by DSS.** When `tsa.url` is unset, a stand-in `TSPSource` fails with
  "no TSA is configured" when DSS asks for a timestamp. There is no pre-check by level, because whether a
  timestamp is needed depends on the document: B→LT needs one, T→LT does not.
- **No "changed" flag in the result.** DSS appends a revision even when it has nothing new: LT→LT on the
  fixture goes from 26,428 to 31,760 bytes. T→T adds another document timestamp.
- **Base64/PEM input** is decoded as for validation. The result is the decoded PDF, extended, and
  `transformations` says so.
- **Tests.**
  - `ExtensionTest`: every level from B, T, LT and LTA. Each result is re-validated, also by an engine that
    fetches no revocation data, so it passes only on what was embedded. It also covers the refusals and option
    and config parsing.
  - The in-memory test TSA, `TestPki.timestampResponse`, issues RFC 3161 responses from the test PKI.
  - `HttpsLoopbackTest` adds a TSA over HTTPS behind Basic auth.
  - `DssJsonApiTest` checks that the document is handed back only on success.
  - The C smoke test, the Rust engine tests and the CLI test cover the out-parameters, concurrency and exit
    codes.
- **Metadata.** The agent run over the new tests added only the test classes' JUnit methods. The library's
  extension path (`PAdESService`, PDFBox incremental save, `OnlineTSPSource`, BouncyCastle TSP, HttpClient
  Basic auth) needed no new registration. The native test suite passes with exact metadata in `Exit` mode.

## After Phase 6: signing with an external signer (2026-10-28)

`dss_sign_prepare` and `dss_sign_complete` (Java `DssEngine.prepareSignature`/`completeSignature`, Rust
`Engine::prepare_signature`/`complete_signature`, `dss-cli sign prepare|complete`) create CAdES and PAdES
signatures whose key is held elsewhere: a remote signing service, an HSM, a smart card. DSS builds the document;
the signer only sees a digest. The logic is in `ExternalSigning`.

- **Two stateless steps, not a session.** `prepare` returns the digest; `complete` gets the same document and
  options again, plus the signer's output, and redoes `prepare`'s work before building anything. Nothing is held in
  the engine between the calls. External signing can take minutes (user confirmation, a second factor, queues),
  and the two steps may run in different processes. A session table would need expiry, limits and an answer to
  "what if the process restarts". This is DSS's own remote-signing pattern (`getDataToSign` and `signDocument` on
  separate requests with the same parameters).
- **The signing time is the only value the caller carries over.** `prepare` picks it (now, in whole seconds) unless
  one is given, and returns it; `complete` requires it. For PAdES the prepared PDF follows from the options, the
  signing time and the document name (DSS derives the document ID from them), so `complete` prepares the same
  bytes. Nothing comes from the host: the signing date in the signature dictionary is written in UTC. DSS would
  otherwise use the host's time zone, so prepare and complete on hosts in different zones would build different
  PDFs; the first CI run, in UTC against fixtures made in Europe/Rome, failed on exactly that. The tests check
  that the native library reproduces, byte for byte, what the JVM prepared when the fixtures were made.
- **Two modes, by what the signer returns.**
  - `"cms"`: it gets the content's digest (PAdES: the ByteRange digest, from `PAdESWithExternalCMSService`) and
    returns a whole detached CMS, possibly with its own signature timestamp.
  - `"signature_value"`: it gets the digest of the signed attributes DSS built (`getDataToSign`) and returns the
    bare signature value; `signDocument` builds the CMS around it.

  Signers come in both shapes, and neither covers the other: a CMS-returning signer cannot be driven through
  `signature_value`, and a bare signer cannot produce a CMS.
- **The external result is checked before anything is built, with reasons a caller can act on.** DSS's own
  checks (`isValidCMSSignedData`, `CMSForPAdESBaselineRequirementsChecker`) only log why they fail.
  - `"cms"`: one signer; detached; the expected digest algorithm; content-type `id-data`; message-digest equal to
    the digest `complete` recomputed; signing-certificate(-v2); the signer's certificate inside, and equal to
    `signing_certificate` when one is given; the signature verifying (DSS's `CAdESSignature` over a
    `DigestDocument`).
  - signing-time is **refused for PAdES**, where `/M` holds the time (PAdES baseline forbids the attribute), and
    **required for CAdES** (CAdES-BASELINE-B requires it). A signer that adds signing-time by default must be asked
    not to for PAdES. The message says so.
  - `"signature_value"`: DSS's `isValidSignatureValue` against the rebuilt data to be signed. `signDocument` does
    not verify the value itself, and would embed a wrong one.

  A mismatch between the two calls (another signing time, filename or `pades` entry) shows up here as
  `SIGNING_FAILED` "not this document's digest", not as a broken PDF.
- **Accepted encodings.** A CMS may be DER, BER with indefinite lengths (common from streaming encoders), base64
  or PEM; it is re-encoded as DER, which PAdES requires and DSS's verification assumes. A signature value may be
  raw or base64. For ECDSA keys both DER and `r||s` are accepted: signers differ, and DSS converts.
- **`/Contents` size depends on the mode.** In `"signature_value"` mode DSS builds the CMS and its default (9,472
  bytes) fits. In `"cms"` mode the signer's CMS may carry its whole chain and a timestamp: 16 KB is realistic. The
  size is fixed at `prepare`, and a CMS that does not fit is lost along with the signature spent on it. So the
  default there is 32,768 (`pades.content_size` overrides both), and `complete` reports an oversized CMS before DSS
  does.
- **Levels.** B is what the signer delivers. Above it, DSS adds what is missing, with the engine's own TSA and
  revocation sources, as for `dss_extend`. In `"cms"` mode `PAdESWithExternalCMSService.signDocument` embeds and
  then extends, and skips T when the CMS already has a signature timestamp; CAdES follows the same rule via
  `CAdESService.extendDocument`. A timestamped CMS asked for at B is reported as T, the level it has.
- **Trusted lists only where they matter.** `prepare` and B/T `complete` need none: nothing is validated against
  trust anchors. LT and LTA collect validation data along the chain and follow `require_trusted_lists` like
  validation.
- **`prepare` refuses an expired or not-yet-valid signing certificate** (DSS's default `CertificateVerifier`
  alerts at `getDataToSign`), so no external signature is spent on a document `complete` would refuse. In
  `"cms"` mode the certificate is only known from the result.
- **CAdES signs the bytes given.** `parallelSignature` is off: a `.p7m` given as content becomes a `.p7m.p7m`
  instead of gaining a co-signer, the same in both modes (a CMS-returning signer cannot co-sign anyway).
  Enveloping in `"cms"` mode puts the content into the detached CMS's `encapContentInfo`; the signature covers
  the signed attributes, which hold the content's digest, so it stays valid.
- **One new error code, `SIGNING_FAILED`.** It covers an unusable external result, an invalid certificate at
  `prepare`, and DSS failing to add a level (no TSA, revocation missing). These all mean "this signature cannot be
  completed as asked", and the message says which. Malformed options stay `INVALID_ARGUMENT`.
- **C API.** `dss_sign_complete` takes the signer's output as a second buffer, not base64 inside `options_json`,
  and hands the document back through out-parameters like `dss_extend`. `DssJsonApi.Extended` became
  `DocumentResult`, shared by both.
- **Not done.** XAdES/JAdES/ASiC signing, co-signing and counter-signing, and RSASSA-PSS signature values (RSA
  keys are PKCS#1 v1.5). Visible appearances came next, see "Visible signatures".
- **Tests.**
  - `SigningTest` uses `ExternalSigner`, a test stand-in for a signer that holds a test-PKI key and only sees
    digests. It covers both modes, both formats, every level, detached and enveloping, RSA and ECDSA (DER and
    `r||s`), BER and base64 input, and every refusal. Each result is validated again, LT and LTA also without
    fetching revocation data.
  - `testdata/fixtures/signing/` records four cases (options with a fixed signing time, plus the signer's
    output). The Rust tests, the CLI test and the C smoke test complete them through the shared library.
  - Metadata: see `reflection-audit.md`. The only new library entry is DSS's `CMSGenerator` service provider.

## After Phase 6: visible signatures (2026-10-29)

`pades.visible` in the signing options draws a visible appearance: text, a PNG or JPEG, or both, in a new field
(page and box) or in an empty signature field of the PDF. README.md, "Visible signatures", has the contract.

- **Our own drawer, not DSS's.** DSS 6.5.1's `NativePdfBoxVisibleSignatureDrawer` needs AWT in three places, and
  the shipped library has no libawt, liblcms or libjavajpeg (see "PDFBox and the JDK's libawt"):
  - every visible signature on a PDF without an output intent, which is most PDFs, adds an sRGB one through
    `ICC_Profile.getInstance(CS_sRGB).getData()`, and `new PDOutputIntent` parses it again: both LittleCMS;
  - images go through ImageIO for their size and resolution (`ImageUtils`, from the field-size builder), then
    through `PDImageXObject.createFromByteArray`, which uses ImageIO for every JPEG and for grayscale or
    transparent PNGs;
  - `DSSFont.getJavaFont()` is `java.awt.Font`, whose initializer loads libawt (reached for anything but
    `DSSFileFont` and `PdfBoxNativeFont`).

  `java.awt.Color` is fine: on JDK 25 it loads no native code (DSS uses it for every signature, visible or not).
- **What is ours and what is DSS's.** `AwtFreePdfObjFactory` extends `PdfBoxNativeObjectFactory` and overrides
  `getSignatureDrawerFactory()`. `AwtFreeSignatureDrawer` implements DSS's `PdfBoxSignatureDrawer` and
  `SignatureFieldBoxBuilder` directly, so DSS still does the rest: the signature field and widget, filling an
  existing field, merging the appearance into the PDF (`SignatureOptions.setVisualSignature`), the overlap check
  for new fields, permission checks, the document ID and the incremental save.
  - Images (`SignatureImage`): a JPEG goes in as `DCTDecode`, with its size and components read from the frame
    header; a PNG is decoded by `PngDecoder` (every colour type and bit depth, `tRNS`) into 8-bit samples and an
    alpha soft mask, Flate-compressed at a fixed level. A test compares the decoder with ImageIO sample by
    sample, on the JVM.
  - Colour (`SrgbProfile`): the sRGB output intent's ICC v2 profile is built byte by byte (primaries, white
    point, the sRGB curve as a 1024-entry table computed with `StrictMath`). No third-party file, the same bytes
    everywhere; on the JVM, LittleCMS reads it and maps colours like the JDK's sRGB within 0.01 in XYZ.
  - Text: PDFBox's `PDType0Font` and FontBox, which are plain Java, with the caller's TTF or DSS's default PT
    Serif from the dss-pades jar (now registered as a resource), embedded as a subset.
- **Our own layout, simpler than DSS's.** DSS's `SignatureFieldDimensionAndPositionBuilder` needs the image
  through ImageIO, and its model (zoom also scaling the text, DPI from image metadata, auto-sized boxes) is more
  than a box needs. Ours: an explicit box (or the field's), a 3-point margin, an image beside the text at most
  half the box and in its aspect ratio (or behind the text), text wrapped at spaces and shrunk from `font_size`
  by 5% steps until it fits. One code path for all cases, documented in README.md.
- **Coordinates are what the reader sees.** `x`/`y` are from the top-left of the page as displayed: on a page
  with `/Rotate`, the box is mapped to user space and the content is drawn turned back, so it reads upright
  (DSS's `AUTOMATIC` rotation, as the default). The page area is the crop box. For an existing field, our code
  finds its page (`/P`, else by scanning the annotations) and tells DSS: DSS otherwise takes page 1 for the
  page size and rotation.
- **Checked before anything is signed.** Options are parsed and checked at `prepare` (image decoded, font
  loaded, template parsed), and the page, box and field are resolved against the PDF before DSS runs (one
  extra parse of the PDF), so mistakes are `INVALID_ARGUMENT` with the caller's terms. DSS's overlap check
  throws our error through a custom `StatusAlert`. A character the font cannot show is an error.
- **Placeholders are filled by the library** (`{signer_name}`, `{signing_time}`, `{reason}`, `{location}`), so
  the date shown is the signing time of the signature even when `prepare` picks it. `{signing_time}` uses
  `time_zone` and a `java.time` pattern, with English names (the library has the US locale only).
- **Prepare and complete draw the same bytes.**
  - Everything drawn follows from the options and the PDF. The font subset tag is a hash of the glyphs used;
    the image and ICC streams are compressed at a fixed level; float arithmetic is the same on every JVM and in
    the native image.
  - DSS seeds the encryption of an encrypted PDF (`PdfBoxSignatureService.buildSeed`) with
    `imageParameters.toString()`, whose default includes identity hash codes. `VisibleImageParameters` overrides
    `toString()` with a SHA-256 of the appearance, so an owner-password PDF signed visibly in two processes
    gets the same revision. A test prepares it in two engines.
  - The spike before the build-out compared digests from the JVM and from the shipped library on macOS: equal
    for text, a transparent PNG and a JPEG. The signing fixtures `pades-visible-cms` and
    `pades-visible-field-signature-value` keep checking it on every CI platform: the Rust tests, the CLI test and
    the C smoke test complete them through `build/native/…`, which has no AWT library.
- **Fixtures.** `FixtureGenerator` adds `content/form.pdf` (an empty signature field `Firma1` and a text field),
  `content/rotated.pdf` (`/Rotate 90`), `content/protected.pdf` (owner password, empty user password) and
  `content/stamp.jpg`. `--signing-only` writes them only when missing, as the signing fixtures depend on them.
  Test PNGs are encoded in the tests (`TestImages`), so the native tests need no ImageIO.
- **Metadata.** The visible path needed no new registration beyond the default font, now in `DssFeature`'s
  resource globs. The agent run did record ImageIO and colour-management entries, but only from the two
  JVM-only tests (`@DisabledInNativeImage`) that compare against them; `merge-metadata.py` drops those
  (`DROP_JVM_ONLY_TESTS`). The native test suite passes with exact metadata in `Exit` mode.
- **Not done.** Preview rendering (DSS's `previewPageWithVisualSignature` needs AWT), creating a named new
  field, CMYK JPEGs, interlaced PNGs, colour profiles inside images (taken as sRGB), automatic flattening of
  transparency for PDF/A-1, and right-to-left or complex-script text (no shaping: glyphs are laid out one by
  one).

## After Phase 6: HTTP sidecar (2026-11-03)

`dss-server` (new crate `rust/dss-server`, axum on tokio) serves one `dss::Engine` over HTTP. It is for clients
in other languages; the first one is a Laravel application on Octane with FrankenPHP. `php/DssClient.php` is its
client. API, options and deployment: [server.md](server.md).

- **A sidecar, not PHP FFI or a PHP extension.** All three can call the library. The in-process options lose
  in different ways:
  - Under PHP-FPM, each worker process would load its own copy of the trusted lists (4–8 s, a heap each) and
    refresh them itself. FFI cannot even keep the engine between requests.
  - Under FrankenPHP, every worker is a thread of one process. A Rust extension holding one `Engine` would work
    there, but then a native crash stops the whole server, not one request. The GraalVM runtime would also share
    the process with Go's runtime and its signal handlers, a combination nobody has tested.
  - An extension must be built for every PHP minor version, thread-safety mode and platform.

  The sidecar loads the lists once, survives the application's restarts and deploys as one binary per
  platform.
- **Multipart in, the library's JSON out.** The `options` part is the library's `options_json` and results pass
  through verbatim, so README.md's contract is also the HTTP contract. The only additions are the `detached`
  and `signature` parts.
- **Documents come back as the response body**, with the result JSON in a `Dss-Result` header, not as base64
  inside JSON. The reasoning is that of `dss_extend`'s out-parameters: base64 would make them a third larger.
  The result JSON is small, and anything non-ASCII in it is escaped, so it always fits a header.
- **`detached_contents[].path` is refused.** Over HTTP it would let a client make the server read any file it can
  read. Detached content arrives as `detached` parts and goes to the library as `base64`.
- **The upload's filename becomes `filename` only for `/validate` and `/extend`.** Signing passes its options
  untouched: the filename enters the prepared PDF, and a name the server added could differ between `prepare`
  and `complete`, changing the digest.
- **Listen first, then start the engine.** The port is open at once. `/health` answers 503 and the other
  endpoints `NOT_INITIALIZED` until the engine is up, so a container's health check and the client both see
  "starting" rather than "refused". If the engine fails to start, the process exits with status 2 and the
  orchestrator restarts it.
- **Refreshes** use `dss::schedule::RefreshScheduler`: every 6 hours by default, and at start only when nothing
  was cached. `POST /tl/refresh` answers 202 at once rather than holding a connection open for ~15 s;
  `/tl/status` reports the outcome. `Engine::trusted_list_status_json` was added so `/tl/status` passes the
  library's JSON through like every other endpoint.
- **Error codes map to HTTP statuses** (server.md, "Errors"). A signature that fails validation stays a 200
  result, as in the library. The server adds only `UNAUTHORIZED`, `NOT_FOUND` and `REQUEST_TOO_LARGE`.
- **Optional bearer token, read from a file.** An argument or environment variable would show up in `ps` and
  `docker inspect`. It is compared in constant time. There is no TLS: the server is meant for the same host or a
  private network.
- **`--health-check`.** The image needs no curl: the binary checks its own `/health`.
- **OpenAPI 3.1 description** in `docs/openapi.yaml`, written by hand from the library's contract.
  - **Embedded and served.** It is compiled into the binary and served at `/openapi.yaml` without a token,
    with `info.version` stamped from the binary. The file keeps the `0.0.0-dev` placeholder like every other
    committed file.
  - **Schemas.** Option schemas are closed (`additionalProperties: false`), because the library refuses unknown
    keys. Result schemas are open, because the library may add fields. Enumerated option values list the
    canonical spelling, though the library accepts any case.
  - **Documents** are binary bodies, with the `Dss-Result` header described as JSON content.
  - **Kept in sync.** `openapi_document_matches_the_router` sends every operation in the document to a server
    that has a token. Operations marked `security: []` must answer 200 and the rest 401: a 404 or 405 would
    mean the document describes a route the router does not have.
- **Packaging.** `scripts/package.sh` builds and ships `bin/dss-server` next to `dss-cli`, with the release-only
  rpath, and checks it starts from the package. `docker/dss-server/Dockerfile` builds the image from a Linux
  package on Debian slim, because the library needs glibc.
- **Tests.**
  - `tests/http.rs` runs the router in process (`tower::ServiceExt::oneshot`) against an offline engine. It
    covers validation (with detached parts), extension, both signing steps with the recorded fixtures, every
    error path, the token and the starting state.
  - `tests/process.rs` runs the binary. It checks that the port opens before the engine is ready, `--health-check`
    (also against 0.0.0.0), shutdown on SIGTERM, and exit status 2 when the engine cannot start.
  - By hand on macOS aarch64, against a live server: `php/DssClient.php` through Laravel's HTTP client (15 checks:
    validate, detached, nested, errors, extend, both signing modes, token), and 400 validations from 32 parallel
    clients (all 200, in 0.9 s). The process grew from 116 to 243 MB resident, with no trusted lists loaded.
  - By hand, `docs/openapi.yaml` passed Redocly's lint. Its only warnings: `/health` and `/openapi.yaml` have no
    4XX response, which is correct. A contract check then made 31 calls to a live server, with the real EU
    lists and the test root trusted. It checked every endpoint, the starting state, and the 400, 401, 409, 413,
    422 and 503 answers. Every status, content type, body and `Dss-Result` header matched the document (Ajv,
    JSON Schema 2020-12), and no response had a field the document lacks. Against a copy with one field removed
    and one type changed, the same check failed 7 calls.
  - By hand, the packaged server against the real EU LOTL, with an empty cache. The engine was ready in 127 ms,
    and the refresh at start completed in 9.7 s: 31 national lists, 4,905 trusted certificates, no alerts.
    `/tl/refresh` answered 202, and 409 when called again while that refresh ran. The process used 234 MB
    resident after the first refresh, 288 MB after the second, and 306 MB after a restart from the cache, which
    was ready in 7.5 s.
- **Not verified yet.** The Docker image built from a real Linux package: only its layout was checked, with a
  stand-in package.

## After Phase 6: licensing review before going public (2026-11-06)

- **Copyright holder: Coding Duck.** No file named one before. Every source file now carries
  `SPDX-FileCopyrightText: 2026 Coding Duck` next to its `SPDX-License-Identifier: LGPL-2.1-or-later`; Rust, PHP,
  shell, Python, the Dockerfile and the CI files had no header at all. `LICENSING.md` and the README say the same,
  and `java/pom.xml` names the organisation, URL and SCM. The licence stays LGPL-2.1-or-later, as DSS.
- **Release packages carry every third-party notice.** They shipped only `LICENSE` and `LICENSING.md`, while the
  library contains Apache-2.0 code with NOTICE files, MIT and BSD code whose licences ask for their copyright
  notice in binary distributions, the GPLv2 + Classpath Exception GraalVM runtime and an OFL font, and the
  executables contain MIT/Apache-2.0 crates. Now:
  - the pom's `third-party-licenses` execution (native profile) unpacks `META-INF/LICENSE*` and `NOTICE*` from
    every runtime jar but DSS's, which carry none;
  - `scripts/build-native.sh` adds the LGPL, `third-party/` (DSS, PT Serif with the OFL, Stax2 API, whose jar
    only links to its licence) and GraalVM CE's `LICENSE.txt`, `THIRD_PARTY_LICENSE.txt`, `legal/` and `release`
    (component source commits) into `build/native/<platform>/licenses/`;
  - `scripts/collect-rust-licenses.py` adds `licenses/rust/` in `scripts/package.sh`: the licence files of the
    crates linked into `dss-cli` and `dss-server` (normal dependencies for the host target, procedural macros
    excluded: 55 crates today) and the standard library's `COPYRIGHT-library.html`. It fails on a crate without
    a licence file;
  - `SOURCE` names the full commit, the DSS source tag and the GraalVM CE release.
- **Checked:** every runtime jar and crate is under a licence compatible with distributing the combined library
  and executables (Apache-2.0, MIT, BSD-2/3-Clause, EDL, Unlicense, OFL, GPLv2 + Classpath Exception). The
  `com.oracle.*enterprise*` module names in the GraalVM CE build are empty stubs (`module-info` only), so no
  Oracle GraalVM code is involved. The test fixtures are generated by the project's own code.

## After Phase 6: trusted-list snapshots (2026-11-06)

Asked for: start an engine fast where cold starts matter (e.g. AWS Lambda). Loading the lists from the cache
parses every list and validates its XAdES signature again, 3.8 s for IT and 6.5–32 s for the full EU list
depending on cores; the library itself starts in 60 ms. A trusted-list snapshot is the engine's resulting trust
pool in one file, written by `dss_tl_export_snapshot` and loaded by `dss_init` when `config_json` names it in
`tl_snapshot`. Measured natively on macOS aarch64 (M5 Pro): full EU list 0.63 s from a snapshot, against 6.5 s
from the cache; IT 0.10 s, against 3.8 s.

- **Trust is the application's decision, not the library's (asked; answered).** A snapshot holds trust anchors
  that nothing re-checks against the EU's signatures, so whoever can write one can make any certificate trusted.
  The user decided the library only exports and imports, and the application that stores and hands over a
  snapshot vouches for it (read-only deployment, its own hash or signature). No pinned hash or signature
  verification in the library.
- **What the library still checks** (`TL_SNAPSHOT_REJECTED`, failing `dss_init`, as the user asked for rejected
  snapshots; no fallback to the cache): layout and CRC-32C, format version, DSS version, and the trusted-list
  settings the pool depends on (LOTL and OJ URLs, the OJ keystore by a SHA-256 over its sorted certificate
  digests, countries as a set, TL versions, pivots, sunset dates, `tl_sync`). Mistakes, not attacks: the CRC
  catches a damaged file, not a forged one.
- **`tl_sync` is applied again at load time.** DSS decides at every load whether a list may be used, and refuses
  one past its next update when `accept_expired` is false. A snapshot that trusts a list a load from the cache
  would now refuse is rejected as a whole, so a snapshot never keeps trusting more than the cache would. With
  `accept_expired` true (the default) this cannot fire: signature validity does not change with time.
- **Format: Java serialization of DSS's own model, behind a header.** `TlSnapshotFile`: magic `DSSTLSNP`,
  format version, a JSON header (versions, creation time, `lists_loaded`, settings; readable without the
  payload), the payload, a CRC-32C trailer. The payload is what `TrustedListManager` already publishes after
  every load: trust properties and trust times per certificate, the job summary (which the status and the
  diagnostic data use) and the alerts. DSS's model classes are `Serializable`; a hand-written format would have
  to map every field, the qualifier condition trees included, and a forgotten one would silently change
  qualifications. The price: a snapshot only loads under the DSS version that wrote it.
  - Certificates are written as their DER encoding and parsed again with `DSSUtils.loadCertificate`, so they are
    the same BouncyCastle objects a load from the cache makes. Downloaded documents (`FileDocument`s of the cache
    files) are written as null: not part of the trust pool, and they would carry the producer's paths.
  - Size: 14 MB for the full EU list, 1.5 MB for IT.
- **Deserialization is defensive anyway.** An `ObjectInputFilter` accepts only the classes a snapshot holds (the
  DSS trusted-list model packages, a fixed list of JDK collections and boxed types) and limits depth, references
  and array sizes, before anything is instantiated. `TlSnapshotTest` checks that a class outside the list is
  refused without its `readObject` ever running. Found on the real lists, not the synthetic ones: `HashMap` and
  `ArrayList` ask the filter about the `Map.Entry[]` and `Object[]` they allocate, and the filter is also asked
  about the `CertificateToken`s that `resolveObject` returns.
- **BouncyCastle's RSA modulus tests are skipped while reading, on that thread only.** The first prototype read
  the full EU snapshot in 23 s, three times slower than the cache. Almost all of it was BouncyCastle, not
  deserialization: building a certificate's public key runs probabilistic primality tests on an RSA modulus
  (`RSAKeyParameters.validate`, about 4 ms each), and `CertificateToken` builds the key at once. Those keys were
  tested when the lists were loaded to make the snapshot, so `TlSnapshotFile` sets BouncyCastle's thread-local
  override `org.bouncycastle.rsa.allow_unsafe_mod` while reading and removes it afterwards. Keys built during
  validations, on other threads, are tested as before. The same cost is part of every load from the cache:
  an estimated 1.9 s of the 3.8 s for IT (468 certificates at about 4 ms, on one thread; not measured). That
  path is unchanged.
- **Behaviour around a snapshot.**
  - Status: `tl_snapshot` (header, path, size); `last_offline_refresh` with `mode: "snapshot"`.
  - The snapshot also fills the staging source DSS's job synchronizes into, like a load from the cache.
  - An online refresh replaces the snapshot's lists with what it downloads. DSS's job has no earlier results to
    keep for a list that fails to download, so that list stays missing until a refresh succeeds; a `cache_dir`
    holding the lists is the fallback, as before.
  - A refresh that cannot run at all (an exception out of DSS's job) no longer publishes the staging source,
    which may be half refilled; the published lists, and where they came from, stay as they were. Before, the
    staging source was published regardless.
  - Exporting lists that came from a snapshot is allowed and keeps the original `lists_loaded`: it describes
    the load that validated them.
- **Native Image.** `DssFeature` registers the serialization family from `TlSnapshotFile`'s allowlist
  (reflection-audit.md, "Trusted-list snapshots"); `merge-metadata.py` drops the agent's serialization records
  for library classes. The library grew from 91.4 to 94.4 MB.
- **Verified:**
  - JVM and native test suites (`TlSnapshotTest`: same status and byte-identical simple, detailed and diagnostic
    reports for the PAdES/CAdES fixtures from both engines; damaged, foreign and mismatched files; the filter; a
    list expiring between export and import);
  - Rust (`tl_snapshot_errors_are_typed`, `synthetic_tl_snapshot_round_trip`), the CLI (`--tl-snapshot`, `tl
    snapshot`), the C smoke test offline and `--online` (a snapshot of the real IT list, after an online
    refresh);
  - by hand, the real EU lists through the shipped library: the status from a snapshot matches the cache's (lists,
    counts, alerts), and three real signed PDFs (`testdata/private`) gave the same `dss-cli validate --json`
    output from both. The only difference was `best_signature_time` of two untimestamped signatures, which is the
    validation time.
- **Not verified:** Linux (built and tested on macOS aarch64 only).
