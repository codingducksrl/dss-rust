# The native library

`libdssnative` is DSS, the dss-native wrapper and the Substrate VM runtime compiled by GraalVM Native Image
(Community Edition) into one shared library with a C API. No JVM is needed where it runs.

## Building

```bash
export JAVA_HOME=<GraalVM CE 25.4.4.1.1>
scripts/build-native.sh               # or --with-tests: JVM tests + native tests first
```

Output, in `build/native/<os>-<arch>/` (`macos-aarch64`, `linux-x64`, `linux-aarch64`):

| File | |
|---|---|
| `libdssnative.dylib` / `.so` | ~91 MB (macOS aarch64). macOS install name `@rpath/libdssnative.dylib`; Linux soname `libdssnative.so` |
| `libdssnative.h` | the `dss_*` functions. Self-contained: it includes `<stddef.h>` and `<graal_isolate.h>` |
| `graal_isolate.h` | isolate and thread management (`graal_create_isolate`, `graal_attach_thread`, …), exported by the same library |
| `libdssnative_dynamic.h`, `graal_isolate_dynamic.h` | the same as function-pointer typedefs, for `dlopen` |

Build choices:
- **`-march=compatibility`**: runs on any x86-64 / ARMv8-A CPU. The default would target x86-64-v3 (AVX2) or
  ARMv8.1-A.
- **Oldest OS.** Linux: glibc 2.34 or later, and `libz.so.1`. macOS: 14.0, set with
  `-mmacosx-version-min` (the deployment target of GraalVM CE's own C libraries); without it the library would
  require the build machine's macOS. See DECISIONS.md, "Binary compatibility".
- **No AWT side libraries.** native-image also writes `libawt*`, `libfontmanager`, `liblcms`, … next to the
  library, because PDFBox references `java.awt`. They are not shipped, on any platform.
  - Opening a PDF makes PDFBox try to load `libawt`; it catches the `UnsatisfiedLinkError`, and neither
    validation nor signing needs AWT: visible signatures are drawn without it (DECISIONS.md, "Visible
    signatures"). `scripts/smoke-test-c.sh` runs from `build/native/…`, which lacks those libraries.
  - Do not add them. The JDK's libawt keeps process-wide state and can crash the process when several
    isolates load it at once (DECISIONS.md, Phase 6, "PDFBox and the JDK's libawt"). The library also forces
    `java.awt.headless=true`, in case a libawt is found anyway on the library search path.

## Using the C API

```c
#include "libdssnative.h"

graal_isolate_t *isolate;
graal_isolatethread_t *thread;
graal_create_isolate(NULL, &isolate, &thread);           /* once per process (or more, see below) */

char *r = dss_init(thread, "/var/lib/app/dss-cache", config_json);
dss_free(thread, r);

r = dss_validate(thread, bytes, len, NULL);              /* JSON: see README.md */
/* ... */
dss_free(thread, r);

char *pdf = NULL;                                        /* the extended document, on success */
size_t pdf_len = 0;
r = dss_extend(thread, bytes, len, "{\"level\":\"LT\"}", &pdf, &pdf_len);
/* {"ok":true,...}: write pdf_len bytes of pdf; {"ok":false,...}: pdf is NULL */
dss_free(thread, pdf);
dss_free(thread, r);

r = dss_sign_prepare(thread, bytes, len, options_json);  /* {"ok":true,"digest":"<base64>","signing_time":...} */
/* ... the external signer signs the digest; add "signing_time" to options_json ... */
char *signed_doc = NULL;
size_t signed_len = 0;
r = dss_sign_complete(thread, bytes, len, options_json, sig, sig_len, &signed_doc, &signed_len);
dss_free(thread, signed_doc);                            /* NULL unless {"ok":true,...} */
dss_free(thread, r);

dss_free(thread, dss_shutdown(thread));                  /* stop background threads */
graal_tear_down_isolate(thread);
```

The JSON contract (config, options, results, status, error codes) is in [README.md](../README.md#api).

### Rules

- **Threads.** Every call takes the *calling thread's* `graal_isolatethread_t*`. A thread other than the one
  that created the isolate must call `graal_attach_thread(isolate, &t)` first and `graal_detach_thread(t)`
  before it exits. All `dss_*` functions are thread-safe. `dss_validate`, `dss_extend` and the `dss_sign_*`
  functions run concurrently on any number of threads, also during `dss_tl_refresh_online`.
- **Memory.** Every returned `char*` is malloc'd UTF-8 JSON owned by the caller: release it with `dss_free`.
  `dss_free(NULL)` is allowed. Input strings and the document and signature buffers are only read during the
  call. `dss_extend` and `dss_sign_complete` also hand back a document in `*out_document`: binary, `*out_len`
  bytes, not NUL-terminated, owned by the caller and released with `dss_free` too. They set `*out_document` to
  `NULL` and `*out_len` to 0 whenever the result is not `"ok":true`. Both out-parameters are required.
- **Errors.** Results always carry `"ok"`. No Java exception ever reaches C. `NULL` is returned only if not
  even an error result could be built (the Java heap and native memory are both exhausted).
- **Shutdown.** Call `dss_shutdown` before `graal_tear_down_isolate`, so the trusted-list worker threads stop.
  Calling `dss_init` again replaces the engine without a shutdown.
- **Several isolates** in one process are independent (separate heaps, separate engines), and may validate at
  the same time: the C smoke test starts 4 at once. One isolate with many attached threads is the normal setup.
  Native code that assumes one JVM per process is the hazard here, which is why no JDK AWT library is shipped.
- **Make the first isolate creation one that cannot fail.** In GraalVM CE 25.4, if the *first*
  `graal_create_isolate` of a process fails (e.g. an invalid `-Xmx` in `argv`), every later
  `graal_create_isolate` in that process hangs. A failure after a successful creation is harmless. The Rust
  `dss` crate handles this by creating and tearing down one option-less isolate before its first engine. C
  hosts that pass user-supplied isolate options should do the same.

### Heap size

The isolate's heap is set by runtime options passed when creating it. Without any, Native Image's default
lets the heap grow to a large share of physical memory.

```c
graal_create_isolate_params_t p = {0};
p.version = __graal_create_isolate_params_version;
char *args[] = {"app", "-Xmx512m"};          /* argv[0] is ignored, as for a command line */
p.argc = 2; p.argv = args;
graal_create_isolate(&p, &isolate, &thread);
```

A document or report that does not fit the heap fails as
`{"ok":false,"error":{"code":"INTERNAL_ERROR","message":"java.lang.OutOfMemoryError: …"}}` and the isolate stays
usable. The smoke test checks this with a 128 MB document on a 64 MB heap.

Implementation detail: Native Image unwinds an `OutOfMemoryError` raised by an allocation to the *calling*
compiled frame, skipping handlers in the allocating frame itself. So the C entry points allocate nothing large:
- the document goes to Java as a `ByteBuffer` view and is copied inside `DssJsonApi`'s error handling;
- results are encoded to UTF-8 directly into malloc'd memory;
- `dss_extend` and `dss_sign_complete` copy the document from the Java array `DssJsonApi` returned into malloc'd
  memory.

### Logging

DSS logs through SLF4J (`slf4j-simple`) to the host process's **stderr**, at `config_json.log_level` (default
`warn`). The level is fixed by the first `dss_init` in an isolate.

### Locale

The library sets its isolate's default locale to `en-US` on the first call, so reports and formatting do not
depend on the host's `LANG`/`LC_*` (and only en-US locale data is in the image). This does not touch the host
process's own locale.

## TLS: which CAs are trusted

HTTPS is used for trusted-list downloads, CRL/OCSP, AIA (missing intermediate certificates) and the TSA of
`dss_extend` and `dss_sign_complete`.

| | Trusted-list downloads (LOTL, national TLs) | CRL, OCSP, AIA, TSA |
|---|---|---|
| Default | **Server certificate not verified** (`http.tl_verify_tls: false`). Each list's XML signature is verified (LOTL against the OJ keystore, TLs against the LOTL), and lists with a bad signature are never used | Verified against the **CA bundle embedded at build time** |
| `http.tl_verify_tls: true` | Verified against the embedded bundle, or `http.trust_store` if set | — |
| `http.trust_store: {path, type, password}` | Used if `tl_verify_tls` | **Replaces** the embedded bundle |

**Embedded bundle (build-time capture).** native-image stores the default trust store of the JDK running the
build (GraalVM CE's `lib/security/cacerts`) inside the library. No certificate file is needed at run time,
and the host's system CA store is *not* consulted. To embed a different bundle, build with
`-Djavax.net.ssl.trustStore=<file>` (and `…Type`/`…Password`) passed to native-image, e.g.
`NATIVE_IMAGE_OPTIONS="-Djavax.net.ssl.trustStore=/path/ca.p12" scripts/build-native.sh`. Updating the
embedded bundle means rebuilding.

**Run-time override.** `http.trust_store` in `config_json` points DSS's HTTP client at a PKCS#12/JKS file
for this engine. It replaces the embedded set; it does not add to it. Native Image also honours the
`javax.net.ssl.trustStore*` system properties at run time, but those are process-wide inside the isolate and
not exposed by this API.

**Verified** by:
- `scripts/smoke-test-c.sh --online`: real EU LOTL and Italian TL downloaded with `tl_verify_tls: true`
  against the embedded bundle, then rejected (`PKIX`) with a `trust_store` holding an unrelated CA;
- `HttpsLoopbackTest`, also in the native test image: TLS server on 127.0.0.1 with a test-PKI certificate,
  checking the override, rejection by the embedded bundle and the unverified default for lists, and a TSA
  behind HTTP Basic auth (`tsa.username`/`tsa.password`, sent with the first request).

## Security providers

DSS registers BouncyCastle at run time (`Security.addProvider`), and resolves algorithms by name from the
documents being validated. `DssFeature` registers every BouncyCastle service class for reflection. The JDK's
own providers (SUN, SunRsaSign, SunEC, SunJCE, SunJSSE) are included by Native Image automatically.

## Performance

Measured on macOS aarch64; see `docs/DECISIONS.md` for details.
- **Cold start, loading the trusted lists from the cache:** about 7.6 s for the full LOTL (32 lists), 4.1 s for
  IT only. Every list's signature is re-validated on load; `tl_threads` sets the parallelism. Measured again on
  an M5 Pro (2026-11-06): 6.5 s full with 15 threads, 17 s with 2, 32 s with 1; 3.8 s for IT, whatever the
  threads (the LOTL and its pivots are validated one after another).
- **Cold start from a trusted-list snapshot** (`tl_snapshot`, README.md): 0.63 s for the full LOTL (266 MB peak
  resident, against 337–366 MB from the cache), 0.10 s for IT (92 MB, against 145 MB). One thread; no list is
  parsed or validated.
- **A validation:** tens of milliseconds.
- **An online refresh of the full LOTL:** about 15 s.

## Tests of the library itself

| | Covers |
|---|---|
| `./mvnw -Pnative test` | JUnit suite compiled as a native executable with `--exact-reachability-metadata` |
| `scripts/smoke-test-c.sh` | C API from C: seeded synthetic TL cache (offline), all fixture kinds, `dss_extend` and `dss_sign_*` with their out-parameters, error paths, 4 attached threads, a small-heap isolate |
| `scripts/smoke-test-c.sh --online` | Same against the real EU LOTL (IT): first refresh, refresh concurrent with validations, TLS CA embedding and override |
| `scripts/test-rust.sh [--online]` | The Rust `dss` crate against the library: fixtures, errors, threads, heap limit, refresh concurrency, scheduler. `dss-cli` with its stdout closed |
