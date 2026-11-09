# The native library

`libdssnative` is DSS, the dss-native wrapper and the Substrate VM runtime compiled by GraalVM Native Image
(Community Edition) into one shared library with a C API. No JVM is needed where it runs.

## Building

```bash
export JAVA_HOME=<GraalVM CE 25.5.5.0.3>
scripts/build-native.sh               # or --with-tests: JVM tests + native tests first
```

`build-native.sh` refuses a `JAVA_HOME` that is not GraalVM Community Edition. Another CE release than the pinned
one (`graalvm.sdk.version` in `java/pom.xml`) only warns locally and is refused in CI (DECISIONS.md, "Dependency
monitoring").

Output, in `build/native/<os>-<arch>/` (`macos-aarch64`, `linux-x64`, `linux-aarch64`):

| File | |
|---|---|
| `libdssnative.dylib` / `.so` | ~94 MB (macOS aarch64). macOS install name `@rpath/libdssnative.dylib`; Linux soname `libdssnative.so` |
| `libdssnative.h` | the `dss_*` functions. Self-contained: it includes `<stddef.h>` and `<graal_isolate.h>` |
| `graal_isolate.h` | isolate and thread management (`graal_create_isolate`, `graal_attach_thread`, …), exported by the same library |
| `libdssnative_dynamic.h`, `graal_isolate_dynamic.h` | the same as function-pointer typedefs, for `dlopen` |
| `licenses/` | licence texts and notices of everything compiled into the library, to ship with it (LICENSING.md) |

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
/* {"ok":true,"trusted_lists_loaded":true,"log_level":"warn","initial_load":{...},
    "oj_keystore":{"path":"...","sha256":"<64 hex>"}}: the root of trust in use, as dss_tl_status reports it */
dss_free(thread, r);

r = dss_validate(thread, bytes, len, NULL);              /* JSON: see README.md */
/* ... */
dss_free(thread, r);

const char *names[] = { "contract.pdf" };                /* a detached .p7s with its content, no base64 */
const char *contents[] = { content };
size_t lens[] = { content_len };
r = dss_validate_with_contents(thread, p7s, p7s_len, 1, names, contents, lens, NULL);
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
  - **A wrong handle stops the process.** This is the precondition of every Native Image C API, checked before
    any code of this library runs, so it cannot produce a JSON result. `NULL` fails with
    `Fatal error: Failed to enter the specified IsolateThread context` (exit status 2). A handle that belongs to
    *another* thread is a fatal error too (`A call from native code to Java code provided a ... IsolateThread
    that is either corrupt or belongs to a different OS thread`, `SIGABRT`): the library is built with
    `-H:+CheckIsolateThreadAtEntry`, because without it such a call is silently accepted and corrupts the
    isolate. A handle of a torn-down isolate or of a detached thread points at freed memory: the call is
    undefined behaviour, in practice a `SIGSEGV` or a fatal error, never a result to rely on. The C smoke test
    runs the NULL and other-thread cases in forked children and fails if a child returns a result; the torn-down
    case is run for information only. The Rust `dss` crate never exposes the handles, so only C hosts can get
    this wrong; dss-server's PHP client talks HTTP and is not affected.
- **Strings** (`cache_dir`, `config_json`, `options_json`, and each `names[i]` of `dss_validate_with_contents`)
  are NUL-terminated UTF-8 and are decoded strictly: a malformed sequence is refused with `INVALID_ARGUMENT` (`"cache_dir is not valid UTF-8 (byte 11)"`, naming the
  parameter and the offset of the first bad byte), never repaired with U+FFFD and acted upon, which would create
  the cache or look for a snapshot at a path other than the one passed. Paths inside `config_json` are strings
  of a JSON document, so they are checked the same way.
- **Detached contents as buffers.** `dss_validate_with_contents` behaves as `dss_validate`, with `contents[i]`
  (`lens[i]` bytes, named `names[i]`) added to `options_json`'s `detached_contents` before any entry the JSON
  carries, exactly as if sent as `{"name": names[i], "base64": ...}`. `names` may be `NULL` (all unnamed), and so
  may any `names[i]`; `count` 0 with `NULL` arrays is the same as `dss_validate`. It refuses with
  `INVALID_ARGUMENT` and one of these messages: `count larger than 1024`; `contents and lens are required when
  count is not 0`; `contents[<i>] is NULL`; `contents[<i>] is empty` (the JSON route refuses `"base64": ""` too);
  `contents[<i>] larger than 2147483639 bytes`; `names[<i>] is not valid UTF-8 (byte <n>)`; `options_json is not
  valid JSON: ...`; `options: 'detached_contents' must be an array of objects`. Everything else (unknown keys,
  report names, `path` entries) is refused by the engine with its usual messages. The contents are not re-encoded
  inside the library either: the entry point hands the engine views of the caller's buffers and each one is
  copied into the Java heap once, inside the error handling, so a content too large for the heap is an
  `INTERNAL_ERROR` result. The cap of 1024 exists because the entry point allocates one small object per content
  before that error handling can run.
- **Versions.** `dss_version` returns `{"ok":true,"library":"<semver>","dss":"6.5.1","runtime":"<JVM name and
  version>","api_version":1}` and works before `dss_init`. `api_version` is the integer version of the C/JSON
  contract this library speaks. It is bumped only on an incompatible change (a removed or renamed field, a changed
  verdict or error-code meaning, a changed C signature); additive changes keep it. A caller built against a
  different API version should refuse the library instead of guessing at the contract (the Rust `dss` crate does,
  with `Error::Protocol`); a library that omits the field predates the check and is treated as version 1.
- **Memory.** Every returned `char*` is malloc'd UTF-8 JSON owned by the caller: release it with `dss_free`.
  `dss_free(NULL)` is allowed. Input strings and the document, detached-content and signature buffers are only
  read during the call. `dss_extend` and `dss_sign_complete` also hand back a document in `*out_document`, and
  `dss_tl_export_snapshot` a snapshot file in `*out_snapshot`: binary, `*out_len` bytes, not NUL-terminated,
  owned by the caller and released with `dss_free` too. They set it to `NULL` and `*out_len` to 0 whenever the
  result is not `"ok":true`. Both out-parameters are required. A call that fails allocates nothing the caller
  must free: the document buffer is released again if its result JSON cannot be allocated.
- **Errors.** Results always carry `"ok"`. No Java exception ever reaches C: what escapes the engine's own
  handling (an `OutOfMemoryError` while decoding a string argument or copying a result, for instance) becomes
  `{"ok":false,"error":{"code":"INTERNAL_ERROR","message":"java.lang.OutOfMemoryError: ..."}}`, written straight
  into malloc'd memory without touching the Java heap, so it can be built when the heap is exhausted. `NULL` is
  returned only if not even that `malloc` succeeds (native memory exhausted). The isolate stays usable in both
  cases. A heap exhausted *during* DSS processing may instead abort the process: see "Heap size".
- **Shutdown.** Call `dss_shutdown` before `graal_tear_down_isolate`, so the trusted-list worker threads stop.
  Calling `dss_init` again replaces the engine without a shutdown. Call `dss_shutdown` only when no refresh is
  running (wait for `dss_tl_refresh_online` to return, or check `refresh_in_progress` in `dss_tl_status`): a
  trusted-list thread still inside an HTTP read ends only when the socket timeout does, and
  `graal_tear_down_isolate` waits for it. The result's `trusted_list_threads_stopped` says whether the threads
  stopped within the shutdown's wait (5 s); `false` means a tear-down may block until they do.
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

**What the heap cap does and does not do.** `-Xmx` bounds the isolate's memory; it is not a safety boundary
that turns every oversized request into an error result. Two outcomes exist:

- **A structured error, isolate kept.** An `OutOfMemoryError` raised on the *calling* thread is caught and
  returned as `{"ok":false,"error":{"code":"INTERNAL_ERROR","message":"java.lang.OutOfMemoryError: …"}}`. This
  is certain at the boundaries, where the library itself allocates: the copy of the document into the heap, the
  decoding of a string argument, the encoding of the result. The smoke test checks a 128 MB document and a
  128 MB `options_json` on a 64 MB heap, and that the isolate keeps working afterwards.
- **The process aborts.** An `OutOfMemoryError` raised *while DSS is processing* the document can land on a
  thread of the Native Image runtime instead of the caller's. The runtime treats that as fatal:
  `Fatal error: Reference processing and cleaners must handle all potential exceptions:
  java.lang.OutOfMemoryError: Garbage-collected heap size exceeded`, then `SIGABRT`, thread "Reference Handler".
  Every isolate in the process dies with it. Which thread the error hits depends on the GC's timing, so the
  same request can end either way: a 40 MB CAdES file validated with `dss-cli --max-heap` gave `INTERNAL_ERROR`
  at 64m, 96m and 176m, an abort at 128m and 144m (3 runs of 3 each), and `TOTAL_PASSED` from 256m.

No build or runtime option of GraalVM CE 25 changes this. `ReferenceHandlerThread.run` and
`ReferenceHandler.processPendingReferencesInRegularThread` (the variant without the dedicated thread,
`-R:-AutomaticReferenceHandling`) both end in `VMError.shouldNotReachHere` on any `Throwable`;
`-H:+ExitOnOutOfMemoryError` and `-H:+ReportFatalErrorOnOutOfMemoryError` only make *every* heap OOM fatal.

So size the heap for the work, and bound the work: validation needs several times the document in heap (the
copy, DSS's and PDFBox's own copies, the reports), a signature or an extension more; with `-Xmx` set, limit the
document size and the number of concurrent calls accordingly, and treat an abort as what it is, a crash of the
host process. dss-server bounds the work entering the isolate with `--max-in-flight` and `--request-timeout`
([server.md](server.md), "Sizing") for this reason. The smoke test runs the mid-processing case (preparing a
PAdES signature of a 40 MB PDF on a 64 MB heap) in a forked child and accepts either outcome, never a success,
a `NULL` or a hang.

Implementation detail: Native Image unwinds an `OutOfMemoryError` raised by an allocation to the *calling*
compiled frame, skipping handlers in the allocating frame itself. So the C entry points allocate nothing large:
- the document goes to Java as a `ByteBuffer` view and is copied inside `DssJsonApi`'s error handling;
- results are encoded to UTF-8 directly into malloc'd memory, and so is the `INTERNAL_ERROR` result for an
  error that escaped `DssJsonApi`, from strings that already exist, with no Java allocation at all;
- `dss_extend`, `dss_sign_complete` and `dss_tl_export_snapshot` copy the document or snapshot from the Java
  array `DssJsonApi` returned into malloc'd memory, before the result JSON, and release it again if the JSON's
  `malloc` fails.

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
| `cd java && ./mvnw -Pnative test` | JUnit suite compiled as a native executable with `--exact-reachability-metadata` |
| `scripts/smoke-test-c.sh` | C API from C: the header compiles on its own; in forked children, the two deterministic handle misuses (NULL, another thread's) stop the process (the torn-down isolate is run for information) and a heap exhausted mid-processing ends as documented; 4 isolates started at once; seeded synthetic TL cache (offline), all fixture kinds, `dss_extend`, `dss_sign_*` (visible signatures too) and `dss_tl_export_snapshot` with their out-parameters, an engine started from the snapshot and a damaged one refused, error paths, malformed UTF-8 in `cache_dir`, `config_json` and `options_json`, 4 attached threads, `dss_init` three times and `dss_shutdown` while 4 threads validate (every result a success or `NOT_INITIALIZED`, `trusted_list_threads_stopped` true), a small-heap isolate (128 MB document and 128 MB `options_json` on 64 MB) |
| `scripts/smoke-test-c.sh --online` | Same, except the 4 isolates, against the real EU LOTL (IT): first refresh, refresh concurrent with validations, TLS CA embedding and override |
| `scripts/test-rust.sh [--online]` | The Rust `dss` crate against the library: fixtures, errors, threads, heap limit, refresh concurrency, scheduler. `dss-cli` with its stdout closed |
