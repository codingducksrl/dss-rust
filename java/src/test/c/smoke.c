/*
 * dss-native: smoke test of the C API, run by scripts/smoke-test-c.sh.
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 *   smoke <cache_dir> <config.json> <fixtures_dir> [--online [<bad_tls_config.json>]]
 *
 * Offline (default): the cache holds the synthetic trusted lists, so init must load them without network.
 * Online: the cache starts empty and config.json points at the real EU LOTL; the test refreshes it, then
 * refreshes again while worker threads keep validating. With bad_tls_config.json (an http.trust_store that does
 * not contain the servers' CA), a further refresh must fail every download: the run-time CA override works.
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libdssnative.h"

static int failures = 0;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

#define FAIL(...)                                                   \
    do {                                                            \
        pthread_mutex_lock(&lock);                                  \
        failures++;                                                 \
        fprintf(stderr, "FAIL (%s:%d) ", __FILE__, __LINE__);       \
        fprintf(stderr, __VA_ARGS__);                               \
        fputc('\n', stderr);                                        \
        pthread_mutex_unlock(&lock);                                \
    } while (0)

static char *read_file(const char *path, size_t *len_out) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        FAIL("cannot open %s", path);
        exit(2);
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t) len + 1);
    if (fread(buf, 1, (size_t) len, f) != (size_t) len) {
        FAIL("cannot read %s", path);
        exit(2);
    }
    fclose(f);
    buf[len] = '\0';
    if (len_out) {
        *len_out = (size_t) len;
    }
    return buf;
}

/* Checks that the result contains every needle, then frees it. */
static int expect(graal_isolatethread_t *t, char *result, const char *what, const char *needle, const char *needle2) {
    if (result == NULL) {
        FAIL("%s: NULL result", what);
        return 0;
    }
    int ok = strstr(result, needle) != NULL && (needle2 == NULL || strstr(result, needle2) != NULL);
    if (!ok) {
        FAIL("%s: expected %s%s%s in: %.600s", what, needle, needle2 ? " and " : "", needle2 ? needle2 : "", result);
    }
    dss_free(t, result);
    return ok;
}

static char *validate_fixture(graal_isolatethread_t *t, const char *fixtures, const char *rel, const char *options) {
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", fixtures, rel);
    size_t len;
    char *doc = read_file(path, &len);
    char *result = dss_validate(t, doc, len, options);
    free(doc);
    return result;
}

#define PASSED "\"indication\":\"TOTAL_PASSED\""
#define FAILED "\"indication\":\"TOTAL_FAILED\""

struct worker {
    graal_isolate_t *isolate;
    const char *fixtures;
    int iterations;
    int done;
};

static void *worker_main(void *arg) {
    struct worker *w = arg;
    graal_isolatethread_t *t;
    if (graal_attach_thread(w->isolate, &t) != 0) {
        FAIL("graal_attach_thread failed");
        return NULL;
    }
    for (int i = 0; i < w->iterations; i++) {
        if (i % 2 == 0) {
            expect(t, validate_fixture(t, w->fixtures, "pades/b-lta.pdf", NULL), "worker b-lta", PASSED, NULL);
        } else {
            expect(t, validate_fixture(t, w->fixtures, "tampered/cades/attached-ber.p7m", NULL), "worker tampered",
                   FAILED, "HASH_FAILURE");
        }
        w->done++;
    }
    graal_detach_thread(t);
    return NULL;
}

static void common_checks(graal_isolatethread_t *t, const char *fx) {
    expect(t, validate_fixture(t, fx, "pades/b-lta.pdf", NULL), "PAdES B-LTA", PASSED, "PAdES-BASELINE-LTA");
    expect(t, validate_fixture(t, fx, "pades/b-lt.pdf", NULL), "PAdES B-LT", PASSED, NULL);
    expect(t, validate_fixture(t, fx, "tampered/pades/b-lta.pdf", NULL), "tampered PAdES", FAILED, "HASH_FAILURE");
    expect(t, validate_fixture(t, fx, "cades/nested.p7m.p7m", NULL), "nested p7m", "\"nested\":[", "CAdES-BASELINE-B");
    expect(t, validate_fixture(t, fx, "cades/attached-base64.p7m", NULL), "base64 p7m",
           "\"transformations\":[\"base64\"]", NULL);
    expect(t, validate_fixture(t, fx, "cades/multi-signer.p7m", NULL), "multi-signer", "Giulia Bianchi", "Mario Rossi");
    expect(t, validate_fixture(t, fx, "pades/b-lta.pdf", "{\"reports\":[\"detailed\",\"etsi\",\"diagnostic\"]}"),
           "all reports", "\"etsi_report_xml\":", "\"diagnostic_data_xml\":");
    expect(t, dss_validate(t, "hello", 5, NULL), "garbage", "UNSUPPORTED_DOCUMENT", NULL);
    expect(t, dss_validate(t, NULL, 0, NULL), "NULL document", "INVALID_ARGUMENT", NULL);
    expect(t, validate_fixture(t, fx, "pades/b-b.pdf", "{bad json"), "bad options", "INVALID_ARGUMENT", NULL);
    dss_free(t, NULL);
}

/* dss_extend with the smoke config (embedded revocation only, no TSA): an LT signature extends to LT again, the
   rest is refused. The document comes back through the out-parameters only on success. */
static void extend_checks(graal_isolatethread_t *t, const char *fx) {
    char path[4096];
    snprintf(path, sizeof path, "%s/pades/b-lt.pdf", fx);
    size_t len;
    char *doc = read_file(path, &len);

    char *out = NULL;
    size_t out_len = 0;
    expect(t, dss_extend(t, doc, len, "{\"level\":\"LT\"}", &out, &out_len), "extend LT to LT", "\"ok\":true",
           "\"level\":\"PAdES-BASELINE-LT\"");
    if (out == NULL || out_len <= len || memcmp(out, doc, len) != 0) {
        FAIL("extend LT to LT: the result must be the original followed by an incremental update (%zu -> %zu bytes)",
             len, out_len);
    } else {
        expect(t, dss_validate(t, out, out_len, NULL), "validate extended", PASSED, "PAdES-BASELINE-LT");
    }
    dss_free(t, out);

    /* A failed call resets the out-parameters. */
    out = doc;
    out_len = 42;
    expect(t, dss_extend(t, doc, len, "{\"level\":\"LTA\"}", &out, &out_len), "extend without TSA", "EXTENSION_FAILED",
           "no TSA is configured");
    if (out != NULL || out_len != 0) {
        FAIL("extend without TSA: *out_document and *out_len must be NULL and 0");
    }
    expect(t, dss_extend(t, doc, len, NULL, &out, &out_len), "extend without level", "INVALID_ARGUMENT", NULL);
    expect(t, dss_extend(t, doc, len, "{\"level\":\"LT\"}", NULL, &out_len), "extend without out_document",
           "INVALID_ARGUMENT", NULL);
    expect(t, dss_extend(t, "hello", 5, "{\"level\":\"LT\"}", &out, &out_len), "extend garbage",
           "UNSUPPORTED_DOCUMENT", NULL);
    free(doc);
}

/* The real servers have hiccups: AgID's TSL-IT.xml has answered HTTP 504 in CI. Refreshes again, at most 3 times
   30 s apart, while a list failed to download. A list that downloads but fails validation is left to the checks. */
/* dss_sign_prepare/dss_sign_complete with the committed fixture: options with a fixed signing time and the CMS an
   external signer returned for the digest prepare gave. Completing works only if this library prepares exactly
   the PDF the JVM prepared when the fixture was made. */
static void sign_checks(graal_isolatethread_t *t, const char *fx) {
    char path[4096];
    size_t len, sig_len;
    snprintf(path, sizeof path, "%s/content/document.pdf", fx);
    char *doc = read_file(path, &len);
    snprintf(path, sizeof path, "%s/signing/pades-cms.json", fx);
    char *options = read_file(path, NULL);
    snprintf(path, sizeof path, "%s/signing/pades-cms.sig", fx);
    char *sig = read_file(path, &sig_len);

    expect(t, dss_sign_prepare(t, doc, len, options), "sign prepare", "\"ok\":true", "\"digest\":\"");
    char *out = NULL;
    size_t out_len = 0;
    expect(t, dss_sign_complete(t, doc, len, options, sig, sig_len, &out, &out_len), "sign complete", "\"ok\":true",
           "\"level\":\"PAdES-BASELINE-T\"");
    if (out == NULL || out_len <= len || memcmp(out, doc, len) != 0) {
        FAIL("sign complete: the result must be the original followed by the signature revision (%zu -> %zu bytes)",
             len, out_len);
    } else {
        /* Embedded revocation only: not TOTAL_PASSED, but the signature and its timestamp must be intact. */
        expect(t, dss_validate(t, out, out_len, NULL), "validate signed", "PAdES-BASELINE-T", "Mario Rossi");
    }
    dss_free(t, out);

    /* A failed call resets the out-parameters. */
    out = doc;
    out_len = 42;
    expect(t, dss_sign_complete(t, doc, len, options, "not a CMS", 9, &out, &out_len), "sign complete garbage",
           "SIGNING_FAILED", NULL);
    if (out != NULL || out_len != 0) {
        FAIL("sign complete garbage: *out_document and *out_len must be NULL and 0");
    }
    expect(t, dss_sign_complete(t, doc, len, "{\"mode\":\"cms\",\"level\":\"B\"}", sig, sig_len, &out, &out_len),
           "sign complete without signing_time", "INVALID_ARGUMENT", "signing_time");
    expect(t, dss_sign_complete(t, doc, len, options, NULL, 0, &out, &out_len), "sign complete without signature",
           "INVALID_ARGUMENT", NULL);
    expect(t, dss_sign_complete(t, doc, len, options, sig, sig_len, NULL, &out_len), "sign complete without out",
           "INVALID_ARGUMENT", NULL);
    expect(t, dss_sign_prepare(t, doc, len, NULL), "sign prepare without options", "INVALID_ARGUMENT", NULL);
    expect(t, dss_sign_prepare(t, "hello", 5, "{\"format\":\"PAdES\",\"mode\":\"cms\",\"level\":\"B\"}"),
           "PAdES of a non-PDF", "UNSUPPORTED_DOCUMENT", NULL);
    free(doc);
    free(options);
    free(sig);
}

/* Visible signatures from the committed fixtures. This library has no AWT next to it, like an application's copy:
   the appearance must be drawn without it, and byte for byte as the JVM drew it when the fixture was made. */
static void visible_sign_checks(graal_isolatethread_t *t, const char *fx) {
    const char *cases[][3] = {{"pades-visible-cms", "content/document.pdf", "Mario Rossi"},
                              {"pades-visible-field-signature-value", "content/form.pdf", "Mario Rossi"}};
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        char path[4096];
        size_t len, sig_len;
        snprintf(path, sizeof path, "%s/%s", fx, cases[i][1]);
        char *doc = read_file(path, &len);
        snprintf(path, sizeof path, "%s/signing/%s.json", fx, cases[i][0]);
        char *options = read_file(path, NULL);
        snprintf(path, sizeof path, "%s/signing/%s.sig", fx, cases[i][0]);
        char *sig = read_file(path, &sig_len);
        char *out = NULL;
        size_t out_len = 0;
        expect(t, dss_sign_complete(t, doc, len, options, sig, sig_len, &out, &out_len), cases[i][0], "\"ok\":true",
               "\"level\":\"PAdES-BASELINE-B\"");
        if (out == NULL || out_len <= len || memcmp(out, doc, len) != 0) {
            FAIL("%s: the result must be the original followed by the signature revision", cases[i][0]);
        } else {
            expect(t, dss_validate(t, out, out_len, NULL), cases[i][0], "PAdES-BASELINE-B", cases[i][2]);
        }
        dss_free(t, out);
        free(doc);
        free(options);
        free(sig);
    }
}

static char *refresh_until_downloaded(graal_isolatethread_t *t) {
    for (int attempt = 1;; attempt++) {
        char *result = dss_tl_refresh_online(t);
        char *status = dss_tl_status(t);
        int failed = status != NULL && strstr(status, "\"download\":{\"status\":\"ERROR\"") != NULL;
        dss_free(t, status);
        if (!failed || attempt == 3) {
            return result;
        }
        fprintf(stderr, "a list failed to download (attempt %d), refreshing again in 30 s\n", attempt);
        dss_free(t, result);
        sleep(30);
    }
}

/* Several isolates start at once, each validating a PDF, before any other isolate in this process has opened one.
   Opening a PDF makes PDFBox try to load the JDK's libawt, which keeps process-wide state and can crash the process
   when isolates load it concurrently. The library ships without libawt (scripts/build-native.sh); this check fails,
   at least under load, if it ever comes back. */
struct isolate_job {
    const char *cache, *config, *fixtures;
};

static void *isolate_main(void *arg) {
    struct isolate_job *job = arg;
    graal_isolate_t *isolate;
    graal_isolatethread_t *t;
    if (graal_create_isolate(NULL, &isolate, &t) != 0) {
        FAIL("graal_create_isolate (concurrent isolates) failed");
        return NULL;
    }
    expect(t, dss_init(t, job->cache, job->config), "concurrent isolates: init", "\"ok\":true", NULL);
    expect(t, validate_fixture(t, job->fixtures, "pades/b-lta.pdf", NULL), "concurrent isolates: PAdES", PASSED, NULL);
    expect(t, dss_shutdown(t), "concurrent isolates: shutdown", "\"ok\":true", NULL);
    graal_tear_down_isolate(t);
    return NULL;
}

static void concurrent_isolates_check(const char *cache, const char *config, const char *fixtures) {
    enum { ISOLATES = 4 };
    pthread_t threads[ISOLATES];
    struct isolate_job job = {cache, config, fixtures};
    for (int i = 0; i < ISOLATES; i++) {
        pthread_create(&threads[i], NULL, isolate_main, &job);
    }
    for (int i = 0; i < ISOLATES; i++) {
        pthread_join(threads[i], NULL);
    }
}

static void write_file(const char *path, const char *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f || fwrite(data, 1, len, f) != len) {
        FAIL("cannot write %s", path);
    }
    if (f) {
        fclose(f);
    }
}

/* config_json with "tl_snapshot" added: config is a JSON object, path needs no escaping. */
static char *config_with_snapshot(const char *config, const char *path) {
    const char *end = strrchr(config, '}');
    size_t head = (size_t) (end - config);
    size_t size = head + strlen(path) + 32;
    char *out = malloc(size);
    snprintf(out, size, "%.*s,\"tl_snapshot\":\"%s\"}", (int) head, config, path);
    return out;
}

/* dss_tl_export_snapshot, then an engine started from the file with an empty cache: it trusts the same lists. A
   damaged file fails dss_init with TL_SNAPSHOT_REJECTED. Leaves the engine initialised from the cache again. */
static void tl_snapshot_checks(graal_isolatethread_t *t, const char *cache, const char *config, const char *fx) {
    size_t len = 0;
    expect(t, dss_tl_export_snapshot(t, NULL, &len), "export snapshot without out_snapshot", "INVALID_ARGUMENT",
           NULL);
    char *snapshot = NULL;
    if (!expect(t, dss_tl_export_snapshot(t, &snapshot, &len), "export snapshot", "\"ok\":true", "\"format\":1")
        || snapshot == NULL || len == 0) {
        FAIL("export snapshot: no file in *out_snapshot");
        dss_free(t, snapshot);
        return;
    }
    char dir[4000], path[4096], damaged[4096];
    if (getcwd(dir, sizeof dir) == NULL) {
        FAIL("getcwd failed");
        dss_free(t, snapshot);
        return;
    }
    snprintf(path, sizeof path, "%s/lists.tlsnap", dir);
    snprintf(damaged, sizeof damaged, "%s/damaged.tlsnap", dir);
    write_file(path, snapshot, len);
    snapshot[len / 2] ^= 1;
    write_file(damaged, snapshot, len);
    dss_free(t, snapshot);

    char *with = config_with_snapshot(config, path);
    expect(t, dss_init(t, "snapshot-cache", with), "init from snapshot", "\"ok\":true", "\"mode\":\"snapshot\"");
    expect(t, dss_tl_status(t), "status from snapshot", "\"tl_snapshot\":{", "lists.tlsnap");
    expect(t, validate_fixture(t, fx, "pades/b-lta.pdf", NULL), "validate from snapshot", PASSED, NULL);
    free(with);
    with = config_with_snapshot(config, damaged);
    expect(t, dss_init(t, "snapshot-cache", with), "init from damaged snapshot", "TL_SNAPSHOT_REJECTED", "checksum");
    free(with);
    expect(t, dss_init(t, cache, config), "init from the cache again", "\"ok\":true", "\"trusted_lists_loaded\":true");
}

/* A second isolate with a 64 MB heap gets a 128 MB document: the copy into the Java heap must fail as a
   structured error, never as an exception unwinding into C (which would abort this process). */
static void small_heap_check(const char *cache, const char *config) {
    graal_create_isolate_params_t params;
    memset(&params, 0, sizeof params);
    params.version = __graal_create_isolate_params_version;
    char *args[] = {"smoke", "-Xmx64m"};
    params.argc = 2;
    params.argv = args;
    graal_isolate_t *isolate;
    graal_isolatethread_t *t;
    if (graal_create_isolate(&params, &isolate, &t) != 0) {
        FAIL("graal_create_isolate(-Xmx64m) failed");
        return;
    }
    expect(t, dss_init(t, cache, config), "small-heap init", "\"ok\":true", NULL);
    size_t len = 128u * 1024 * 1024;
    char *big = calloc(len, 1);
    expect(t, dss_validate(t, big, len, NULL), "128 MB document, 64 MB heap", "\"ok\":false", "OutOfMemoryError");
    char *out = NULL;
    size_t out_len = 0;
    expect(t, dss_extend(t, big, len, "{\"level\":\"LT\"}", &out, &out_len), "extend 128 MB, 64 MB heap", "\"ok\":false",
           "OutOfMemoryError");
    if (out != NULL) {
        FAIL("extend 128 MB, 64 MB heap: *out_document must be NULL");
    }
    free(big);
    expect(t, dss_validate(t, "hello", 5, NULL), "small-heap isolate still usable", "UNSUPPORTED_DOCUMENT", NULL);
    expect(t, dss_shutdown(t), "small-heap shutdown", "\"ok\":true", NULL);
    graal_tear_down_isolate(t);
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <cache_dir> <config.json> <fixtures_dir> [--online]\n", argv[0]);
        return 64;
    }
    const char *cache = argv[1], *fixtures = argv[3];
    int online = argc > 4 && strcmp(argv[4], "--online") == 0;
    char *config = read_file(argv[2], NULL);

    if (!online) {
        concurrent_isolates_check(cache, config, fixtures); /* first: no PDF opened in this process yet */
    }

    graal_isolate_t *isolate;
    graal_isolatethread_t *t;
    if (graal_create_isolate(NULL, &isolate, &t) != 0) {
        fprintf(stderr, "graal_create_isolate failed\n");
        return 1;
    }

    expect(t, dss_version(t), "version", "\"dss\":\"6.5.1\"", NULL);
    expect(t, dss_validate(t, "x", 1, NULL), "validate before init", "NOT_INITIALIZED", NULL);
    char *early = NULL;
    size_t early_len = 0;
    expect(t, dss_extend(t, "x", 1, "{\"level\":\"LT\"}", &early, &early_len), "extend before init", "NOT_INITIALIZED",
           NULL);
    expect(t, dss_sign_prepare(t, "x", 1, "{}"), "sign prepare before init", "NOT_INITIALIZED", NULL);
    expect(t, dss_sign_complete(t, "x", 1, "{}", "x", 1, &early, &early_len), "sign complete before init",
           "NOT_INITIALIZED", NULL);
    expect(t, dss_tl_export_snapshot(t, &early, &early_len), "export snapshot before init", "NOT_INITIALIZED", NULL);
    if (early != NULL) {
        FAIL("export snapshot before init: *out_snapshot must be NULL");
    }
    expect(t, dss_init(t, cache, "{not json"), "bad config", "INVALID_CONFIG", NULL);

    if (online) {
        expect(t, dss_init(t, cache, config), "init (empty cache)", "\"ok\":true", "\"trusted_lists_loaded\":false");
        expect(t, validate_fixture(t, fixtures, "pades/b-lta.pdf", NULL), "validate without TLs",
               "TRUSTED_LISTS_NOT_LOADED", NULL);
        expect(t, refresh_until_downloaded(t), "first online refresh", "\"ok\":true", "\"completed\":true");
        expect(t, dss_tl_status(t), "status after refresh", "\"loaded\":true", "\"territory\":\"IT\"");
    } else {
        expect(t, dss_init(t, cache, config), "init (seeded cache)", "\"ok\":true", "\"trusted_lists_loaded\":true");
        expect(t, dss_tl_status(t), "status", "\"loaded\":true", "\"used_for_trust\":true");
    }
    common_checks(t, fixtures);
    extend_checks(t, fixtures);
    sign_checks(t, fixtures);
    visible_sign_checks(t, fixtures);

    /* Several threads attached to the isolate validate while the main thread refreshes (online) or polls the
       status (offline). */
    enum { WORKERS = 4 };
    pthread_t threads[WORKERS];
    struct worker workers[WORKERS];
    for (int i = 0; i < WORKERS; i++) {
        workers[i] = (struct worker) {isolate, fixtures, online ? 40 : 20, 0};
        pthread_create(&threads[i], NULL, worker_main, &workers[i]);
    }
    if (online) {
        expect(t, dss_tl_refresh_online(t), "refresh during validation", "\"ok\":true", "\"completed\":true");
    } else {
        for (int i = 0; i < 50; i++) {
            expect(t, dss_tl_status(t), "status during validation", "\"loaded\":true", NULL);
        }
    }
    int total = 0;
    for (int i = 0; i < WORKERS; i++) {
        pthread_join(threads[i], NULL);
        total += workers[i].done;
    }
    tl_snapshot_checks(t, cache, config, fixtures);

    if (online && argc > 5) {
        char *bad = read_file(argv[5], NULL);
        expect(t, dss_init(t, cache, bad), "init with foreign trust store", "\"ok\":true",
               "\"trusted_lists_loaded\":true");
        expect(t, dss_tl_refresh_online(t), "refresh with foreign trust store", "\"ok\":true", NULL);
        expect(t, dss_tl_status(t), "TLS rejected by trust store override", "\"error\":", "PKIX");
        free(bad);
    }

    expect(t, dss_shutdown(t), "shutdown", "\"ok\":true", NULL);
    expect(t, dss_tl_status(t), "status after shutdown", "NOT_INITIALIZED", NULL);
    small_heap_check(cache, config);
    if (graal_tear_down_isolate(t) != 0) {
        FAIL("graal_tear_down_isolate failed");
    }
    free(config);

    printf("%s smoke test: %d concurrent validations on %d threads, %d failure(s)\n",
           online ? "online" : "offline", total, WORKERS, failures);
    return failures == 0 ? 0 : 1;
}
