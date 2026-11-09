/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

/**
 * The JSON-in/JSON-out contract behind the C API. One engine per isolate (static state is per isolate in
 * Native Image). Every method catches {@link Throwable} and returns {@code {"ok":false,"error":{...}}}, so the
 * FFI layer only converts strings.
 */
public final class DssJsonApi {

    /**
     * Version of the C/JSON contract this library speaks, reported as {@code api_version} by {@link #version()}.
     * Bumped on an incompatible change (a removed or renamed field, a changed verdict or error code meaning, a
     * changed C signature); additive changes keep it. Callers that know a different version should refuse the
     * library rather than guess at the contract.
     */
    public static final int API_VERSION = 1;

    private static volatile DssEngine engine;
    private static final Object INIT_LOCK = new Object();

    private DssJsonApi() {
    }

    /**
     * Builds the engine and loads trusted lists from the cache. Calling it again replaces the engine
     * (validations already running finish on the old one).
     */
    public static String init(String cacheDir, String configJson) {
        return call(() -> {
            if (cacheDir == null || cacheDir.isBlank()) {
                throw new DssError(DssError.Code.INVALID_ARGUMENT, "cache_dir is required");
            }
            EngineConfig config = EngineConfig.fromJson(configJson);
            String effectiveLogLevel = applyLogLevel(config.logLevel);
            DssEngine created = DssEngine.create(Path.of(cacheDir), config);
            DssEngine previous;
            synchronized (INIT_LOCK) {
                previous = engine;
                engine = created;
            }
            if (previous != null) {
                previous.close();
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("trusted_lists_loaded", created.trustedListStatus().get("loaded"));
            m.put("oj_keystore", created.ojKeystore());
            m.put("log_level", effectiveLogLevel);
            m.put("initial_load", created.initialLoad().toMap());
            return m;
        });
    }

    /**
     * Runs an online refresh. {@code TL_REFRESH_FAILED} when it published nothing (DSS's job threw, or what it
     * built was unusable: the previous lists are kept); per-list problems are in the status, not here.
     */
    public static String refreshTrustedListsOnline() {
        return call(() -> refreshResult(requireEngine().refreshTrustedListsOnline()));
    }

    static Map<String, Object> refreshResult(TrustedListManager.RefreshRecord record) {
        if (!record.completed()) {
            throw new DssError(DssError.Code.TL_REFRESH_FAILED, "the online refresh published no trusted lists"
                    + (record.error() == null ? "" : ": " + record.error()) + "; the lists loaded before (if any) "
                    + "are kept, see dss_tl_status");
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("refresh", record.toMap());
        return m;
    }

    public static String trustedListStatus() {
        return call(() -> requireEngine().trustedListStatus());
    }

    /**
     * The loaded trusted lists as a snapshot file, for {@code tl_snapshot} in another engine's config. The result
     * JSON describes the snapshot; the file itself comes back as the document.
     */
    public static DocumentResult exportTlSnapshot() {
        byte[][] produced = new byte[1][];
        boolean[] succeeded = new boolean[1];
        String json = call(() -> {
            TrustedListManager.Exported exported = requireEngine().exportTlSnapshot();
            produced[0] = exported.bytes();
            return exported.info();
        }, () -> succeeded[0] = true);
        return new DocumentResult(json, succeeded[0] ? produced[0] : null);
    }

    public static String validate(byte[] document, String optionsJson) {
        return call(() -> requireEngine().validate(document, ValidationOptions.fromJson(optionsJson)).toMap());
    }

    /**
     * As {@link #validate(byte[], String)}, reading the document from a buffer (the C caller's memory, without
     * copying it first). The copy into the Java heap happens inside the error handling, so a document too large
     * for the heap yields an {@code INTERNAL_ERROR} result instead of an {@code OutOfMemoryError} in the caller.
     */
    public static String validate(ByteBuffer document, String optionsJson) {
        return call(() -> {
            DssEngine engine = requireEngine();
            return engine.validate(copy(document), ValidationOptions.fromJson(optionsJson)).toMap();
        });
    }

    /**
     * The signed content of a detached signature, as bytes: {@code bytes} is read from its position to its limit
     * (neither changes); {@code name} may be null.
     */
    public record DetachedContent(String name, ByteBuffer bytes) {
    }

    /**
     * As {@link #validate(ByteBuffer, String)}, with the signed content of a detached signature passed as buffers
     * instead of base64 inside {@code options_json} (the route behind {@code dss_validate_with_contents}). Each
     * content is added to the options' {@code detached_contents} before any entry the JSON already carries,
     * exactly as if it had been sent as {@code {"name":…,"base64":…}}; the bytes are copied into the Java heap
     * once, inside the error handling, so a content too large for the heap is an {@code INTERNAL_ERROR} result.
     * A null or empty {@code contents} makes this {@link #validate(ByteBuffer, String)}; a null or empty content
     * is {@code INVALID_ARGUMENT} ({@code contents[i] is NULL} / {@code contents[i] is empty}), as the JSON route
     * refuses an empty {@code base64}.
     */
    public static String validate(ByteBuffer document, String optionsJson, List<DetachedContent> contents) {
        return call(() -> {
            DssEngine engine = requireEngine();
            ValidationOptions options = ValidationOptions.fromJson(optionsJson);
            if (contents != null && !contents.isEmpty()) {
                List<DSSDocument> merged = new ArrayList<>(contents.size() + options.detachedContents.size());
                for (int i = 0; i < contents.size(); i++) {
                    DetachedContent content = contents.get(i);
                    if (content == null || content.bytes() == null) {
                        throw new DssError(DssError.Code.INVALID_ARGUMENT, "contents[" + i + "] is NULL");
                    }
                    if (content.bytes().remaining() == 0) {
                        throw new DssError(DssError.Code.INVALID_ARGUMENT, "contents[" + i + "] is empty");
                    }
                    merged.add(new InMemoryDocument(copy(content.bytes()), content.name()));
                }
                merged.addAll(options.detachedContents);
                options = options.withDetachedContents(merged);
            }
            return engine.validate(copy(document), options).toMap();
        });
    }

    /**
     * Result JSON of a call that produces a document ({@link #extend}, {@link #completeSignature}), and the
     * document when the JSON says {@code "ok":true}.
     */
    public record DocumentResult(String json, byte[] document) {
    }

    /**
     * Extends the signatures of a PDF ({@link DssEngine#extend}). As in {@link #validate(ByteBuffer, String)},
     * the document is copied into the Java heap inside the error handling.
     */
    public static DocumentResult extend(ByteBuffer document, String optionsJson) {
        byte[][] produced = new byte[1][];
        boolean[] succeeded = new boolean[1];
        String json = call(() -> {
            DssEngine engine = requireEngine();
            ExtensionResult result = engine.extend(copy(document), ExtensionOptions.fromJson(optionsJson));
            produced[0] = result.document();
            return result.toMap();
        }, () -> succeeded[0] = true);
        return new DocumentResult(json, succeeded[0] ? produced[0] : null);
    }

    public static DocumentResult extend(byte[] document, String optionsJson) {
        return extend(document == null ? null : ByteBuffer.wrap(document), optionsJson);
    }

    /** Step 1 of signing with an external signer ({@link DssEngine#prepareSignature}): the digest to sign. */
    public static String prepareSignature(ByteBuffer document, String optionsJson) {
        return call(() -> {
            DssEngine engine = requireEngine();
            return engine.prepareSignature(copy(document), SigningOptions.fromJson(optionsJson)).toMap();
        });
    }

    public static String prepareSignature(byte[] document, String optionsJson) {
        return prepareSignature(document == null ? null : ByteBuffer.wrap(document), optionsJson);
    }

    /**
     * Step 2 ({@link DssEngine#completeSignature}): the signed document, from what the external signer returned
     * ({@code signature}: a CMS or a bare signature value, as {@code options_json "mode"} says).
     */
    public static DocumentResult completeSignature(ByteBuffer document, String optionsJson, ByteBuffer signature) {
        byte[][] produced = new byte[1][];
        boolean[] succeeded = new boolean[1];
        String json = call(() -> {
            DssEngine engine = requireEngine();
            SigningResult result = engine.completeSignature(copy(document), SigningOptions.fromJson(optionsJson),
                    copy(signature));
            produced[0] = result.document();
            return result.toMap();
        }, () -> succeeded[0] = true);
        return new DocumentResult(json, succeeded[0] ? produced[0] : null);
    }

    public static DocumentResult completeSignature(byte[] document, String optionsJson, byte[] signature) {
        return completeSignature(document == null ? null : ByteBuffer.wrap(document), optionsJson,
                signature == null ? null : ByteBuffer.wrap(signature));
    }

    private static byte[] copy(ByteBuffer document) {
        if (document == null) {
            return null;
        }
        byte[] bytes = new byte[document.remaining()];
        document.duplicate().get(bytes);
        return bytes;
    }

    /**
     * Drops the engine (used when the isolate is torn down). {@code trusted_list_threads_stopped} says whether its
     * trusted-list threads ended within the wait; a thread still inside an HTTP read ends when the socket timeout
     * does, and an isolate teardown waits for it.
     */
    public static String shutdown() {
        return call(() -> {
            DssEngine previous;
            synchronized (INIT_LOCK) {
                previous = engine;
                engine = null;
            }
            boolean stopped = true;
            if (previous != null) {
                previous.close();
                stopped = previous.trustedListThreadsStopped();
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("trusted_list_threads_stopped", stopped);
            return m;
        });
    }

    private static DssEngine requireEngine() {
        DssEngine e = engine;
        if (e == null) {
            throw new DssError(DssError.Code.NOT_INITIALIZED, "dss_init has not completed successfully");
        }
        return e;
    }

    private static String call(Supplier<Map<String, Object>> body) {
        return call(body, () -> { });
    }

    /** {@code onSuccess} runs once the {@code "ok":true} result is encoded, and only then. */
    private static String call(Supplier<Map<String, Object>> body, Runnable onSuccess) {
        try {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("ok", Boolean.TRUE);
            result.putAll(body.get());
            String json = Json.write(result);
            onSuccess.run();
            return json;
        } catch (DssError e) {
            return error(e.code(), e.getMessage());
        } catch (Throwable t) {
            try {
                LoggerFactory.getLogger(DssJsonApi.class).error("Unexpected failure", t);
            } catch (Throwable ignored) {
                // logging must never turn an error result into a crash
            }
            return error(DssError.Code.INTERNAL_ERROR, t.getClass().getName() + ": " + t.getMessage());
        }
    }

    /**
     * Library, DSS and runtime versions (from the Maven-filtered {@code version.properties}) plus
     * {@code api_version}, the integer {@link #API_VERSION} of the C/JSON contract.
     */
    public static String version() {
        return call(() -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("library", BuildInfo.library());
            m.put("dss", BuildInfo.dss());
            m.put("runtime", System.getProperty("java.vm.name") + " " + System.getProperty("java.vm.version"));
            m.put("api_version", (long) API_VERSION);
            return m;
        });
    }

    /** Builds an error result without anything that could itself throw (beyond OOM). */
    public static String error(DssError.Code code, String message) {
        Map<String, Object> err = new LinkedHashMap<>();
        err.put("code", code.name());
        err.put("message", message == null ? code.name() : message);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("ok", Boolean.FALSE);
        result.put("error", err);
        return Json.write(result);
    }

    /** Loggers that print request headers, and with them the TSA's Basic credentials, at debug. */
    static final List<String> SECRET_BEARING_LOGGERS = List.of("org.apache.hc.client5.http.headers",
            "org.apache.hc.client5.http.wire");

    /**
     * slf4j-simple reads its level once, when the first logger is created. In the native library dss_init is the
     * first call, so setting the property here works; a later dss_init on the same isolate cannot change it, and
     * on the JVM it only applies if nothing logged before. The level in force is returned (and reported by init),
     * so a caller sees when the one it asked for did not take. Whatever the level, Apache HttpClient's header
     * and wire loggers are held at info: at debug they print {@code Authorization: Basic …} to the TSA.
     *
     * @return the level slf4j-simple uses
     */
    static String applyLogLevel(String level) {
        for (String logger : SECRET_BEARING_LOGGERS) {
            System.setProperty("org.slf4j.simpleLogger.log." + logger, "info");
        }
        String property = "org.slf4j.simpleLogger.defaultLogLevel";
        if (System.getProperty(property) == null) {
            System.setProperty(property, level);
        }
        System.setProperty("org.slf4j.simpleLogger.logFile", "System.err");
        String effective = System.getProperty(property);
        if (!effective.equalsIgnoreCase(level)) {
            LoggerFactory.getLogger(DssJsonApi.class).warn("log_level '{}' requested, but the logging level was "
                    + "fixed at '{}' when the process first logged and cannot change", level, effective);
        }
        return effective;
    }
}
