/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.ffi;

import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.graalvm.nativeimage.IsolateThread;
import org.graalvm.nativeimage.UnmanagedMemory;
import org.graalvm.nativeimage.c.CHeader;
import org.graalvm.nativeimage.c.function.CEntryPoint;
import org.graalvm.nativeimage.c.type.CCharPointer;
import org.graalvm.nativeimage.c.type.CCharPointerPointer;
import org.graalvm.nativeimage.c.type.CConst;
import org.graalvm.nativeimage.c.type.CTypeConversion;
import org.graalvm.nativeimage.c.type.CTypedef;
import org.graalvm.nativeimage.c.type.WordPointer;
import org.graalvm.word.UnsignedWord;
import org.graalvm.word.WordFactory;
import org.slf4j.LoggerFactory;

import it.codingduck.dssnative.engine.DssError;
import it.codingduck.dssnative.engine.DssJsonApi;
import it.codingduck.dssnative.engine.RuntimeDefaults;

/**
 * The C API. C strings in, {@link DssJsonApi} call, C string out. The engine behaviour and its error handling
 * live in {@code DssJsonApi}, tested on the JVM; this class only decodes arguments strictly ({@link #fromC}),
 * encodes results into malloc'd memory ({@link #toC}) and turns what escapes {@code DssJsonApi} into an error
 * result ({@link #failure}).
 *
 * <p>Every function takes the calling thread's {@code graal_isolatethread_t*} first. Strings are UTF-8 and
 * NUL-terminated, and are decoded strictly: a malformed string is refused as {@code INVALID_ARGUMENT} rather than
 * repaired with U+FFFD and acted upon (a {@code cache_dir} with a replaced byte would create the cache at another
 * path, with a success result). Every returned pointer, including the document {@code dss_extend} and
 * {@code dss_sign_complete} hand back through their out-parameters, is owned by the caller and must be released
 * with {@code dss_free}. A NULL return means that not even an error result could be malloc'd.
 *
 * <p>{@code dss_validate_with_contents} takes the signed content of a detached signature as binary buffers, so a
 * host does not base64-encode megabytes into {@code options_json}; the views of the caller's buffers go straight
 * to {@code DssJsonApi.validate(ByteBuffer, String, List)}, which copies each one into the Java heap once.
 *
 * <p>No Java exception may unwind into C (that aborts the process), so every entry point catches
 * {@code Throwable} itself. A custom {@code CEntryPoint.exceptionHandler} would need the internal
 * {@code @Uninterruptible} annotation, which is not part of the public SDK. What escapes {@code DssJsonApi}'s
 * own handling (an {@code OutOfMemoryError} while decoding a string argument or copying a result, for instance)
 * becomes the same {@code INTERNAL_ERROR} result {@code DssJsonApi} would have produced, written by
 * {@link #failure} without allocating on the Java heap, so that it can still be built when the heap is exhausted.
 *
 * <p>Native Image does not deliver an {@code OutOfMemoryError} from an allocation to a handler in the same
 * compiled frame: it unwinds to the caller, here the C entry stub, which aborts the process. So the entry
 * points allocate nothing large themselves. The document is handed over as a {@code ByteBuffer} view and copied
 * inside {@code DssJsonApi}'s error handling. Results are encoded to UTF-8 straight into malloc'd memory,
 * without a Java byte array, and an extended or signed document is copied from the array {@code DssJsonApi}
 * returns.
 *
 * <p>The isolate-thread handle is checked on entry ({@code -H:+CheckIsolateThreadAtEntry} in
 * {@code native-image.properties}): a handle of another thread, or of a detached one, is a fatal error with a
 * message instead of silent memory corruption. A NULL handle and one of a torn-down isolate are fatal too. These
 * are the preconditions of every Native Image C API, not results of this library; docs/native-library.md lists
 * them.
 */
@CHeader(DssLib.Header.class)
public final class DssLib {

    /** {@code libdssnative.h}: self-contained, so it can be the first include (it uses {@code size_t}). */
    public static final class Header implements CHeader.Header {
        @Override
        public String name() {
            return "libdssnative";
        }

        @Override
        public void writePreamble(PrintWriter writer) {
            writer.println("#include <stddef.h>");
            writer.println("#include <graal_isolate.h>"); // a custom header loses the generator's own include
        }
    }

    /** {@code byte[]} limit, minus the headroom the JDK reserves. */
    private static final long MAX_DOCUMENT_BYTES = Integer.MAX_VALUE - 8;

    /**
     * Most detached contents one {@code dss_validate_with_contents} call takes. The entry point allocates an
     * array per content before any error handling can run (see the class comment), so the count is bounded;
     * a detached signature covers a handful of files.
     */
    private static final long MAX_CONTENTS = 1024;

    /** Per isolate: static state is not shared between isolates. */
    private static volatile boolean defaultsApplied;

    private DssLib() {
    }

    @CEntryPoint(name = "dss_init", documentation = {
            "Builds the engine and loads the trusted lists from <cache_dir>/tl (offline, no network), or from the",
            "trusted-list snapshot config_json \"tl_snapshot\" names (TL_SNAPSHOT_REJECTED if it cannot be used).",
            "Calling it again replaces the engine. Returns result JSON: {\"ok\":true,...} or {\"ok\":false,\"error\":{...}}."})
    public static CCharPointer init(IsolateThread thread, @CConst CCharPointer cacheDir,
                                    @CConst CCharPointer configJson) {
        try {
            prologue();
            return toC(DssJsonApi.init(fromC(cacheDir, "cache_dir"), fromC(configJson, "config_json")));
        } catch (Throwable t) {
            return failure(t);
        }
    }

    @CEntryPoint(name = "dss_tl_refresh_online", documentation = {
            "Downloads and validates the LOTL and national trusted lists. Blocking.",
            "Validation keeps working meanwhile. Returns REFRESH_IN_PROGRESS if a refresh is already running."})
    public static CCharPointer refreshTrustedListsOnline(IsolateThread thread) {
        try {
            prologue();
            return toC(DssJsonApi.refreshTrustedListsOnline());
        } catch (Throwable t) {
            return failure(t);
        }
    }

    @CEntryPoint(name = "dss_tl_status", documentation = {
            "Trusted-list status JSON: loaded, last refreshes, per-list state, alerts. Never blocks on a refresh."})
    public static CCharPointer trustedListStatus(IsolateThread thread) {
        try {
            prologue();
            return toC(DssJsonApi.trustedListStatus());
        } catch (Throwable t) {
            return failure(t);
        }
    }

    @CEntryPoint(name = "dss_tl_export_snapshot", documentation = {
            "The loaded trusted lists as a trusted-list snapshot file, for config_json \"tl_snapshot\": an engine",
            "started from it parses and validates no list. On success *out_snapshot receives the file (*out_len",
            "bytes; release it with dss_free), otherwise NULL and 0. The result JSON describes the snapshot."})
    public static CCharPointer exportTlSnapshot(IsolateThread thread, CCharPointerPointer outSnapshot,
                                                @CTypedef(name = "size_t *") WordPointer outLen) {
        try {
            prologue();
            if (outSnapshot.isNull() || outLen.isNull()) {
                return toC(DssJsonApi.error(DssError.Code.INVALID_ARGUMENT, "out_snapshot and out_len are required"));
            }
            outSnapshot.write(WordFactory.nullPointer());
            outLen.write(WordFactory.zero());
            return toC(DssJsonApi.exportTlSnapshot(), outSnapshot, outLen);
        } catch (Throwable t) {
            return failure(t);
        }
    }

    @CEntryPoint(name = "dss_validate", documentation = {
            "Validates a PDF or CMS/CAdES document of len bytes. options_json may be NULL.",
            "The input buffer is only read during the call."})
    public static CCharPointer validate(IsolateThread thread, @CConst CCharPointer bytes,
                                        @CTypedef(name = "size_t") UnsignedWord len,
                                        @CConst CCharPointer optionsJson) {
        try {
            prologue();
            if (bytes.isNonNull() && len.aboveThan(WordFactory.unsigned(MAX_DOCUMENT_BYTES))) {
                return toC(tooLarge());
            }
            return toC(DssJsonApi.validate(view(bytes, len), fromC(optionsJson, "options_json")));
        } catch (Throwable t) {
            return failure(t);
        }
    }

    @CEntryPoint(name = "dss_validate_with_contents", documentation = {
            "As dss_validate, with the signed content of a detached signature passed as count binary buffers:",
            "contents[i] of lens[i] bytes, named names[i] (names, or an entry of it, may be NULL). They are added",
            "to options_json \"detached_contents\" (which may also carry entries) without a base64 round trip.",
            "count is at most 1024; a NULL or empty content is INVALID_ARGUMENT. The input buffers are only read",
            "during the call."})
    public static CCharPointer validateWithContents(IsolateThread thread, @CConst CCharPointer bytes,
                                                    @CTypedef(name = "size_t") UnsignedWord len,
                                                    @CTypedef(name = "size_t") UnsignedWord count,
                                                    @CConst CCharPointerPointer names,
                                                    @CConst CCharPointerPointer contents,
                                                    @CConst @CTypedef(name = "size_t *") WordPointer lens,
                                                    @CConst CCharPointer optionsJson) {
        try {
            prologue();
            if (bytes.isNonNull() && len.aboveThan(WordFactory.unsigned(MAX_DOCUMENT_BYTES))) {
                return toC(tooLarge());
            }
            if (count.aboveThan(WordFactory.unsigned(MAX_CONTENTS))) {
                return toC(DssJsonApi.error(DssError.Code.INVALID_ARGUMENT, "count larger than " + MAX_CONTENTS));
            }
            int n = (int) count.rawValue();
            if (n > 0 && (contents.isNull() || lens.isNull())) {
                return toC(DssJsonApi.error(DssError.Code.INVALID_ARGUMENT,
                        "contents and lens are required when count is not 0"));
            }
            // Views only (no copy): the bytes are copied into the Java heap inside DssJsonApi's error handling.
            List<DssJsonApi.DetachedContent> detached = new ArrayList<>(n);
            for (int i = 0; i < n; i++) {
                CCharPointer content = contents.read(i);
                UnsignedWord contentLen = lens.read(i);
                if (content.isNull()) {
                    return toC(DssJsonApi.error(DssError.Code.INVALID_ARGUMENT, "contents[" + i + "] is NULL"));
                }
                if (contentLen.aboveThan(WordFactory.unsigned(MAX_DOCUMENT_BYTES))) {
                    return toC(DssJsonApi.error(DssError.Code.INVALID_ARGUMENT,
                            "contents[" + i + "] larger than " + MAX_DOCUMENT_BYTES + " bytes"));
                }
                String name = names.isNull() ? null : fromC(names.read(i), "names[" + i + "]");
                detached.add(new DssJsonApi.DetachedContent(name, view(content, contentLen)));
            }
            return toC(DssJsonApi.validate(view(bytes, len), fromC(optionsJson, "options_json"), detached));
        } catch (Throwable t) {
            return failure(t);
        }
    }

    @CEntryPoint(name = "dss_extend", documentation = {
            "Extends the signatures of a PDF of len bytes to PAdES-BASELINE-T, -LT or -LTA (options_json \"level\").",
            "On success *out_document receives the extended PDF (*out_len bytes; release it with dss_free).",
            "Otherwise *out_document is NULL and *out_len 0. The input buffer is only read during the call."})
    public static CCharPointer extend(IsolateThread thread, @CConst CCharPointer bytes,
                                      @CTypedef(name = "size_t") UnsignedWord len,
                                      @CConst CCharPointer optionsJson, CCharPointerPointer outDocument,
                                      @CTypedef(name = "size_t *") WordPointer outLen) {
        try {
            prologue();
            if (outDocument.isNull() || outLen.isNull()) {
                return toC(DssJsonApi.error(DssError.Code.INVALID_ARGUMENT, "out_document and out_len are required"));
            }
            outDocument.write(WordFactory.nullPointer());
            outLen.write(WordFactory.zero());
            if (bytes.isNonNull() && len.aboveThan(WordFactory.unsigned(MAX_DOCUMENT_BYTES))) {
                return toC(tooLarge());
            }
            return toC(DssJsonApi.extend(view(bytes, len), fromC(optionsJson, "options_json")), outDocument, outLen);
        } catch (Throwable t) {
            return failure(t);
        }
    }

    @CEntryPoint(name = "dss_sign_prepare", documentation = {
            "Signing with an external signer, step 1: the digest it must sign, for a document of len bytes and",
            "options_json (mode, level, format, ...). Returns {\"ok\":true,\"digest\":<base64>,\"signing_time\":...}.",
            "The input buffer is only read during the call."})
    public static CCharPointer signPrepare(IsolateThread thread, @CConst CCharPointer bytes,
                                           @CTypedef(name = "size_t") UnsignedWord len,
                                           @CConst CCharPointer optionsJson) {
        try {
            prologue();
            if (bytes.isNonNull() && len.aboveThan(WordFactory.unsigned(MAX_DOCUMENT_BYTES))) {
                return toC(tooLarge());
            }
            return toC(DssJsonApi.prepareSignature(view(bytes, len), fromC(optionsJson, "options_json")));
        } catch (Throwable t) {
            return failure(t);
        }
    }

    @CEntryPoint(name = "dss_sign_complete", documentation = {
            "Step 2: the signed document, from the same document and options_json as dss_sign_prepare (plus the",
            "signing_time it returned) and what the external signer returned (signature, signature_len bytes: a CMS",
            "or a bare signature value, as options_json \"mode\" says). On success *out_document receives the",
            "signed document (*out_len bytes; release it with dss_free), otherwise NULL and 0.",
            "The input buffers are only read during the call."})
    public static CCharPointer signComplete(IsolateThread thread, @CConst CCharPointer bytes,
                                            @CTypedef(name = "size_t") UnsignedWord len,
                                            @CConst CCharPointer optionsJson, @CConst CCharPointer signature,
                                            @CTypedef(name = "size_t") UnsignedWord signatureLen,
                                            CCharPointerPointer outDocument,
                                            @CTypedef(name = "size_t *") WordPointer outLen) {
        try {
            prologue();
            if (outDocument.isNull() || outLen.isNull()) {
                return toC(DssJsonApi.error(DssError.Code.INVALID_ARGUMENT, "out_document and out_len are required"));
            }
            outDocument.write(WordFactory.nullPointer());
            outLen.write(WordFactory.zero());
            if ((bytes.isNonNull() && len.aboveThan(WordFactory.unsigned(MAX_DOCUMENT_BYTES)))
                    || (signature.isNonNull() && signatureLen.aboveThan(WordFactory.unsigned(MAX_DOCUMENT_BYTES)))) {
                return toC(tooLarge());
            }
            return toC(DssJsonApi.completeSignature(view(bytes, len), fromC(optionsJson, "options_json"),
                    view(signature, signatureLen)), outDocument, outLen);
        } catch (Throwable t) {
            return failure(t);
        }
    }

    @CEntryPoint(name = "dss_version", documentation = {
            "Library, DSS and GraalVM versions, as JSON."})
    public static CCharPointer version(IsolateThread thread) {
        try {
            prologue();
            return toC(DssJsonApi.version());
        } catch (Throwable t) {
            return failure(t);
        }
    }

    @CEntryPoint(name = "dss_shutdown", documentation = {
            "Stops the engine's background threads. Call before graal_tear_down_isolate."})
    public static CCharPointer shutdown(IsolateThread thread) {
        try {
            return toC(DssJsonApi.shutdown());
        } catch (Throwable t) {
            return failure(t);
        }
    }

    @CEntryPoint(name = "dss_free", documentation = {
            "Frees a string or document returned by any dss_* function. NULL is ignored."})
    public static void free(IsolateThread thread, CCharPointer pointer) {
        if (pointer.isNonNull()) {
            UnmanagedMemory.free(pointer);
        }
    }

    // ------------------------------------------------------------------ helpers

    private static void prologue() {
        if (!defaultsApplied) {
            RuntimeDefaults.apply();
            defaultsApplied = true;
        }
    }

    /** A read-only view of the caller's buffer (no copy), or null for a NULL pointer. len is at most 2^31 - 9. */
    private static ByteBuffer view(CCharPointer bytes, UnsignedWord len) {
        return bytes.isNull() ? null : CTypeConversion.asByteBuffer(bytes, (int) len.rawValue()).asReadOnlyBuffer();
    }

    /**
     * The result JSON; on success the document is copied into malloc'd memory and handed out too. The document,
     * the large allocation, comes first: if it fails nothing has been allocated yet, and if the JSON's malloc
     * then fails the document is released again, so that a failing call leaks nothing.
     */
    private static CCharPointer toC(DssJsonApi.DocumentResult result, CCharPointerPointer outDocument,
                                    WordPointer outLen) {
        byte[] document = result.document();
        CCharPointer out = WordFactory.nullPointer();
        CCharPointer json;
        try {
            if (document != null) {
                out = UnmanagedMemory.malloc(WordFactory.unsigned(Math.max(1, document.length)));
                CTypeConversion.asByteBuffer(out, document.length).put(document);
            }
            json = toC(result.json());
        } catch (Throwable t) {
            if (out.isNonNull()) {
                UnmanagedMemory.free(out);
            }
            throw t;
        }
        if (document != null) {
            outDocument.write(out);
            outLen.write(WordFactory.unsigned(document.length));
        }
        return json;
    }

    private static String tooLarge() {
        return DssJsonApi.error(DssError.Code.INVALID_ARGUMENT, "document larger than " + MAX_DOCUMENT_BYTES + " bytes");
    }

    /**
     * The Java string of a NUL-terminated C string, or null for a NULL pointer. Strictly decoded: a malformed
     * sequence is an {@code INVALID_ARGUMENT} ({@link DssError}, turned into the result by {@link #failure})
     * naming the parameter and the byte offset, never a U+FFFD the engine would act on.
     */
    private static String fromC(CCharPointer s, String name) {
        if (s.isNull()) {
            return null;
        }
        long len = 0;
        while (s.read(WordFactory.signed(len)) != 0) {
            if (++len > MAX_DOCUMENT_BYTES) {
                throw new DssError(DssError.Code.INVALID_ARGUMENT, name + " longer than " + MAX_DOCUMENT_BYTES + " bytes");
            }
        }
        int malformed = StrictUtf8.firstMalformed(CTypeConversion.asByteBuffer(s, (int) len));
        if (malformed >= 0) {
            throw new DssError(DssError.Code.INVALID_ARGUMENT, name + " is not valid UTF-8 (byte " + malformed + ")");
        }
        return CTypeConversion.toJavaString(s, WordFactory.unsigned(len), StandardCharsets.UTF_8);
    }

    /**
     * The result for a {@code Throwable} that escaped {@code DssJsonApi} (an {@code OutOfMemoryError} decoding a
     * string argument or copying a result, or an {@code INVALID_ARGUMENT} from {@link #fromC}): the same
     * {@code {"ok":false,"error":{...}}} {@code DssJsonApi.error} builds, but written straight into malloc'd memory
     * from strings that already exist, with no Java-heap allocation, so it can be produced when the heap is
     * exhausted. Only if even that malloc fails is NULL returned. An unexpected failure is logged as
     * {@code DssJsonApi.call} logs its own, but only once the result exists: logging allocates, and the result
     * must not be lost to a second {@code OutOfMemoryError}. Never throws.
     */
    private static CCharPointer failure(Throwable t) {
        CCharPointer result;
        try {
            if (t instanceof DssError e) {
                return errorToC(e.code(), e.getMessage(), null, null);
            }
            result = errorToC(DssError.Code.INTERNAL_ERROR, t.getClass().getName(), ": ", t.getMessage());
        } catch (Throwable ignored) {
            return WordFactory.nullPointer();
        }
        try {
            LoggerFactory.getLogger(DssLib.class).error("Unexpected failure", t);
        } catch (Throwable ignored) {
            // The caller gets the result either way.
        }
        return result;
    }

    /**
     * {@code {"ok":false,"error":{"code":"<code>","message":"<m1><m2><m3>"}}} as NUL-terminated UTF-8 in malloc'd
     * memory, the message parts JSON-escaped as {@code Json.write} does (null parts are skipped). Allocates no Java
     * object: this is the failure path.
     */
    private static CCharPointer errorToC(DssError.Code code, String m1, String m2, String m3) {
        long size = writeError(WordFactory.nullPointer(), code, m1, m2, m3);
        CCharPointer out = UnmanagedMemory.malloc(WordFactory.unsigned(size + 1));
        long o = writeError(out, code, m1, m2, m3);
        out.write(WordFactory.signed(o), (byte) 0);
        return out;
    }

    private static long writeError(CCharPointer out, DssError.Code code, String m1, String m2, String m3) {
        long o = write(out, 0, "{\"ok\":false,\"error\":{\"code\":\"", false);
        o = write(out, o, code.name(), false);
        o = write(out, o, "\",\"message\":\"", false);
        o = write(out, o, m1 == null && m2 == null && m3 == null ? code.name() : m1, true);
        o = write(out, o, m2, true);
        o = write(out, o, m3, true);
        return write(out, o, "\"}}", false);
    }

    /**
     * Encodes {@code s} as NUL-terminated UTF-8 into malloc'd memory the caller frees with {@code dss_free}.
     * No Java heap allocation (see the class comment). Unpaired surrogates become U+FFFD, as in
     * {@code String.getBytes(UTF_8)}.
     */
    private static CCharPointer toC(String s) {
        long size = write(WordFactory.nullPointer(), 0, s, false);
        CCharPointer out = UnmanagedMemory.malloc(WordFactory.unsigned(size + 1));
        long o = write(out, 0, s, false);
        out.write(WordFactory.signed(o), (byte) 0);
        return out;
    }

    /**
     * Writes {@code s} as UTF-8 at offset {@code o} of {@code out} and returns the offset after it; with a NULL
     * {@code out} it only measures. A null {@code s} writes nothing. With {@code jsonEscape}, the characters
     * {@code Json.write} escapes inside a JSON string are escaped the same way.
     */
    private static long write(CCharPointer out, long o, String s, boolean jsonEscape) {
        if (s == null) {
            return o;
        }
        int len = s.length();
        for (int i = 0; i < len; i++) {
            int c = s.charAt(i);
            if (Character.isHighSurrogate((char) c) && i + 1 < len && Character.isLowSurrogate(s.charAt(i + 1))) {
                c = Character.toCodePoint((char) c, s.charAt(++i));
            } else if (Character.isSurrogate((char) c)) {
                c = 0xFFFD;
            }
            if (jsonEscape && (c < 0x20 || c == '"' || c == '\\' || c == 0x2028 || c == 0x2029)) {
                o = writeEscaped(out, o, c);
            } else if (c < 0x80) {
                o = put(out, o, c);
            } else if (c < 0x800) {
                o = put(out, o, 0xC0 | (c >> 6));
                o = put(out, o, 0x80 | (c & 0x3F));
            } else if (c < 0x10000) {
                o = put(out, o, 0xE0 | (c >> 12));
                o = put(out, o, 0x80 | ((c >> 6) & 0x3F));
                o = put(out, o, 0x80 | (c & 0x3F));
            } else {
                o = put(out, o, 0xF0 | (c >> 18));
                o = put(out, o, 0x80 | ((c >> 12) & 0x3F));
                o = put(out, o, 0x80 | ((c >> 6) & 0x3F));
                o = put(out, o, 0x80 | (c & 0x3F));
            }
        }
        return o;
    }

    private static final String HEX = "0123456789abcdef";

    private static long writeEscaped(CCharPointer out, long o, int c) {
        o = put(out, o, '\\');
        switch (c) {
            case '"': return put(out, o, '"');
            case '\\': return put(out, o, '\\');
            case '\n': return put(out, o, 'n');
            case '\r': return put(out, o, 'r');
            case '\t': return put(out, o, 't');
            case '\b': return put(out, o, 'b');
            case '\f': return put(out, o, 'f');
            default:
                o = put(out, o, 'u');
                o = put(out, o, HEX.charAt((c >> 12) & 0xF));
                o = put(out, o, HEX.charAt((c >> 8) & 0xF));
                o = put(out, o, HEX.charAt((c >> 4) & 0xF));
                return put(out, o, HEX.charAt(c & 0xF));
        }
    }

    private static long put(CCharPointer out, long o, int b) {
        if (out.isNonNull()) {
            out.write(WordFactory.signed(o), (byte) b);
        }
        return o + 1;
    }
}
