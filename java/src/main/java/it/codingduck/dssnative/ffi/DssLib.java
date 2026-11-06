/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.ffi;

import java.io.PrintWriter;
import java.nio.ByteBuffer;

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

import it.codingduck.dssnative.engine.DssError;
import it.codingduck.dssnative.engine.DssJsonApi;
import it.codingduck.dssnative.engine.RuntimeDefaults;

/**
 * The C API. Thin by design: C strings in, {@link DssJsonApi} call, C string out. All behaviour, including
 * catching every {@code Throwable}, lives in {@code DssJsonApi}, which is tested on the JVM.
 *
 * <p>Every function takes the calling thread's {@code graal_isolatethread_t*} first. Strings are UTF-8 and
 * NUL-terminated. Every returned pointer, including the document {@code dss_extend} and {@code dss_sign_complete}
 * hand back through their out-parameters, is owned by the caller and must be released with {@code dss_free}. A NULL return means the
 * library could not even build an error result (out of memory).
 *
 * <p>No Java exception may unwind into C (that aborts the process), so every entry point catches
 * {@code Throwable} itself. A custom {@code CEntryPoint.exceptionHandler} would need the internal
 * {@code @Uninterruptible} annotation, which is not part of the public SDK.
 *
 * <p>Native Image does not deliver an {@code OutOfMemoryError} from an allocation to a handler in the same
 * compiled frame: it unwinds to the caller, here the C entry stub, which aborts the process. So the entry
 * points allocate nothing large themselves. The document is handed over as a {@code ByteBuffer} view and copied
 * inside {@code DssJsonApi}'s error handling. Results are encoded to UTF-8 straight into malloc'd memory,
 * without a Java byte array, and an extended or signed document is copied from the array {@code DssJsonApi}
 * returns.
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
            return toC(DssJsonApi.init(fromC(cacheDir), fromC(configJson)));
        } catch (Throwable t) {
            return WordFactory.nullPointer();
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
            return WordFactory.nullPointer();
        }
    }

    @CEntryPoint(name = "dss_tl_status", documentation = {
            "Trusted-list status JSON: loaded, last refreshes, per-list state, alerts. Never blocks on a refresh."})
    public static CCharPointer trustedListStatus(IsolateThread thread) {
        try {
            prologue();
            return toC(DssJsonApi.trustedListStatus());
        } catch (Throwable t) {
            return WordFactory.nullPointer();
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
            return WordFactory.nullPointer();
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
            return toC(DssJsonApi.validate(view(bytes, len), fromC(optionsJson)));
        } catch (Throwable t) {
            return WordFactory.nullPointer();
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
            return toC(DssJsonApi.extend(view(bytes, len), fromC(optionsJson)), outDocument, outLen);
        } catch (Throwable t) {
            return WordFactory.nullPointer();
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
            return toC(DssJsonApi.prepareSignature(view(bytes, len), fromC(optionsJson)));
        } catch (Throwable t) {
            return WordFactory.nullPointer();
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
            return toC(DssJsonApi.completeSignature(view(bytes, len), fromC(optionsJson), view(signature, signatureLen)),
                    outDocument, outLen);
        } catch (Throwable t) {
            return WordFactory.nullPointer();
        }
    }

    @CEntryPoint(name = "dss_version", documentation = {
            "Library, DSS and GraalVM versions, as JSON."})
    public static CCharPointer version(IsolateThread thread) {
        try {
            prologue();
            return toC(DssJsonApi.version());
        } catch (Throwable t) {
            return WordFactory.nullPointer();
        }
    }

    @CEntryPoint(name = "dss_shutdown", documentation = {
            "Stops the engine's background threads. Call before graal_tear_down_isolate."})
    public static CCharPointer shutdown(IsolateThread thread) {
        try {
            return toC(DssJsonApi.shutdown());
        } catch (Throwable t) {
            return WordFactory.nullPointer();
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

    /** The result JSON; on success the document is copied into malloc'd memory and handed out too. */
    private static CCharPointer toC(DssJsonApi.DocumentResult result, CCharPointerPointer outDocument,
                                    WordPointer outLen) {
        CCharPointer json = toC(result.json());
        byte[] document = result.document();
        if (document != null) {
            CCharPointer out = UnmanagedMemory.malloc(WordFactory.unsigned(Math.max(1, document.length)));
            CTypeConversion.asByteBuffer(out, document.length).put(document);
            outDocument.write(out);
            outLen.write(WordFactory.unsigned(document.length));
        }
        return json;
    }

    private static String tooLarge() {
        return DssJsonApi.error(DssError.Code.INVALID_ARGUMENT, "document larger than " + MAX_DOCUMENT_BYTES + " bytes");
    }

    private static String fromC(CCharPointer s) {
        return s.isNull() ? null : CTypeConversion.utf8ToJavaString(s);
    }

    /**
     * Encodes {@code s} as NUL-terminated UTF-8 into malloc'd memory the caller frees with {@code dss_free}.
     * No Java heap allocation (see the class comment). Unpaired surrogates become U+FFFD, as in
     * {@code String.getBytes(UTF_8)}.
     */
    private static CCharPointer toC(String s) {
        int len = s.length();
        long size = 0;
        for (int i = 0; i < len; i++) {
            char c = s.charAt(i);
            if (c < 0x80) {
                size += 1;
            } else if (c < 0x800) {
                size += 2;
            } else if (Character.isHighSurrogate(c) && i + 1 < len && Character.isLowSurrogate(s.charAt(i + 1))) {
                size += 4;
                i++;
            } else {
                size += 3; // BMP character, or an unpaired surrogate encoded as U+FFFD
            }
        }
        CCharPointer out = UnmanagedMemory.malloc(WordFactory.unsigned(size + 1));
        int o = 0;
        for (int i = 0; i < len; i++) {
            int c = s.charAt(i);
            if (Character.isHighSurrogate((char) c) && i + 1 < len && Character.isLowSurrogate(s.charAt(i + 1))) {
                c = Character.toCodePoint((char) c, s.charAt(++i));
            } else if (Character.isSurrogate((char) c)) {
                c = 0xFFFD;
            }
            if (c < 0x80) {
                out.write(o++, (byte) c);
            } else if (c < 0x800) {
                out.write(o++, (byte) (0xC0 | (c >> 6)));
                out.write(o++, (byte) (0x80 | (c & 0x3F)));
            } else if (c < 0x10000) {
                out.write(o++, (byte) (0xE0 | (c >> 12)));
                out.write(o++, (byte) (0x80 | ((c >> 6) & 0x3F)));
                out.write(o++, (byte) (0x80 | (c & 0x3F)));
            } else {
                out.write(o++, (byte) (0xF0 | (c >> 18)));
                out.write(o++, (byte) (0x80 | ((c >> 12) & 0x3F)));
                out.write(o++, (byte) (0x80 | ((c >> 6) & 0x3F)));
                out.write(o++, (byte) (0x80 | (c & 0x3F)));
            }
        }
        out.write(o, (byte) 0);
        return out;
    }
}
