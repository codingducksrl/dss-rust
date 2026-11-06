/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

/** An expected failure with a stable code; becomes {@code {"ok":false,"error":{code,message}}} at the API boundary. */
public final class DssError extends RuntimeException {
    private static final long serialVersionUID = 1L;

    /** Stable error codes. Rust maps these 1:1, so only ever add to this list. */
    public enum Code {
        /** A null/empty/malformed argument (bad JSON, unknown option value, missing file). */
        INVALID_ARGUMENT,
        /** {@code config_json} is invalid, or a file it references cannot be loaded. */
        INVALID_CONFIG,
        /** Called before a successful {@code init}. */
        NOT_INITIALIZED,
        /** No trusted list has been loaded yet (empty cache and no successful online refresh). */
        TRUSTED_LISTS_NOT_LOADED,
        /** An online refresh is already running; this call did not start another one. */
        REFRESH_IN_PROGRESS,
        /** The online refresh could not run at all (per-list download/parse errors are in the status instead). */
        TL_REFRESH_FAILED,
        /** The input is neither a PDF nor a CMS/CAdES structure (after base64/PEM unwrapping). */
        UNSUPPORTED_DOCUMENT,
        /** DSS could not process the document (corrupt structure, unreadable PDF, …). */
        VALIDATION_FAILED,
        /**
         * DSS refused to extend the signatures or could not (invalid signature, revoked or expired certificate,
         * missing revocation data, already at a higher level, no TSA configured or the TSA failed, …).
         */
        EXTENSION_FAILED,
        /**
         * A signature could not be prepared or completed: the external signature does not match the document and
         * options (wrong digest, signer or key, or not a usable CMS), the signing certificate is expired or not yet
         * valid, the CMS does not fit the space reserved in the PDF, or DSS refused to add the requested level (no
         * TSA configured, the TSA failed, revocation data missing, …).
         */
        SIGNING_FAILED,
        /** Anything unexpected, including JVM errors. */
        INTERNAL_ERROR,
        /**
         * The trusted-list snapshot named by {@code tl_snapshot} cannot be used: unreadable, not a snapshot, corrupt,
         * written by another DSS version or with other trusted-list settings, or holding a list that can no longer be
         * used under {@code tl_sync}.
         */
        TL_SNAPSHOT_REJECTED
    }

    private final Code code;

    public DssError(Code code, String message) {
        super(message);
        this.code = code;
    }

    public DssError(Code code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public Code code() {
        return code;
    }
}
