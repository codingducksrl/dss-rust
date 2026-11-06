/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

/**
 * Outcome of {@link DssEngine#prepareSignature}: what to send to the external signer.
 *
 * @param digest      the digest the external signer signs: in {@link SigningOptions.Mode#CMS} the content's
 *                    (for PAdES, the PDF's signed byte ranges'), in {@link SigningOptions.Mode#SIGNATURE_VALUE} that
 *                    of {@code dataToSign}
 * @param dataToSign  {@link SigningOptions.Mode#SIGNATURE_VALUE} only: the DER signed attributes, for signers that
 *                    hash the data themselves; null otherwise
 * @param signingTime the signing time the signature claims; {@code complete} needs it back
 */
public record PreparedSignature(SigningOptions.Format format, DigestAlgorithm digestAlgorithm, byte[] digest,
                                byte[] dataToSign, Instant signingTime) {

    /** The JSON shape returned by {@code dss_sign_prepare} (minus {@code ok}). */
    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("format", format == SigningOptions.Format.PADES ? "PAdES" : "CAdES");
        m.put("digest_algorithm", digestAlgorithm.getName());
        m.put("digest", Base64.getEncoder().encodeToString(digest));
        if (dataToSign != null) {
            m.put("data_to_sign", Base64.getEncoder().encodeToString(dataToSign));
        }
        m.put("signing_time", signingTime.toString());
        return m;
    }
}
