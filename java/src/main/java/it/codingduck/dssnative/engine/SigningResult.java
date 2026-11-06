/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import java.util.LinkedHashMap;
import java.util.Map;

import eu.europa.esig.dss.enumerations.SignatureLevel;

/**
 * Outcome of {@link DssEngine#completeSignature}: the signed document. For PAdES, the PDF followed by the
 * signature revision (and, from T up, the revisions extension added); for CAdES, the CMS ({@code .p7s} detached,
 * {@code .p7m} enveloping).
 *
 * @param level     the level reached: the requested one, or T when an external CMS asked for at B already
 *                  carries a signature timestamp
 * @param packaging {@code ENVELOPED} for PAdES; {@code DETACHED} or {@code ENVELOPING} for CAdES
 */
public record SigningResult(byte[] document, SigningOptions.Format format, SignatureLevel level, String packaging) {

    /** The JSON shape returned by {@code dss_sign_complete} (minus {@code ok}); the document travels separately. */
    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("format", format == SigningOptions.Format.PADES ? "PAdES" : "CAdES");
        m.put("level", level.toString());
        m.put("packaging", packaging);
        return m;
    }
}
