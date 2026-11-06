/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import eu.europa.esig.dss.enumerations.SignatureLevel;

/**
 * Outcome of {@link DssEngine#extend}: the extended document, which is the input PDF (after any base64/PEM
 * decoding) followed by an incremental update. DSS appends one even when it has no new validation data.
 */
public record ExtensionResult(byte[] document, String containerType, List<String> transformations,
                              SignatureLevel level) {

    /** The JSON shape returned by {@code dss_extend} (minus {@code ok}); the document travels separately. */
    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("container", containerType);
        m.put("transformations", transformations);
        m.put("level", level.toString());
        return m;
    }
}
