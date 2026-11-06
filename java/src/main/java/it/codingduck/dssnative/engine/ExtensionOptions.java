/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import java.util.Locale;
import java.util.Map;
import java.util.Set;

import eu.europa.esig.dss.enumerations.SignatureLevel;

/** Per-call options of {@link DssEngine#extend}, parsed from {@code options_json}. */
public final class ExtensionOptions {

    /** Target level. The format follows the document: PAdES for a PDF (the only kind extended for now). */
    public enum Level {
        T(SignatureLevel.PAdES_BASELINE_T),
        LT(SignatureLevel.PAdES_BASELINE_LT),
        LTA(SignatureLevel.PAdES_BASELINE_LTA);

        final SignatureLevel pades;

        Level(SignatureLevel pades) {
            this.pades = pades;
        }
    }

    public final Level level;
    /** Name of the document in DSS's messages. */
    public final String filename;

    public ExtensionOptions(Level level, String filename) {
        this.level = level;
        this.filename = filename;
    }

    public static ExtensionOptions fromJson(String json) {
        Map<String, Object> map;
        try {
            map = Json.parseObject(json);
        } catch (Json.ParseException e) {
            throw new DssError(DssError.Code.INVALID_ARGUMENT, "options_json is not valid JSON: " + e.getMessage());
        }
        JsonFields f = new JsonFields(map, "options", DssError.Code.INVALID_ARGUMENT)
                .allowOnly(Set.of("level", "filename"));
        Level level;
        try {
            level = Level.valueOf(f.requiredString("level").toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw f.error("'level' must be \"T\", \"LT\" or \"LTA\"");
        }
        return new ExtensionOptions(level, f.string("filename", null));
    }
}
