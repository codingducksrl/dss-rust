/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** DSS reports a caller can ask for. The simple report is always returned. */
public enum ReportKind {
    SIMPLE("simple_report_xml"),
    DETAILED("detailed_report_xml"),
    ETSI("etsi_report_xml"),
    DIAGNOSTIC("diagnostic_data_xml");

    private final String jsonKey;

    ReportKind(String jsonKey) {
        this.jsonKey = jsonKey;
    }

    public String jsonKey() {
        return jsonKey;
    }

    static Set<ReportKind> parse(List<String> names, DssError.Code code, String where) {
        Set<ReportKind> out = EnumSet.of(SIMPLE);
        for (String name : names) {
            try {
                out.add(ReportKind.valueOf(name.toUpperCase(Locale.ROOT)));
            } catch (IllegalArgumentException e) {
                throw new DssError(code, where + ": unknown report '" + name + "' (simple, detailed, etsi, diagnostic)");
            }
        }
        return out;
    }
}
