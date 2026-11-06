/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

/** Per-call options, parsed from {@code options_json}. */
public final class ValidationOptions {

    /** Reports to return; null means the engine's configured default. */
    public final Set<ReportKind> reports;
    /** Signed content for detached signatures. */
    public final List<DSSDocument> detachedContents;
    /** Validate as of this instant instead of now. */
    public final Instant validationTime;
    /** Name used for the document in the reports. */
    public final String filename;
    /** Also validate CAdES envelopes nested inside the signed content (Italian {@code .p7m.p7m}). */
    public final boolean unwrapNested;

    public static final ValidationOptions DEFAULT = new ValidationOptions(null, Collections.emptyList(), null, null, true);

    public ValidationOptions(Set<ReportKind> reports, List<DSSDocument> detachedContents, Instant validationTime,
                             String filename, boolean unwrapNested) {
        this.reports = reports;
        this.detachedContents = detachedContents;
        this.validationTime = validationTime;
        this.filename = filename;
        this.unwrapNested = unwrapNested;
    }

    public static ValidationOptions fromJson(String json) {
        Map<String, Object> map;
        try {
            map = Json.parseObject(json);
        } catch (Json.ParseException e) {
            throw new DssError(DssError.Code.INVALID_ARGUMENT, "options_json is not valid JSON: " + e.getMessage());
        }
        JsonFields f = new JsonFields(map, "options", DssError.Code.INVALID_ARGUMENT)
                .allowOnly(Set.of("reports", "detached_contents", "validation_time", "filename", "unwrap_nested"));

        Set<ReportKind> reports = f.has("reports")
                ? ReportKind.parse(f.strings("reports", List.of()), DssError.Code.INVALID_ARGUMENT, "options")
                : null;

        List<DSSDocument> detached = new ArrayList<>();
        for (JsonFields d : f.objects("detached_contents")) {
            d.allowOnly(Set.of("name", "path", "base64"));
            String name = d.string("name", null);
            if (d.has("path") == d.has("base64")) {
                throw d.error("exactly one of 'path' or 'base64' is required");
            }
            if (d.has("path")) {
                Path p = Path.of(d.requiredString("path"));
                if (!Files.isRegularFile(p)) {
                    throw d.error("file not found: " + p);
                }
                FileDocument doc = new FileDocument(p.toFile());
                if (name != null) {
                    doc.setName(name);
                }
                detached.add(doc);
            } else {
                byte[] bytes;
                try {
                    bytes = Base64.getMimeDecoder().decode(d.requiredString("base64"));
                } catch (IllegalArgumentException e) {
                    throw d.error("'base64' is not valid base64");
                }
                detached.add(new InMemoryDocument(bytes, name));
            }
        }

        Instant validationTime = null;
        String vt = f.string("validation_time", null);
        if (vt != null) {
            try {
                validationTime = Instant.parse(vt);
            } catch (DateTimeParseException e) {
                throw f.error("'validation_time' must be ISO-8601 UTC, e.g. 2026-01-31T12:00:00Z");
            }
        }

        return new ValidationOptions(reports, detached, validationTime, f.string("filename", null),
                f.bool("unwrap_nested", true));
    }
}
