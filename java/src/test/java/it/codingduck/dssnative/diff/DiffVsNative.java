/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.diff;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import it.codingduck.dssnative.engine.EngineConfig;
import it.codingduck.dssnative.engine.Json;

/**
 * Compares the native library's results (JSON lines from {@code dss-cli validate-batch}) with plain DSS on this
 * JVM ({@link PlainDssReference}) for the same cases, config, cache and validation time. Run by
 * scripts/diff-vs-jvm.sh.
 *
 * <pre>DiffVsNative --config F --cache D --cases F --native F --validation-time T --report F [--name N]</pre>
 *
 * Exit status 1 if any document differs or is missing from the native output.
 */
public final class DiffVsNative {

    private DiffVsNative() {
    }

    public static void main(String[] argv) throws Exception {
        Map<String, String> a = new HashMap<>();
        for (int i = 0; i + 1 < argv.length; i += 2) {
            a.put(argv[i], argv[i + 1]);
        }
        String name = a.getOrDefault("--name", "documents");
        Path base = Path.of(a.getOrDefault("--base", ".")).toAbsolutePath().normalize();
        EngineConfig config = EngineConfig.fromJson(Files.readString(Path.of(a.get("--config"))));
        Date validationTime = Date.from(Instant.parse(a.get("--validation-time")));

        // One native line per case, in case order (the same document can appear in several cases, e.g. a
        // detached signature with different contents), so cases are matched by position, and the file checked.
        List<String> nativeFiles = new ArrayList<>();
        List<Outcome> nativeResults = new ArrayList<>();
        for (String line : Files.readAllLines(Path.of(a.get("--native")))) {
            if (line.isBlank()) {
                continue;
            }
            Map<String, Object> m = Json.parseObject(line);
            @SuppressWarnings("unchecked")
            Outcome o = Boolean.TRUE.equals(m.get("ok"))
                    ? Outcome.ofJson((Map<String, Object>) m.get("result"))
                    : Outcome.rejected(String.valueOf(((Map<?, ?>) m.get("error")).get("code")));
            nativeFiles.add((String) m.get("file"));
            nativeResults.add(o);
        }

        List<String[]> rows = new ArrayList<>();
        List<String> details = new ArrayList<>();
        int differing = 0;
        int signatures = 0;
        try (PlainDssReference reference = new PlainDssReference(Path.of(a.get("--cache")), config)) {
            for (String line : Files.readAllLines(Path.of(a.get("--cases")))) {
                if (line.isBlank() || line.startsWith("#")) {
                    continue;
                }
                String[] parts = line.split("\t");
                String file = parts[0];
                List<Path> detached = new ArrayList<>();
                for (int i = 1; i < parts.length; i++) {
                    detached.add(Path.of(parts[i]));
                }
                Outcome expected = reference.validate(Files.readAllBytes(Path.of(file)), detached, validationTime);
                int index = rows.size();
                List<String> diff;
                if (index >= nativeResults.size()) {
                    diff = List.of("missing from the native output");
                } else if (!file.equals(nativeFiles.get(index))) {
                    diff = List.of("native output out of order: line " + (index + 1) + " is " + nativeFiles.get(index));
                } else {
                    diff = Outcome.compare(expected, nativeResults.get(index));
                }
                int sigs = count(expected);
                signatures += sigs;
                String label = relative(base, Path.of(file))
                        + (detached.isEmpty() ? "" : " + " + relative(base, detached.get(0)));
                rows.add(new String[] {label, verdicts(expected), diff.isEmpty() ? "same" : "**DIFFERENT**"});
                if (!diff.isEmpty()) {
                    differing++;
                    details.add("### " + label + "\n\n" + String.join("\n", diff.stream().map(d -> "- " + d).toList()));
                }
            }
            StringBuilder md = new StringBuilder();
            md.append("# Differential test: ").append(name).append("\n\n")
                    .append("Plain DSS on the JVM vs the native library through Rust (`dss-cli validate-batch`).\n\n")
                    .append("- validation time: `").append(validationTime.toInstant()).append("`\n")
                    .append("- trusted certificates from the cached lists: ").append(reference.trustedListCertificates())
                    .append("\n- revocation: ").append(config.revocation.name().toLowerCase()).append("\n")
                    .append("- compared per signature: indication, sub-indication, level, qualification, signing time, "
                            + "signer DN, at every nesting level\n\n")
                    .append("**").append(rows.size()).append(" documents, ").append(signatures).append(" signatures, ")
                    .append(differing).append(" different.**\n\n")
                    .append("| Document | Plain DSS verdicts | Native |\n|---|---|---|\n");
            for (String[] r : rows) {
                md.append("| `").append(r[0]).append("` | ").append(r[1]).append(" | ").append(r[2]).append(" |\n");
            }
            if (!details.isEmpty()) {
                md.append("\n## Differences\n\n").append(String.join("\n\n", details)).append('\n');
            }
            Files.writeString(Path.of(a.get("--report")), md.toString());
        }
        System.out.println(name + ": " + rows.size() + " documents, " + signatures + " signatures, " + differing
                + " different (report: " + a.get("--report") + ")");
        details.forEach(System.out::println);
        System.exit(differing == 0 ? 0 : 1);
    }

    private static String relative(Path base, Path p) {
        Path abs = p.toAbsolutePath().normalize();
        return abs.startsWith(base) ? base.relativize(abs).toString() : abs.toString();
    }

    private static int count(Outcome o) {
        int n = o.signatures().size();
        for (Outcome nested : o.nested()) {
            n += count(nested);
        }
        return n;
    }

    private static String verdicts(Outcome o) {
        if (o.error() != null) {
            return "rejected";
        }
        List<String> v = new ArrayList<>();
        for (Outcome.SignatureRecord s : o.signatures()) {
            v.add(s.indication() + (s.subIndication() == null ? "" : "/" + s.subIndication()));
        }
        for (Outcome n : o.nested()) {
            v.add("nested: " + verdicts(n));
        }
        return v.isEmpty() ? "no signature" : String.join(", ", v);
    }
}
