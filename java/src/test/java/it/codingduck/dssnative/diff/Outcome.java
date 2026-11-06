/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.diff;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import it.codingduck.dssnative.engine.ValidationResult;

/**
 * What the differential test compares for one document: per signature the fields named in the brief
 * (indication, sub-indication, level, qualification, signing time, signer DN), at every nesting level, or the
 * fact that the document was rejected.
 */
public record Outcome(String error, List<SignatureRecord> signatures, List<Outcome> nested) {

    public record SignatureRecord(String id, String indication, String subIndication, String format,
                                  String qualification, String signingTime, String signerDn) {
    }

    public static Outcome rejected(String error) {
        return new Outcome(error, List.of(), List.of());
    }

    static String iso(Date d) {
        return d == null ? null : d.toInstant().toString();
    }

    /** From the engine on the JVM. */
    public static Outcome of(ValidationResult r) {
        List<SignatureRecord> sigs = new ArrayList<>();
        for (ValidationResult.SignatureSummary s : r.signatures) {
            sigs.add(new SignatureRecord(s.id(), s.indication() == null ? null : s.indication().name(),
                    s.subIndication() == null ? null : s.subIndication().name(),
                    s.format() == null ? null : s.format().toString(),
                    s.qualification() == null ? null : s.qualification().name(),
                    iso(s.signingTime()), s.signerDn()));
        }
        List<Outcome> nested = new ArrayList<>();
        r.nested.forEach(n -> nested.add(of(n)));
        return new Outcome(null, sigs, nested);
    }

    /** From the native library's result JSON (as printed by {@code dss-cli validate-batch}). */
    @SuppressWarnings("unchecked")
    public static Outcome ofJson(Map<String, Object> result) {
        List<SignatureRecord> sigs = new ArrayList<>();
        for (Object o : (List<Object>) result.getOrDefault("signatures", List.of())) {
            Map<String, Object> s = (Map<String, Object>) o;
            sigs.add(new SignatureRecord((String) s.get("id"), (String) s.get("indication"),
                    (String) s.get("sub_indication"), (String) s.get("format"), (String) s.get("qualification"),
                    (String) s.get("signing_time"), (String) s.get("signer_dn")));
        }
        List<Outcome> nested = new ArrayList<>();
        for (Object n : (List<Object>) result.getOrDefault("nested", List.of())) {
            nested.add(ofJson((Map<String, Object>) n));
        }
        return new Outcome(null, sigs, nested);
    }

    /** Differences between {@code expected} (plain DSS) and {@code actual}, as readable lines; empty if equal. */
    public static List<String> compare(Outcome expected, Outcome actual) {
        List<String> out = new ArrayList<>();
        compare("", expected, actual, out);
        return out;
    }

    private static void compare(String path, Outcome e, Outcome a, List<String> out) {
        if ((e.error == null) != (a.error == null)) {
            out.add(path + "rejected: plain DSS=" + (e.error != null ? e.error : "no") + ", other="
                    + (a.error != null ? a.error : "no"));
            return;
        }
        if (e.error != null) {
            return; // both rejected the document; the messages legitimately differ
        }
        if (e.signatures.size() != a.signatures.size()) {
            out.add(path + "signature count: plain DSS=" + e.signatures.size() + ", other=" + a.signatures.size());
        }
        for (SignatureRecord es : e.signatures) {
            SignatureRecord as = a.signatures.stream().filter(s -> s.id().equals(es.id())).findFirst().orElse(null);
            String p = path + es.id() + " ";
            if (as == null) {
                out.add(p + "missing in other");
                continue;
            }
            field(p + "indication", es.indication(), as.indication(), out);
            field(p + "sub_indication", es.subIndication(), as.subIndication(), out);
            field(p + "format", es.format(), as.format(), out);
            field(p + "qualification", es.qualification(), as.qualification(), out);
            field(p + "signing_time", es.signingTime(), as.signingTime(), out);
            field(p + "signer_dn", es.signerDn(), as.signerDn(), out);
        }
        if (e.nested.size() != a.nested.size()) {
            out.add(path + "nested levels: plain DSS=" + e.nested.size() + ", other=" + a.nested.size());
        }
        for (int i = 0; i < Math.min(e.nested.size(), a.nested.size()); i++) {
            compare(path + "nested[" + i + "] ", e.nested.get(i), a.nested.get(i), out);
        }
    }

    private static void field(String what, String expected, String actual, List<String> out) {
        if (expected == null ? actual != null : !expected.equals(actual)) {
            out.add(what + ": plain DSS=" + expected + ", other=" + actual);
        }
    }
}
