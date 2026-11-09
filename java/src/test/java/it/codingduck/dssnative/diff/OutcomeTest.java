/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.diff;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

/** The comparator itself must catch every kind of difference, or the differential test proves nothing. */
class OutcomeTest {

    private static final Outcome.SignatureRecord SIG = new Outcome.SignatureRecord("S-1", "TOTAL_PASSED", null,
            "PAdES-BASELINE-LTA", "QESIG", "2026-01-01T00:00:00Z", "CN=A,C=IT");

    private static Outcome with(Outcome.SignatureRecord s) {
        return new Outcome(List.of(s), List.of());
    }

    @Test
    void equalOutcomesHaveNoDifferences() {
        assertTrue(Outcome.compare(with(SIG), with(SIG)).isEmpty());
        assertTrue(Outcome.compare(Outcome.rejected("VALIDATION_FAILED", "x"),
                Outcome.rejected("VALIDATION_FAILED", "y")).isEmpty());
        assertTrue(Outcome.compare(Outcome.rejected(null, "x"), Outcome.rejected("UNSUPPORTED_DOCUMENT", "y")).isEmpty(),
                "an unknown code is not a difference");
    }

    @Test
    void everyComparedFieldIsDetected() {
        List<Outcome.SignatureRecord> variants = List.of(
                new Outcome.SignatureRecord("S-1", "INDETERMINATE", null, SIG.format(), SIG.qualification(), SIG.signingTime(), SIG.signerDn()),
                new Outcome.SignatureRecord("S-1", SIG.indication(), "TRY_LATER", SIG.format(), SIG.qualification(), SIG.signingTime(), SIG.signerDn()),
                new Outcome.SignatureRecord("S-1", SIG.indication(), null, "PAdES-BASELINE-B", SIG.qualification(), SIG.signingTime(), SIG.signerDn()),
                new Outcome.SignatureRecord("S-1", SIG.indication(), null, SIG.format(), "ADESIG", SIG.signingTime(), SIG.signerDn()),
                new Outcome.SignatureRecord("S-1", SIG.indication(), null, SIG.format(), SIG.qualification(), "2026-01-01T00:00:01Z", SIG.signerDn()),
                new Outcome.SignatureRecord("S-1", SIG.indication(), null, SIG.format(), SIG.qualification(), SIG.signingTime(), "CN=B,C=IT"),
                new Outcome.SignatureRecord("S-2", SIG.indication(), null, SIG.format(), SIG.qualification(), SIG.signingTime(), SIG.signerDn()));
        for (Outcome.SignatureRecord v : variants) {
            assertEquals(1, Outcome.compare(with(SIG), with(v)).size(), v.toString());
        }
    }

    @Test
    void theReasonForARejectionIsCompared() {
        List<String> diff = Outcome.compare(Outcome.rejected("UNSUPPORTED_DOCUMENT", "not a PDF or CMS"),
                Outcome.rejected("VALIDATION_FAILED", "cannot parse document"));
        assertEquals(List.of("error code: plain DSS=UNSUPPORTED_DOCUMENT, other=VALIDATION_FAILED"), diff);
    }

    @Test
    void structureDifferencesAreDetected() {
        assertEquals(1, Outcome.compare(with(SIG), Outcome.rejected(null, "x")).size());
        assertTrue(!Outcome.compare(with(SIG), new Outcome(List.of(), List.of())).isEmpty(), "missing signature");
        Outcome nested = new Outcome(List.of(SIG), List.of(with(SIG)));
        assertEquals(1, Outcome.compare(nested, with(SIG)).size());
        Outcome nestedDifferent = new Outcome(List.of(SIG), List.of(Outcome.rejected(null, "x")));
        assertEquals(1, Outcome.compare(nested, nestedDifferent).size());
    }
}
