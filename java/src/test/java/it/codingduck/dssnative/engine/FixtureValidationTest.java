/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;

import it.codingduck.dssnative.testsupport.Fixtures;
import it.codingduck.dssnative.testsupport.TestEngines;

/**
 * Every committed fixture against its expected verdict, with trust coming from the synthetic LOTL/TL (so the full
 * trusted-list path is exercised) and revocation from the in-memory CRL endpoint.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FixtureValidationTest {

    private static final String PASSED = "TOTAL_PASSED/-";
    private static final String HASH_FAILURE = "TOTAL_FAILED/HASH_FAILURE";

    private DssEngine engine;
    private final List<String> table = new ArrayList<>();

    @BeforeAll
    void setUp(@TempDir Path tmp) {
        engine = new TestEngines(tmp).onlineLoaded(tmp.resolve("cache"), null);
    }

    @AfterAll
    void tearDown() {
        engine.close();
        System.out.println("\nFixture results\n" + String.join("\n", table));
    }

    /** fixture, expected container, transformations, expected verdict per signature, expected format. */
    static Stream<Arguments> fixtures() {
        return Stream.of(
                Arguments.of("cades/attached-der.p7m", "CMS", List.of(), List.of(PASSED), "CAdES-BASELINE-B"),
                Arguments.of("cades/attached-ber.p7m", "CMS", List.of(), List.of(PASSED), "CAdES-BASELINE-B"),
                Arguments.of("cades/attached-base64.p7m", "CMS", List.of("base64"), List.of(PASSED), "CAdES-BASELINE-B"),
                Arguments.of("cades/multi-signer.p7m", "CMS", List.of(), List.of(PASSED, PASSED), "CAdES-BASELINE-B"),
                Arguments.of("cades/detached.txt.p7s", "CMS", List.of(),
                        List.of("INDETERMINATE/SIGNED_DATA_NOT_FOUND"), "CAdES-BASELINE-B"),
                Arguments.of("pades/b-b.pdf", "PDF", List.of(), List.of(PASSED), "PAdES-BASELINE-B"),
                Arguments.of("pades/b-t.pdf", "PDF", List.of(), List.of(PASSED), "PAdES-BASELINE-T"),
                Arguments.of("pades/b-lt.pdf", "PDF", List.of(), List.of(PASSED), "PAdES-BASELINE-LT"),
                Arguments.of("pades/b-lta.pdf", "PDF", List.of(), List.of(PASSED), "PAdES-BASELINE-LTA"),
                Arguments.of("tampered/cades/attached-der.p7m", "CMS", List.of(), List.of(HASH_FAILURE), "CAdES-BASELINE-B"),
                Arguments.of("tampered/cades/attached-ber.p7m", "CMS", List.of(), List.of(HASH_FAILURE), "CAdES-BASELINE-B"),
                Arguments.of("tampered/cades/attached-base64.p7m", "CMS", List.of("base64"), List.of(HASH_FAILURE),
                        "CAdES-BASELINE-B"),
                Arguments.of("tampered/cades/multi-signer.p7m", "CMS", List.of(), List.of(HASH_FAILURE, HASH_FAILURE),
                        "CAdES-BASELINE-B"),
                Arguments.of("tampered/pades/b-b.pdf", "PDF", List.of(), List.of(HASH_FAILURE), "PAdES-BASELINE-B"),
                Arguments.of("tampered/pades/b-t.pdf", "PDF", List.of(), List.of(HASH_FAILURE), "PAdES-BASELINE-T"),
                Arguments.of("tampered/pades/b-lt.pdf", "PDF", List.of(), List.of(HASH_FAILURE), "PAdES-BASELINE-LT"),
                Arguments.of("tampered/pades/b-lta.pdf", "PDF", List.of(), List.of(HASH_FAILURE), "PAdES-BASELINE-LTA"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("fixtures")
    void fixtureHasExpectedVerdict(String fixture, String container, List<String> transformations,
                                   List<String> verdicts, String format) {
        ValidationResult r = engine.validate(Fixtures.read(fixture), ValidationOptions.DEFAULT);
        record(fixture, r);
        assertEquals(container, r.containerType);
        assertEquals(transformations, r.transformations);
        assertEquals(verdicts, verdicts(r));
        r.signatures.forEach(s -> assertEquals(format, s.format().toString(), fixture));
        assertTrue(r.reports.get(ReportKind.SIMPLE).contains("SimpleReport"));
    }

    @Test
    void nestedP7mIsValidatedAtEveryLevel() {
        ValidationResult r = engine.validate(Fixtures.read("cades/nested.p7m.p7m"), ValidationOptions.DEFAULT);
        record("cades/nested.p7m.p7m", r);
        assertEquals(List.of(PASSED), verdicts(r));
        assertEquals("Giulia Bianchi (TEST)", r.signatures.get(0).signedBy());
        assertEquals(1, r.nested.size());
        assertEquals(List.of(PASSED), verdicts(r.nested.get(0)));
        assertEquals("Mario Rossi (TEST)", r.nested.get(0).signatures.get(0).signedBy());
        assertTrue(r.nested.get(0).nested.isEmpty());
    }

    @Test
    void tamperedNestedP7mFailsAtEveryLevel() {
        ValidationResult r = engine.validate(Fixtures.read("tampered/cades/nested.p7m.p7m"), ValidationOptions.DEFAULT);
        record("tampered/cades/nested.p7m.p7m", r);
        assertEquals(List.of(HASH_FAILURE), verdicts(r));
        assertEquals(List.of(HASH_FAILURE), verdicts(r.nested.get(0)));
    }

    @Test
    void nestedUnwrappingCanBeDisabled() {
        ValidationResult r = engine.validate(Fixtures.read("cades/nested.p7m.p7m"),
                ValidationOptions.fromJson("{\"unwrap_nested\":false}"));
        assertTrue(r.nested.isEmpty());
    }

    @Test
    void detachedSignatureWithItsContentPasses() {
        ValidationResult r = engine.validate(Fixtures.read("cades/detached.txt.p7s"), detached("content/document.txt"));
        record("cades/detached.txt.p7s + content", r);
        assertEquals(List.of(PASSED), verdicts(r));
    }

    @Test
    void detachedSignatureWithTamperedContentFails() {
        ValidationResult r = engine.validate(Fixtures.read("cades/detached.txt.p7s"),
                detached("tampered/content/document.txt"));
        record("cades/detached.txt.p7s + tampered content", r);
        assertEquals(List.of(HASH_FAILURE), verdicts(r));
    }

    @Test
    void requestedReportsAreReturned() {
        ValidationResult r = engine.validate(Fixtures.read("pades/b-lta.pdf"),
                ValidationOptions.fromJson("{\"reports\":[\"detailed\",\"etsi\",\"diagnostic\"]}"));
        assertTrue(r.reports.get(ReportKind.DETAILED).contains("DetailedReport"));
        assertTrue(r.reports.get(ReportKind.ETSI).contains("ValidationReport"));
        assertTrue(r.reports.get(ReportKind.DIAGNOSTIC).contains("DiagnosticData"));
    }

    private static ValidationOptions detached(String contentFixture) {
        return ValidationOptions.fromJson("{\"detached_contents\":[{\"name\":\"document.txt\",\"path\":\""
                + Fixtures.path(contentFixture).toString().replace("\\", "\\\\") + "\"}]}");
    }

    static List<String> verdicts(ValidationResult r) {
        List<String> out = new ArrayList<>();
        for (ValidationResult.SignatureSummary s : r.signatures) {
            out.add(verdict(s.indication(), s.subIndication()));
        }
        return out;
    }

    static String verdict(Indication i, SubIndication s) {
        return i + "/" + (s == null ? "-" : s.name());
    }

    private synchronized void record(String fixture, ValidationResult r) {
        for (ValidationResult.SignatureSummary s : r.signatures) {
            table.add(String.format("%-46s %-4s %-10s %-36s %-20s %s", fixture, r.containerType, r.transformations,
                    verdict(s.indication(), s.subIndication()), s.format(), s.signedBy()));
        }
        for (ValidationResult n : r.nested) {
            record("  └ nested", n);
        }
    }
}
