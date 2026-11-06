/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;

import it.codingduck.dssnative.engine.ExtensionOptions.Level;
import it.codingduck.dssnative.testsupport.Fixtures;
import it.codingduck.dssnative.testsupport.TestEngines;
import it.codingduck.dssnative.testsupport.TestPki;

/**
 * {@link DssEngine#extend} on the PAdES fixtures, with trust from the synthetic LOTL/TL and the CRL and TSA served
 * in memory. Each extended document is validated again, also by an engine that never fetches revocation data, so
 * it passes only on what the extension embedded.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ExtensionTest {

    private static final String PASSED = "TOTAL_PASSED/-";

    private TestEngines t;
    /** Revocation online (the in-memory CRL), TSA configured. */
    private DssEngine engine;
    /** As {@link #engine}, without a TSA. */
    private DssEngine noTsa;
    /** Embedded revocation data only. */
    private DssEngine offline;

    @BeforeAll
    void setUp(@TempDir Path tmp) {
        t = new TestEngines(tmp);
        engine = t.onlineLoaded(tmp.resolve("cache"), TestEngines.tsa());
        noTsa = t.onlineLoaded(tmp.resolve("cache-no-tsa"), null);
        offline = t.onlineLoaded(tmp.resolve("cache-offline"), "\"revocation\":\"offline\",\"aia\":false,"
                + TestEngines.tsa());
    }

    @AfterAll
    void tearDown() {
        engine.close();
        noTsa.close();
        offline.close();
    }

    private static ExtensionOptions to(Level level) {
        return new ExtensionOptions(level, null);
    }

    private int tsaHits() {
        return t.http.hits(TestPki.TSA_URL);
    }

    private static void assertValidatesAs(DssEngine e, byte[] pdf, String format) {
        ValidationResult v = e.validate(pdf, ValidationOptions.DEFAULT);
        assertEquals(List.of(PASSED), FixtureValidationTest.verdicts(v));
        assertEquals(format, v.signatures.get(0).format().toString());
    }

    private static DssError fails(DssError.Code code, Executable call) {
        DssError e = assertThrows(DssError.class, call);
        assertEquals(code, e.code(), e.getMessage());
        return e;
    }

    @Test
    void tToLtEmbedsTheRevocationData() {
        byte[] in = Fixtures.read("pades/b-t.pdf");
        assertNotEquals(List.of(PASSED), FixtureValidationTest.verdicts(offline.validate(in, ValidationOptions.DEFAULT)),
                "without the extension, offline validation lacks revocation data");
        int hits = tsaHits();

        ExtensionResult r = engine.extend(in, to(Level.LT));
        assertEquals(hits, tsaHits(), "T to LT needs no timestamp");
        assertEquals("PDF", r.containerType());
        assertEquals(List.of(), r.transformations());
        assertEquals("PAdES-BASELINE-LT", r.level().toString());
        assertArrayEquals(in, Arrays.copyOf(r.document(), in.length), "an incremental update keeps the original bytes");
        assertValidatesAs(engine, r.document(), "PAdES-BASELINE-LT");
        assertValidatesAs(offline, r.document(), "PAdES-BASELINE-LT");
        // T to LT works without a TSA too.
        assertValidatesAs(engine, noTsa.extend(in, to(Level.LT)).document(), "PAdES-BASELINE-LT");
    }

    @Test
    void bToTAddsADocumentTimestamp() {
        int hits = tsaHits();
        ExtensionResult r = engine.extend(Fixtures.read("pades/b-b.pdf"), to(Level.T));
        assertEquals(hits + 1, tsaHits());
        assertValidatesAs(engine, r.document(), "PAdES-BASELINE-T");
    }

    @Test
    void tToTAddsAnotherDocumentTimestamp() {
        int hits = tsaHits();
        ExtensionResult r = engine.extend(Fixtures.read("pades/b-t.pdf"), to(Level.T));
        assertEquals(hits + 1, tsaHits());
        assertValidatesAs(engine, r.document(), "PAdES-BASELINE-T");
    }

    @Test
    void ltToLtaAddsAnArchiveTimestamp() {
        int hits = tsaHits();
        ExtensionResult r = engine.extend(Fixtures.read("pades/b-lt.pdf"), to(Level.LTA));
        assertEquals(hits + 1, tsaHits());
        assertValidatesAs(engine, r.document(), "PAdES-BASELINE-LTA");
        assertValidatesAs(offline, r.document(), "PAdES-BASELINE-LTA");
    }

    @Test
    void bToLtaGoesThroughEveryLevel() {
        int hits = tsaHits();
        ExtensionResult r = engine.extend(Fixtures.read("pades/b-b.pdf"), to(Level.LTA));
        assertEquals(hits + 2, tsaHits(), "signature timestamp, then archive timestamp");
        assertValidatesAs(engine, r.document(), "PAdES-BASELINE-LTA");
        assertValidatesAs(offline, r.document(), "PAdES-BASELINE-LTA");
    }

    @Test
    void ltaCanBeExtendedAgain() {
        int hits = tsaHits();
        ExtensionResult r = engine.extend(Fixtures.read("pades/b-lta.pdf"), to(Level.LTA));
        assertEquals(hits + 1, tsaHits());
        assertTrue(r.document().length > Fixtures.read("pades/b-lta.pdf").length);
        assertValidatesAs(offline, r.document(), "PAdES-BASELINE-LTA");
    }

    @Test
    void ltToLtAgainStaysValid() {
        byte[] in = Fixtures.read("pades/b-lt.pdf");
        ExtensionResult r = offline.extend(in, to(Level.LT));
        assertArrayEquals(in, Arrays.copyOf(r.document(), in.length));
        assertValidatesAs(offline, r.document(), "PAdES-BASELINE-LT");
    }

    @Test
    void base64InputIsDecoded() {
        byte[] in = Fixtures.read("pades/b-t.pdf");
        byte[] b64 = Base64.getMimeEncoder().encode(in);
        ExtensionResult r = engine.extend(b64, to(Level.LT));
        assertEquals(List.of("base64"), r.transformations());
        assertArrayEquals(in, Arrays.copyOf(r.document(), in.length), "the result is the decoded PDF, extended");
        assertValidatesAs(offline, r.document(), "PAdES-BASELINE-LT");
    }

    @Test
    void aLowerTargetThanTheSignatureIsRefused() {
        DssError e = fails(DssError.Code.EXTENSION_FAILED,
                () -> engine.extend(Fixtures.read("pades/b-lta.pdf"), to(Level.LT)));
        assertTrue(e.getMessage().contains("already extended with a higher level"), e.getMessage());
    }

    @Test
    void aNeededTimestampWithoutTsaIsReported() {
        for (String fixture : List.of("pades/b-lt.pdf", "pades/b-b.pdf")) {
            Level level = fixture.endsWith("b-b.pdf") ? Level.LT : Level.LTA;
            DssError e = fails(DssError.Code.EXTENSION_FAILED, () -> noTsa.extend(Fixtures.read(fixture), to(level)));
            assertTrue(e.getMessage().contains("no TSA is configured"), fixture + ": " + e.getMessage());
        }
    }

    @Test
    void aTamperedSignatureIsRefused() {
        DssError e = fails(DssError.Code.EXTENSION_FAILED,
                () -> engine.extend(Fixtures.read("tampered/pades/b-t.pdf"), to(Level.LT)));
        assertTrue(e.getMessage().contains("Cryptographic signature verification has failed"), e.getMessage());
    }

    @Test
    void missingRevocationDataIsRefused() {
        DssError e = fails(DssError.Code.EXTENSION_FAILED,
                () -> offline.extend(Fixtures.read("pades/b-t.pdf"), to(Level.LT)));
        assertTrue(e.getMessage().contains("Revocation data is missing"), e.getMessage());
    }

    @Test
    void anUnsignedPdfIsRefused() {
        DssError e = fails(DssError.Code.EXTENSION_FAILED,
                () -> engine.extend(Fixtures.read("content/document.pdf"), to(Level.LT)));
        assertTrue(e.getMessage().contains("No signatures found"), e.getMessage());
    }

    @Test
    void onlyPdfsAreExtended() {
        fails(DssError.Code.UNSUPPORTED_DOCUMENT, () -> engine.extend(Fixtures.read("cades/attached-der.p7m"),
                to(Level.LT)));
        fails(DssError.Code.UNSUPPORTED_DOCUMENT,
                () -> engine.extend("hello".getBytes(StandardCharsets.US_ASCII), to(Level.LT)));
        fails(DssError.Code.INVALID_ARGUMENT, () -> engine.extend(new byte[0], to(Level.LT)));
        fails(DssError.Code.INVALID_ARGUMENT, () -> engine.extend(null, to(Level.LT)));
    }

    @Test
    void optionsAreParsed() {
        assertEquals(Level.LTA, ExtensionOptions.fromJson("{\"level\":\"lta\",\"filename\":\"x.pdf\"}").level);
        assertTrue(fails(DssError.Code.INVALID_ARGUMENT, () -> ExtensionOptions.fromJson(null))
                .getMessage().contains("'level' is required"));
        fails(DssError.Code.INVALID_ARGUMENT, () -> ExtensionOptions.fromJson("{\"level\":\"B\"}"));
        fails(DssError.Code.INVALID_ARGUMENT, () -> ExtensionOptions.fromJson("{\"level\":\"LT\",\"reports\":[]}"));
        fails(DssError.Code.INVALID_ARGUMENT, () -> ExtensionOptions.fromJson("{level"));
    }

    @Test
    void tsaConfigIsChecked() {
        EngineConfig c = EngineConfig.fromJson(t.configJson(
                "\"tsa\":{\"url\":\"https://tsa.example.test/tsr\",\"username\":\"u\",\"password\":\"p\"}"));
        assertEquals("tsa.example.test", c.tsaUrl.getHost());
        assertEquals("u", c.tsaUsername);
        assertNull(EngineConfig.fromJson(t.configJson(null)).tsaUrl);
        for (String bad : List.of("{\"url\":\"ftp://tsa.example.test\"}", "{\"url\":\"not a url\"}",
                "{\"url\":\"https://tsa.example.test\",\"username\":\"u\"}", "{\"username\":\"u\",\"password\":\"p\"}",
                "{\"url\":\"https://tsa.example.test\",\"policy\":\"1.2.3\"}")) {
            fails(DssError.Code.INVALID_CONFIG, () -> EngineConfig.fromJson(t.configJson("\"tsa\":" + bad)));
        }
    }
}
