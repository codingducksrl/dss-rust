/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.diff;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import it.codingduck.dssnative.engine.DssEngine;
import it.codingduck.dssnative.engine.DssError;
import it.codingduck.dssnative.engine.EngineConfig;
import it.codingduck.dssnative.engine.ValidationOptions;
import it.codingduck.dssnative.testsupport.Fixtures;
import it.codingduck.dssnative.testsupport.TestEngines;

/**
 * The engine against plain DSS, both on the JVM, over every fixture and with trust coming from the synthetic
 * trusted lists. The same comparison the native differential run does (scripts/diff-vs-jvm.sh), so wrapper bugs
 * show up here, without a native build.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PlainDssParityTest {

    private DssEngine engine;
    private PlainDssReference reference;
    private final Date validationTime = new Date();

    @BeforeAll
    void setUp(@TempDir Path tmp) throws Exception {
        TestEngines t = new TestEngines(tmp);
        Path cache = tmp.resolve("cache");
        String config = t.configJson("\"revocation\":\"offline\",\"aia\":false");
        t.onlineLoaded(cache, null).close(); // seed the cache with the synthetic lists
        engine = new DssEngine(cache, EngineConfig.fromJson(config), t.http, t.http);
        reference = new PlainDssReference(cache, EngineConfig.fromJson(config));
        assertEquals(3, reference.trustedListCertificates());
    }

    @AfterAll
    void tearDown() {
        engine.close();
        reference.close();
    }

    static List<String> fixtures() {
        return List.of("cades/attached-der.p7m", "cades/attached-ber.p7m", "cades/attached-base64.p7m",
                "cades/nested.p7m.p7m", "cades/multi-signer.p7m", "cades/detached.txt.p7s",
                "pades/b-b.pdf", "pades/b-t.pdf", "pades/b-lt.pdf", "pades/b-lta.pdf",
                "tampered/cades/attached-der.p7m", "tampered/cades/attached-ber.p7m",
                "tampered/cades/attached-base64.p7m", "tampered/cades/nested.p7m.p7m",
                "tampered/cades/multi-signer.p7m", "tampered/pades/b-b.pdf", "tampered/pades/b-t.pdf",
                "tampered/pades/b-lt.pdf", "tampered/pades/b-lta.pdf", "content/document.txt");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("fixtures")
    void engineMatchesPlainDss(String fixture) {
        byte[] doc = Fixtures.read(fixture);
        Outcome expected = reference.validate(doc, List.of(), validationTime);
        Outcome actual = engineOutcome(doc);
        List<String> diff = Outcome.compare(expected, actual);
        assertTrue(diff.isEmpty(), fixture + ":\n" + String.join("\n", diff));
        if (!fixture.startsWith("content/")) {
            assertTrue(!expected.signatures().isEmpty(), "reference found no signature in " + fixture);
        }
    }

    /**
     * Inputs that are not a fixture: the reference must refuse them for the same reason as the engine, so that a
     * difference in the input detection shows up as an error-code difference.
     */
    static Stream<Arguments> nonDocuments() {
        byte[] der = Fixtures.read("cades/attached-der.p7m");
        return Stream.of(
                Arguments.of("text starting with '0'", "0 items in stock\n".getBytes(StandardCharsets.US_ASCII),
                        "UNSUPPORTED_DOCUMENT"),
                Arguments.of("base64 decoding to 0x30", "MAIL".getBytes(StandardCharsets.US_ASCII),
                        "UNSUPPORTED_DOCUMENT"),
                Arguments.of("empty", new byte[0], "INVALID_ARGUMENT"),
                Arguments.of("truncated CMS", Arrays.copyOf(der, 200), "VALIDATION_FAILED"),
                Arguments.of("base64 of base64 of base64 CMS", base64(base64(base64(der))), null),
                Arguments.of("four base64 layers", base64(base64(base64(base64(der)))), "UNSUPPORTED_DOCUMENT"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("nonDocuments")
    void inputDetectionMatchesTheEngine(String name, byte[] input, String code) {
        Outcome expected = reference.validate(input, List.of(), validationTime);
        Outcome actual = engineOutcome(input);
        assertEquals(code, expected.errorCode(), name + ": " + expected.error());
        List<String> diff = Outcome.compare(expected, actual);
        assertTrue(diff.isEmpty(), name + ":\n" + String.join("\n", diff));
    }

    private Outcome engineOutcome(byte[] doc) {
        try {
            return Outcome.of(engine.validate(doc, ValidationOptions.fromJson(
                    "{\"validation_time\":\"" + validationTime.toInstant() + "\"}")));
        } catch (DssError e) {
            return Outcome.rejected(e.code().name(), e.getMessage());
        } catch (RuntimeException e) {
            return Outcome.rejected(null, e.toString());
        }
    }

    private static byte[] base64(byte[] b) {
        return Base64.getMimeEncoder().encode(b);
    }

    @ParameterizedTest(name = "detached + {0}")
    @MethodSource("detachedContents")
    void detachedSignatureMatchesPlainDss(String content) {
        byte[] p7s = Fixtures.read("cades/detached.txt.p7s");
        Outcome expected = reference.validate(p7s, List.of(Fixtures.path(content)), validationTime);
        Outcome actual = Outcome.of(engine.validate(p7s, ValidationOptions.fromJson(
                "{\"validation_time\":\"" + validationTime.toInstant() + "\",\"detached_contents\":[{\"path\":\""
                        + Fixtures.path(content).toString().replace("\\", "\\\\") + "\"}]}")));
        List<String> diff = new ArrayList<>(Outcome.compare(expected, actual));
        assertTrue(diff.isEmpty(), content + ":\n" + String.join("\n", diff));
    }

    static List<String> detachedContents() {
        return List.of("content/document.txt", "tampered/content/document.txt");
    }
}
