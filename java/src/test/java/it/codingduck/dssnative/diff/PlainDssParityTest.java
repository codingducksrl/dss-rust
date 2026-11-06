/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.diff;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import it.codingduck.dssnative.engine.DssEngine;
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
        Outcome actual;
        try {
            actual = Outcome.of(engine.validate(doc, ValidationOptions.fromJson(
                    "{\"validation_time\":\"" + validationTime.toInstant() + "\"}")));
        } catch (RuntimeException e) {
            actual = Outcome.rejected(e.getMessage());
        }
        List<String> diff = Outcome.compare(expected, actual);
        assertTrue(diff.isEmpty(), fixture + ":\n" + String.join("\n", diff));
        if (!fixture.startsWith("content/")) {
            assertTrue(!expected.signatures().isEmpty(), "reference found no signature in " + fixture);
        }
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
