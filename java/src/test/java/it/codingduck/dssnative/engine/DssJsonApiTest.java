/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import it.codingduck.dssnative.testsupport.ExternalSigner;
import it.codingduck.dssnative.testsupport.Fixtures;
import it.codingduck.dssnative.testsupport.TestEngines;
import it.codingduck.dssnative.testsupport.TestPki;

/**
 * The JSON contract the C API exposes. These go through {@link DssEngine#create} (the real HTTP loader), so they
 * only use offline paths: init reads the cache, and revocation/AIA are off.
 */
class DssJsonApiTest {

    @TempDir
    Path tmp;
    private TestEngines t;

    @BeforeEach
    void setUp() {
        DssJsonApi.shutdown();
        t = new TestEngines(tmp);
    }

    @AfterEach
    void tearDown() {
        DssJsonApi.shutdown();
    }

    private String offlineConfig() {
        return t.configJson("\"revocation\":\"offline\",\"aia\":false");
    }

    /** Fills {@code cache} through an online refresh against the synthetic lists. */
    private Path seededCache() {
        Path cache = tmp.resolve("seeded");
        t.onlineLoaded(cache, null).close();
        return cache;
    }

    @Test
    void callsBeforeInitReportNotInitialized() {
        assertError(DssJsonApi.trustedListStatus(), "NOT_INITIALIZED");
        assertError(DssJsonApi.refreshTrustedListsOnline(), "NOT_INITIALIZED");
        assertError(DssJsonApi.validate(new byte[] {1}, null), "NOT_INITIALIZED");
    }

    @Test
    void invalidConfigurationIsRejected() {
        String cache = tmp.resolve("c").toString();
        assertError(DssJsonApi.init(null, offlineConfig()), "INVALID_ARGUMENT");
        assertError(DssJsonApi.init(cache, "{not json"), "INVALID_CONFIG");
        assertError(DssJsonApi.init(cache, "{}"), "INVALID_CONFIG"); // oj_keystore.path is required
        assertError(DssJsonApi.init(cache, t.configJson("\"lotl_ulr\":\"typo\"")), "INVALID_CONFIG");
        assertError(DssJsonApi.init(cache, t.configJson("\"revocation\":\"sometimes\"")), "INVALID_CONFIG");
        assertError(DssJsonApi.init(cache, t.configJson("\"countries\":[\"Italy\"]")), "INVALID_CONFIG");
        assertError(DssJsonApi.init(cache, t.configJson("\"reports\":[\"fancy\"]")), "INVALID_CONFIG");
        assertError(DssJsonApi.init(cache, "{\"oj_keystore\":{\"path\":\"/nonexistent.p12\"}}"), "INVALID_CONFIG");
        assertError(DssJsonApi.init(cache, t.configJson("\"http\":{\"trust_store\":{\"path\":\"/nonexistent.p12\"}}")),
                "INVALID_CONFIG");
        // A failed init leaves no engine behind.
        assertError(DssJsonApi.trustedListStatus(), "NOT_INITIALIZED");
    }

    @Test
    void initOnEmptyCacheSucceedsButValidationRefuses() {
        Map<String, Object> init = ok(DssJsonApi.init(tmp.resolve("empty").toString(), offlineConfig()));
        assertEquals(Boolean.FALSE, init.get("trusted_lists_loaded"));
        assertError(DssJsonApi.validate(Fixtures.read("pades/b-lta.pdf"), null), "TRUSTED_LISTS_NOT_LOADED");
        Map<String, Object> status = ok(DssJsonApi.trustedListStatus());
        assertEquals(Boolean.FALSE, status.get("loaded"));
    }

    @Test
    void validateReturnsSummaryAndRequestedReports() {
        ok(DssJsonApi.init(seededCache().toString(), offlineConfig()));
        Map<String, Object> r = ok(DssJsonApi.validate(Fixtures.read("pades/b-lta.pdf"),
                "{\"reports\":[\"detailed\",\"etsi\"],\"filename\":\"contract.pdf\"}"));
        assertEquals("PDF", r.get("container"));
        @SuppressWarnings("unchecked")
        Map<String, Object> sig = ((List<Map<String, Object>>) r.get("signatures")).get(0);
        // LTA carries its own revocation data, so it passes with revocation fetching off.
        assertEquals("TOTAL_PASSED", sig.get("indication"));
        assertEquals("PAdES-BASELINE-LTA", sig.get("format"));
        assertNotNull(sig.get("signing_time"));
        assertTrue(((String) r.get("simple_report_xml")).contains("contract.pdf"));
        assertNotNull(r.get("detailed_report_xml"));
        assertNotNull(r.get("etsi_report_xml"));
        assertEquals(null, r.get("diagnostic_data_xml"));
    }

    @Test
    void offlineRevocationLeavesBaselineBIndeterminate() {
        ok(DssJsonApi.init(seededCache().toString(), offlineConfig()));
        Map<String, Object> r = ok(DssJsonApi.validate(Fixtures.read("pades/b-b.pdf"), null));
        @SuppressWarnings("unchecked")
        Map<String, Object> sig = ((List<Map<String, Object>>) r.get("signatures")).get(0);
        assertEquals("INDETERMINATE", sig.get("indication"));
    }

    @Test
    void badInputsBecomeStructuredErrors() {
        ok(DssJsonApi.init(seededCache().toString(), offlineConfig()));
        assertError(DssJsonApi.validate((byte[]) null, null), "INVALID_ARGUMENT");
        assertError(DssJsonApi.validate(new byte[0], null), "INVALID_ARGUMENT");
        assertError(DssJsonApi.validate("hello, not a signature".getBytes(StandardCharsets.UTF_8), null),
                "UNSUPPORTED_DOCUMENT");
        byte[] pdf = Fixtures.read("pades/b-lta.pdf");
        assertError(DssJsonApi.validate(pdf, "{\"reports\":[\"nope\"]}"), "INVALID_ARGUMENT");
        assertError(DssJsonApi.validate(pdf, "{\"unknown\":1}"), "INVALID_ARGUMENT");
        assertError(DssJsonApi.validate(pdf, "[1,2]"), "INVALID_ARGUMENT");
        assertError(DssJsonApi.validate(pdf, "{\"validation_time\":\"yesterday\"}"), "INVALID_ARGUMENT");
        assertError(DssJsonApi.validate(pdf, "{\"detached_contents\":[{\"path\":\"/nonexistent\"}]}"),
                "INVALID_ARGUMENT");
    }

    @Test
    void corruptDocumentsNeverThrow() {
        ok(DssJsonApi.init(seededCache().toString(), offlineConfig()));
        byte[] cms = Fixtures.read("cades/attached-der.p7m");
        byte[] pdf = Fixtures.read("pades/b-b.pdf");
        List<byte[]> corrupt = List.of(
                new byte[] {0x30, (byte) 0x80, 0x01, 0x02},
                java.util.Arrays.copyOf(cms, cms.length / 2),
                java.util.Arrays.copyOf(pdf, pdf.length / 2),
                "%PDF-1.7\n%%EOF".getBytes(StandardCharsets.US_ASCII));
        for (byte[] doc : corrupt) {
            Map<String, Object> r = parse(DssJsonApi.validate(doc, null));
            if (Boolean.FALSE.equals(r.get("ok"))) {
                @SuppressWarnings("unchecked")
                String code = (String) ((Map<String, Object>) r.get("error")).get("code");
                assertTrue(List.of("VALIDATION_FAILED", "UNSUPPORTED_DOCUMENT").contains(code), code);
            }
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void tlSnapshotExportsAndStartsAnEngine() throws Exception {
        DssJsonApi.DocumentResult early = DssJsonApi.exportTlSnapshot();
        assertError(early.json(), "NOT_INITIALIZED");
        assertNull(early.document());

        ok(DssJsonApi.init(tmp.resolve("empty").toString(), offlineConfig()));
        DssJsonApi.DocumentResult nothing = DssJsonApi.exportTlSnapshot();
        assertError(nothing.json(), "TRUSTED_LISTS_NOT_LOADED");
        assertNull(nothing.document());

        ok(DssJsonApi.init(seededCache().toString(), offlineConfig()));
        DssJsonApi.DocumentResult exported = DssJsonApi.exportTlSnapshot();
        Map<String, Object> info = ok(exported.json());
        assertEquals(1L, info.get("format"));
        assertEquals(3L, info.get("trusted_certificates"));
        assertEquals((long) exported.document().length, info.get("size"));
        assertEquals("offline", ((Map<String, Object>) info.get("lists_loaded")).get("mode"));
        Path file = java.nio.file.Files.write(tmp.resolve("lists.tlsnap"), exported.document());

        String withSnapshot = t.configJson("\"revocation\":\"offline\",\"aia\":false,\"tl_snapshot\":\"" + file + "\"");
        Map<String, Object> init = ok(DssJsonApi.init(tmp.resolve("empty").toString(), withSnapshot));
        assertEquals(Boolean.TRUE, init.get("trusted_lists_loaded"));
        assertEquals("snapshot", ((Map<String, Object>) init.get("initial_load")).get("mode"));
        Map<String, Object> status = ok(DssJsonApi.trustedListStatus());
        assertEquals(file.toString(), ((Map<String, Object>) status.get("tl_snapshot")).get("path"));
        ok(DssJsonApi.validate(Fixtures.read("pades/b-lta.pdf"), null));

        // A rejected snapshot fails init and keeps the engine that was running.
        assertError(DssJsonApi.init(tmp.resolve("empty").toString(),
                t.configJson("\"tl_snapshot\":\"" + tmp.resolve("missing.tlsnap") + "\"")), "TL_SNAPSHOT_REJECTED");
        assertNotNull(ok(DssJsonApi.trustedListStatus()).get("tl_snapshot"));
        assertError(DssJsonApi.init(tmp.resolve("empty").toString(), t.configJson("\"tl_snapshot\":\" \"")),
                "INVALID_CONFIG");
    }

    @Test
    void reInitReplacesTheEngine() {
        ok(DssJsonApi.init(tmp.resolve("empty").toString(), offlineConfig()));
        assertEquals(Boolean.FALSE, ok(DssJsonApi.trustedListStatus()).get("loaded"));
        ok(DssJsonApi.init(seededCache().toString(), offlineConfig()));
        assertEquals(Boolean.TRUE, ok(DssJsonApi.trustedListStatus()).get("loaded"));
    }

    @Test
    void bufferInputBehavesLikeByteArrayInput() {
        ok(DssJsonApi.init(seededCache().toString(), offlineConfig()));
        byte[] pdf = Fixtures.read("pades/b-lta.pdf");
        Map<String, Object> fromArray = ok(DssJsonApi.validate(pdf, null));
        Map<String, Object> fromBuffer = ok(DssJsonApi.validate(java.nio.ByteBuffer.wrap(pdf).asReadOnlyBuffer(), null));
        assertEquals(fromArray.get("signatures").toString().replaceAll("\"id\":\"[^\"]+\"", ""),
                fromBuffer.get("signatures").toString().replaceAll("\"id\":\"[^\"]+\"", ""));
        assertError(DssJsonApi.validate((java.nio.ByteBuffer) null, null), "INVALID_ARGUMENT");
    }

    @Test
    void extendHandsBackTheDocumentOnlyOnSuccess() {
        String lt = "{\"level\":\"LT\"}";
        DssJsonApi.DocumentResult early = DssJsonApi.extend(Fixtures.read("pades/b-lt.pdf"), lt);
        assertError(early.json(), "NOT_INITIALIZED");
        assertNull(early.document());

        ok(DssJsonApi.init(seededCache().toString(), offlineConfig()));
        byte[] pdf = Fixtures.read("pades/b-lt.pdf");
        DssJsonApi.DocumentResult r = DssJsonApi.extend(pdf, "{\"level\":\"lt\",\"filename\":\"contract.pdf\"}");
        Map<String, Object> m = ok(r.json());
        assertEquals("PDF", m.get("container"));
        assertEquals(List.of(), m.get("transformations"));
        assertEquals("PAdES-BASELINE-LT", m.get("level"));
        assertTrue(r.document().length > pdf.length);
        @SuppressWarnings("unchecked")
        Map<String, Object> sig = ((List<Map<String, Object>>) ok(DssJsonApi.validate(r.document(), null))
                .get("signatures")).get(0);
        assertEquals("TOTAL_PASSED", sig.get("indication"));
        assertEquals("PAdES-BASELINE-LT", sig.get("format"));

        // B-T has no revocation data, and this engine may not fetch any.
        DssJsonApi.DocumentResult refused = DssJsonApi.extend(Fixtures.read("pades/b-t.pdf"), lt);
        assertError(refused.json(), "EXTENSION_FAILED");
        assertNull(refused.document());
        assertError(DssJsonApi.extend(pdf, null).json(), "INVALID_ARGUMENT");
        assertError(DssJsonApi.extend(pdf, "{\"level\":\"LTA\"}").json(), "EXTENSION_FAILED"); // no TSA
        assertError(DssJsonApi.extend(Fixtures.read("cades/attached-der.p7m"), lt).json(), "UNSUPPORTED_DOCUMENT");
        assertError(DssJsonApi.extend((java.nio.ByteBuffer) null, lt).json(), "INVALID_ARGUMENT");
    }

    @Test
    void signingHandsBackTheDocumentOnlyOnSuccess() throws Exception {
        String options = "{\"mode\":\"signature_value\",\"level\":\"B\",\"filename\":\"contract.pdf\","
                + "\"signing_certificate\":\"" + Base64.getEncoder().encodeToString(
                        t.pki.x509(TestPki.Entity.SIGNER_RSA).getEncoded()) + "\"";
        byte[] pdf = Fixtures.read("content/document.pdf");
        assertError(DssJsonApi.prepareSignature(pdf, options + "}"), "NOT_INITIALIZED");
        DssJsonApi.DocumentResult early = DssJsonApi.completeSignature(pdf, options + "}", new byte[] {1});
        assertError(early.json(), "NOT_INITIALIZED");
        assertNull(early.document());

        ok(DssJsonApi.init(seededCache().toString(), offlineConfig()));
        Map<String, Object> prepared = ok(DssJsonApi.prepareSignature(pdf, options + "}"));
        assertEquals("PAdES", prepared.get("format"));
        assertEquals("SHA256", prepared.get("digest_algorithm"));
        assertNotNull(prepared.get("data_to_sign"));
        byte[] digest = Base64.getDecoder().decode((String) prepared.get("digest"));
        String complete = options + ",\"signing_time\":\"" + prepared.get("signing_time") + "\"}";

        byte[] value = new ExternalSigner(t.pki, TestPki.Entity.SIGNER_RSA).signatureValue(
                eu.europa.esig.dss.enumerations.DigestAlgorithm.SHA256, digest, false);
        DssJsonApi.DocumentResult r = DssJsonApi.completeSignature(pdf, complete, value);
        Map<String, Object> m = ok(r.json());
        assertEquals("PAdES", m.get("format"));
        assertEquals("PAdES-BASELINE-B", m.get("level"));
        assertEquals("ENVELOPED", m.get("packaging"));
        assertTrue(r.document().length > pdf.length);
        @SuppressWarnings("unchecked")
        Map<String, Object> sig = ((List<Map<String, Object>>) ok(DssJsonApi.validate(r.document(), null))
                .get("signatures")).get(0);
        assertEquals("PAdES-BASELINE-B", sig.get("format"));

        DssJsonApi.DocumentResult refused = DssJsonApi.completeSignature(pdf, complete, new byte[256]);
        assertError(refused.json(), "SIGNING_FAILED");
        assertNull(refused.document());
        assertError(DssJsonApi.completeSignature(pdf, options + "}", value).json(), "INVALID_ARGUMENT"); // no time
        assertError(DssJsonApi.completeSignature(pdf, complete, (byte[]) null).json(), "INVALID_ARGUMENT");
        assertError(DssJsonApi.prepareSignature(pdf, null), "INVALID_ARGUMENT");
        assertError(DssJsonApi.prepareSignature((java.nio.ByteBuffer) null, options + "}"), "INVALID_ARGUMENT");
    }

    @Test
    void versionNeedsNoInit() {
        Map<String, Object> v = ok(DssJsonApi.version());
        assertEquals("6.5.1", v.get("dss"));
        assertNotNull(v.get("library"));
        assertNotNull(v.get("runtime"));
    }

    // ------------------------------------------------------------------ helpers

    @SuppressWarnings("unchecked")
    private static Map<String, Object> parse(String json) {
        return (Map<String, Object>) Json.parse(json);
    }

    private static Map<String, Object> ok(String json) {
        Map<String, Object> m = parse(json);
        assertEquals(Boolean.TRUE, m.get("ok"), json);
        return m;
    }

    @SuppressWarnings("unchecked")
    private static void assertError(String json, String code) {
        Map<String, Object> m = parse(json);
        assertEquals(Boolean.FALSE, m.get("ok"), json);
        Map<String, Object> err = (Map<String, Object>) m.get("error");
        assertEquals(code, err.get("code"), json);
        assertNotNull(err.get("message"));
    }
}
