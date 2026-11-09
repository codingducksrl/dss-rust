/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

    /**
     * BouncyCastle, PDFBox and DSS throw IllegalArgument/IllegalState/NullPointer exceptions on damaged input,
     * which must surface as VALIDATION_FAILED (the document's fault), never as INTERNAL_ERROR (ours).
     */
    @Test
    void damagedCertificatesInACmsAreAValidationFailure() throws Exception {
        ok(DssJsonApi.init(seededCache().toString(), offlineConfig()));
        org.bouncycastle.asn1.cms.ContentInfo ci = org.bouncycastle.asn1.cms.ContentInfo.getInstance(
                Fixtures.read("cades/attached-der.p7m"));
        org.bouncycastle.asn1.cms.SignedData sd = org.bouncycastle.asn1.cms.SignedData.getInstance(ci.getContent());
        org.bouncycastle.asn1.ASN1EncodableVector certs = new org.bouncycastle.asn1.ASN1EncodableVector();
        for (org.bouncycastle.asn1.ASN1Encodable c : sd.getCertificates()) {
            certs.add(c);
        }
        certs.add(new org.bouncycastle.asn1.DERSequence(new org.bouncycastle.asn1.ASN1Integer(1))); // not a Certificate
        org.bouncycastle.asn1.cms.SignedData damaged = new org.bouncycastle.asn1.cms.SignedData(sd.getDigestAlgorithms(),
                sd.getEncapContentInfo(), new org.bouncycastle.asn1.DERSet(certs), sd.getCRLs(), sd.getSignerInfos());
        byte[] cms = new org.bouncycastle.asn1.cms.ContentInfo(ci.getContentType(), damaged)
                .getEncoded(org.bouncycastle.asn1.ASN1Encoding.DER);
        Map<String, Object> r = parse(DssJsonApi.validate(cms, null));
        assertEquals(Boolean.FALSE, r.get("ok"), r.toString());
        @SuppressWarnings("unchecked")
        Map<String, Object> err = (Map<String, Object>) r.get("error");
        assertEquals("VALIDATION_FAILED", err.get("code"), err.toString());
        assertTrue(((String) err.get("message")).contains("IllegalArgumentException"), err.toString());
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
        Map<String, Object> first = ok(DssJsonApi.init(tmp.resolve("empty").toString(), offlineConfig()));
        assertEquals(Boolean.FALSE, ok(DssJsonApi.trustedListStatus()).get("loaded"));
        ok(DssJsonApi.init(seededCache().toString(), offlineConfig()));
        assertEquals(Boolean.TRUE, ok(DssJsonApi.trustedListStatus()).get("loaded"));
        // slf4j-simple fixes its level when the process first logs: init reports the one in force.
        String effective = System.getProperty("org.slf4j.simpleLogger.defaultLogLevel");
        assertEquals(effective, first.get("log_level"));
        Map<String, Object> debug = ok(DssJsonApi.init(seededCache().toString(),
                t.configJson("\"revocation\":\"offline\",\"aia\":false,\"log_level\":\"debug\"")));
        assertEquals(effective, debug.get("log_level"), "a re-init cannot change it, and says so");
        for (String logger : DssJsonApi.SECRET_BEARING_LOGGERS) {
            assertEquals("info", System.getProperty("org.slf4j.simpleLogger.log." + logger),
                    logger + " must never log at debug: it would print the TSA's credentials");
            // slf4j-simple fixes a logger's level when it is created: one made after init must obey the property.
            assertFalse(LoggerFactory.getLogger(logger + ".after-init").isDebugEnabled(),
                    logger + " would print Authorization headers at debug");
        }
        // Positive control: a logger of our own follows the level in force, so the pin above is not vacuous.
        Logger ours = LoggerFactory.getLogger("it.codingduck.dssnative.engine.LogLevelProbe");
        List<String> levels = List.of("trace", "debug", "info", "warn", "error");
        int inForce = levels.indexOf(effective.toLowerCase(java.util.Locale.ROOT));
        assertTrue(inForce >= 0, "slf4j-simple level in force: " + effective);
        assertEquals(inForce <= levels.indexOf("debug"), ours.isDebugEnabled());
        assertEquals(inForce <= levels.indexOf("warn"), ours.isWarnEnabled());
        assertEquals(inForce <= levels.indexOf("error"), ours.isErrorEnabled());
    }

    @Test
    void shutdownReportsWhetherTheTrustedListThreadsStopped() {
        assertEquals(Boolean.TRUE, ok(DssJsonApi.shutdown()).get("trusted_list_threads_stopped"), "nothing to stop");
        ok(DssJsonApi.init(seededCache().toString(), offlineConfig()));
        assertEquals(Boolean.TRUE, ok(DssJsonApi.shutdown()).get("trusted_list_threads_stopped"));
        assertError(DssJsonApi.trustedListStatus(), "NOT_INITIALIZED");
    }

    @Test
    void aRefreshThatPublishedNothingIsAnError() {
        TrustedListManager.RefreshRecord failed = new TrustedListManager.RefreshRecord("online",
                java.time.Instant.parse("2026-01-01T00:00:00Z"), java.time.Instant.parse("2026-01-01T00:00:03Z"), false,
                "DSSException: the LOTL could not be downloaded", 12);
        DssError e = org.junit.jupiter.api.Assertions.assertThrows(DssError.class,
                () -> DssJsonApi.refreshResult(failed));
        assertEquals(DssError.Code.TL_REFRESH_FAILED, e.code());
        assertTrue(e.getMessage().contains("the LOTL could not be downloaded"), e.getMessage());
        TrustedListManager.RefreshRecord fine = new TrustedListManager.RefreshRecord("online",
                java.time.Instant.parse("2026-01-01T00:00:00Z"), java.time.Instant.parse("2026-01-01T00:00:03Z"), true,
                null, 12);
        @SuppressWarnings("unchecked")
        Map<String, Object> refresh = (Map<String, Object>) DssJsonApi.refreshResult(fine).get("refresh");
        assertEquals(Boolean.TRUE, refresh.get("completed"));
        assertEquals(12, refresh.get("trusted_certificates"));
    }

    @Test
    void validationsSurviveReInitAndShutdownUnderway() throws Exception {
        ok(DssJsonApi.init(seededCache().toString(), offlineConfig()));
        byte[] pdf = Fixtures.read("pades/b-lta.pdf");
        List<Thread> workers = new java.util.ArrayList<>();
        List<String> codes = java.util.Collections.synchronizedList(new java.util.ArrayList<>());
        java.util.concurrent.CountDownLatch started = new java.util.concurrent.CountDownLatch(4);
        for (int i = 0; i < 4; i++) {
            Thread w = new Thread(() -> {
                started.countDown();
                for (int n = 0; n < 8; n++) {
                    Map<String, Object> r = parse(DssJsonApi.validate(pdf, null));
                    if (Boolean.FALSE.equals(r.get("ok"))) {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> err = (Map<String, Object>) r.get("error");
                        codes.add((String) err.get("code"));
                    } else {
                        codes.add("OK");
                    }
                }
            });
            w.start();
            workers.add(w);
        }
        started.await();
        for (int i = 0; i < 3; i++) {
            ok(DssJsonApi.init(seededCache().toString(), offlineConfig()));
        }
        ok(DssJsonApi.shutdown());
        for (Thread w : workers) {
            w.join(30_000);
        }
        assertEquals(32, codes.size());
        assertTrue(codes.contains("OK"), codes.toString());
        // Validations that started on an engine replaced meanwhile finish; after shutdown they are refused cleanly.
        codes.forEach(c -> assertTrue(List.of("OK", "NOT_INITIALIZED").contains(c), codes.toString()));
    }

    @Test
    void validationResultCarriesTheAggregateVerdictAndLimitsApply() {
        ok(DssJsonApi.init(seededCache().toString(), t.configJson("\"revocation\":\"offline\",\"aia\":false,"
                + "\"limits\":{\"max_pdf_signatures\":1}")));
        Map<String, Object> unsigned = ok(DssJsonApi.validate(Fixtures.read("content/document.pdf"), null));
        assertEquals(Boolean.FALSE, unsigned.get("all_passed"));
        assertEquals(List.of(), unsigned.get("signatures"));
        assertEquals(List.of(), unsigned.get("timestamps"));
        Map<String, Object> signed = ok(DssJsonApi.validate(Fixtures.read("pades/b-b.pdf"), null));
        assertEquals(Boolean.FALSE, signed.get("all_passed"), "INDETERMINATE without revocation data");
        @SuppressWarnings("unchecked")
        Map<String, Object> sig = ((List<Map<String, Object>>) signed.get("signatures")).get(0);
        assertEquals("trusted_list", sig.get("trust_anchor"));
        assertEquals(Boolean.FALSE, sig.get("modified_after_signing"));
        assertNotNull(sig.get("changes_after_signing"));
        assertNotNull(sig.get("qualification_errors"));
        assertNotNull(sig.get("timestamps"));
        // Two signature revisions (the signature and a document timestamp) against a limit of one.
        assertError(DssJsonApi.validate(Fixtures.read("pades/b-lta.pdf"), null), "VALIDATION_FAILED");
        assertError(DssJsonApi.init(tmp.resolve("c").toString(), t.configJson("\"limits\":{\"max_pdf_pages\":0}")),
                "INVALID_CONFIG");
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
        // api_version is the integer contract version the Rust/PHP mirrors compare against their own constant
        assertEquals(1L, v.get("api_version"), "api_version must be a JSON integer, not a string");
        assertEquals((long) DssJsonApi.API_VERSION, v.get("api_version"));
        assertTrue(DssJsonApi.version().contains("\"api_version\":1"), DssJsonApi.version());
    }

    /** The root of trust is known from init, before any refresh, and is what dss_tl_status reports (F-064). */
    @Test
    @SuppressWarnings("unchecked")
    void initReportsTheOjKeystoreInUse() {
        Map<String, Object> init = ok(DssJsonApi.init(tmp.resolve("empty").toString(), offlineConfig()));
        Map<String, Object> keystore = (Map<String, Object>) init.get("oj_keystore");
        assertNotNull(keystore, init.toString());
        assertEquals(t.ojKeystore.toString(), keystore.get("path"));
        String sha256 = (String) keystore.get("sha256");
        assertTrue(sha256.matches("[0-9a-f]{64}"), sha256);
        assertEquals(keystore, ok(DssJsonApi.trustedListStatus()).get("oj_keystore"));
    }

    /**
     * The buffer route behind dss_validate_with_contents (F-188): the signed content decides the verdict, the
     * buffers are read from position to limit without being moved, and the refusals match the base64 route.
     */
    @Test
    void detachedContentsCanBePassedAsBuffers() {
        ok(DssJsonApi.init(seededCache().toString(), offlineConfig()));
        ByteBuffer signature = ByteBuffer.wrap(Fixtures.read("cades/detached.txt.p7s"));
        byte[] content = Fixtures.read("content/document.txt");
        byte[] tampered = Fixtures.read("tampered/content/document.txt");

        // No content, as a null or an empty list: exactly the plain validate.
        assertEquals("SIGNED_DATA_NOT_FOUND",
                signatureOf(DssJsonApi.validate(signature, null, null)).get("sub_indication"));
        assertEquals("SIGNED_DATA_NOT_FOUND",
                signatureOf(DssJsonApi.validate(signature, "{}", List.of())).get("sub_indication"));

        // The content in a direct buffer, as a slice with a position and a limit, which the call leaves alone.
        ByteBuffer slice = ByteBuffer.allocateDirect(content.length + 8);
        slice.position(4);
        slice.put(content);
        slice.position(4).limit(4 + content.length);
        Map<String, Object> with = signatureOf(DssJsonApi.validate(signature, "{\"reports\":[\"detailed\"]}",
                List.of(new DssJsonApi.DetachedContent("document.txt", slice))));
        assertEquals(4, slice.position());
        assertEquals(4 + content.length, slice.limit());
        assertEquals("CAdES-BASELINE-B", with.get("format"));
        assertNotEquals("SIGNED_DATA_NOT_FOUND", with.get("sub_indication"));
        assertNotEquals("HASH_FAILURE", with.get("sub_indication"));

        Map<String, Object> bad = signatureOf(DssJsonApi.validate(signature, null,
                List.of(new DssJsonApi.DetachedContent("document.txt", ByteBuffer.wrap(tampered)))));
        assertEquals("TOTAL_FAILED", bad.get("indication"));
        assertEquals("HASH_FAILURE", bad.get("sub_indication"));

        // A binary content next to an entry the caller's JSON already carries (the C smoke test's mixed case).
        Map<String, Object> mixed = signatureOf(DssJsonApi.validate(signature,
                "{\"detached_contents\":[{\"name\":\"other\",\"base64\":\"AQID\"}]}",
                List.of(new DssJsonApi.DetachedContent(null, ByteBuffer.wrap(content)))));
        assertEquals("CAdES-BASELINE-B", mixed.get("format"));

        // Refusals, with the messages dss_validate_with_contents documents.
        List<DssJsonApi.DetachedContent> one = List.of(new DssJsonApi.DetachedContent("a", ByteBuffer.wrap(content)));
        assertEquals("contents[1] is empty", errorMessage(DssJsonApi.validate(signature, null, List.of(
                new DssJsonApi.DetachedContent("a", ByteBuffer.wrap(content)),
                new DssJsonApi.DetachedContent(null, ByteBuffer.allocate(0))))));
        assertEquals("contents[0] is NULL", errorMessage(DssJsonApi.validate(signature, null,
                java.util.Collections.singletonList(null))));
        assertTrue(errorMessage(DssJsonApi.validate(signature, "{not json", one))
                .startsWith("options_json is not valid JSON"));
        assertEquals("options: 'detached_contents' must be an array of objects",
                errorMessage(DssJsonApi.validate(signature, "{\"detached_contents\":\"x\"}", one)));
        assertError(DssJsonApi.validate(signature, "{\"nope\":1}", one), "INVALID_ARGUMENT");
        assertError(DssJsonApi.validate(null, null, one), "INVALID_ARGUMENT");
        assertError(DssJsonApi.validate(ByteBuffer.allocate(0), null, one), "INVALID_ARGUMENT");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> signatureOf(String resultJson) {
        Map<String, Object> r = ok(resultJson);
        List<Map<String, Object>> signatures = (List<Map<String, Object>>) r.get("signatures");
        assertEquals(1, signatures.size(), resultJson);
        return signatures.get(0);
    }

    @SuppressWarnings("unchecked")
    private static String errorMessage(String json) {
        Map<String, Object> m = parse(json);
        assertEquals(Boolean.FALSE, m.get("ok"), json);
        return (String) ((Map<String, Object>) m.get("error")).get("message");
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
