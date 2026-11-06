/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;

import it.codingduck.dssnative.testsupport.Fixtures;
import it.codingduck.dssnative.testsupport.SyntheticTrustedLists;
import it.codingduck.dssnative.testsupport.TestEngines;
import it.codingduck.dssnative.testsupport.TestPki;

class TrustedListTest {

    @TempDir
    Path tmp;

    @Test
    void emptyCacheLoadsNothingAndValidationRefuses() {
        TestEngines t = new TestEngines(tmp);
        try (DssEngine engine = t.engine(tmp.resolve("cache"), null)) {
            assertEquals(0, t.http.totalHits(), "startup must not touch the network");
            Map<String, Object> status = engine.trustedListStatus();
            assertEquals(Boolean.FALSE, status.get("loaded"));
            assertEquals(0, status.get("trusted_certificates"));

            DssError e = assertThrows(DssError.class,
                    () -> engine.validate(Fixtures.read("pades/b-lta.pdf"), ValidationOptions.DEFAULT));
            assertEquals(DssError.Code.TRUSTED_LISTS_NOT_LOADED, e.code());
        }
    }

    @Test
    void validationWithoutTrustedListsCanBeAllowedExplicitly() {
        TestEngines t = new TestEngines(tmp);
        try (DssEngine engine = t.engine(tmp.resolve("cache"), "\"require_trusted_lists\":false")) {
            ValidationResult r = engine.validate(Fixtures.read("pades/b-lta.pdf"), ValidationOptions.DEFAULT);
            // No trust anchor at all: DSS cannot build a trusted chain.
            assertEquals("INDETERMINATE/NO_CERTIFICATE_CHAIN_FOUND", FixtureValidationTest.verdicts(r).get(0));
        }
    }

    @Test
    void onlineRefreshLoadsListsAndStatusDescribesThem() {
        TestEngines t = new TestEngines(tmp);
        try (DssEngine engine = t.engine(tmp.resolve("cache"), null)) {
            TrustedListManager.RefreshRecord rec = engine.refreshTrustedListsOnline();
            assertTrue(rec.completed());
            assertEquals(3, rec.trustedCertificates()); // IT: root CA + TSA; DE: other CA

            Map<String, Object> status = engine.trustedListStatus();
            assertEquals(Boolean.TRUE, status.get("loaded"));
            assertNotNull(status.get("last_online_refresh"));
            assertEquals(Boolean.FALSE, status.get("refresh_in_progress"));

            Map<String, Object> lotl = list(status, "lotls").get(0);
            assertEquals(SyntheticTrustedLists.LOTL_URL, lotl.get("url"));
            assertEquals("TOTAL_PASSED", map(lotl, "validation").get("indication"));
            assertEquals("SYNCHRONIZED", map(lotl, "download").get("status"));

            List<Map<String, Object>> tls = list(status, "tls");
            assertEquals(List.of("DE", "IT"), tls.stream().map(m -> (String) m.get("territory")).sorted().toList());
            for (Map<String, Object> tl : tls) {
                assertEquals("TOTAL_PASSED", map(tl, "validation").get("indication"), tl.get("url").toString());
                assertEquals(Boolean.FALSE, tl.get("expired"));
                assertEquals(6L, ((Integer) tl.get("version")).longValue());
            }
        }
    }

    @Test
    void startupLoadsFromCacheWithoutNetwork() {
        TestEngines t = new TestEngines(tmp);
        Path cache = tmp.resolve("cache");
        try (DssEngine seeding = t.onlineLoaded(cache, null)) {
            assertEquals(Boolean.TRUE, seeding.trustedListStatus().get("loaded"));
        }
        t.http.offline(true);
        int hitsBefore = t.http.totalHits();
        long start = System.nanoTime();
        try (DssEngine engine = t.engine(cache, null)) {
            long ms = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
            assertEquals(hitsBefore, t.http.totalHits(), "offline startup must not touch the network");
            Map<String, Object> status = engine.trustedListStatus();
            assertEquals(Boolean.TRUE, status.get("loaded"));
            assertEquals(3, status.get("trusted_certificates"));
            assertTrue(ms < 10_000, "cold start from cache took " + ms + " ms");

            ValidationResult r = engine.validate(Fixtures.read("pades/b-lta.pdf"), ValidationOptions.DEFAULT);
            assertEquals("TOTAL_PASSED/-", FixtureValidationTest.verdicts(r).get(0));
        }
    }

    @Test
    void countryFilterLimitsTheTrustedLists() {
        TestEngines t = new TestEngines(tmp);
        try (DssEngine it = t.onlineLoaded(tmp.resolve("cache-it"), TestEngines.countries(List.of("IT")))) {
            List<Map<String, Object>> tls = list(it.trustedListStatus(), "tls");
            assertEquals(List.of("IT"), tls.stream().map(m -> (String) m.get("territory")).toList());
            assertEquals(2, it.trustedListStatus().get("trusted_certificates"));
            assertEquals("TOTAL_PASSED/-", FixtureValidationTest.verdicts(
                    it.validate(Fixtures.read("cades/attached-der.p7m"), ValidationOptions.DEFAULT)).get(0));
        }
        try (DssEngine de = t.onlineLoaded(tmp.resolve("cache-de"), TestEngines.countries(List.of("DE")))) {
            // The test root CA is only on the IT list.
            assertEquals("INDETERMINATE/NO_CERTIFICATE_CHAIN_FOUND", FixtureValidationTest.verdicts(
                    de.validate(Fixtures.read("cades/attached-der.p7m"), ValidationOptions.DEFAULT)).get(0));
        }
    }

    @Test
    void lotlSignedByKeyOutsideOjKeystoreIsNotTrusted() {
        TestEngines t = new TestEngines(tmp);
        // Re-sign the LOTL with the TL signer, which the "OJ keystore" does not contain.
        TestPki pki = t.pki;
        t.http.route(SyntheticTrustedLists.LOTL_URL,
                new SyntheticTrustedLists(pki, 1).lotlSignedBy(TestPki.Entity.TL_SIGNER));
        try (DssEngine engine = t.onlineLoaded(tmp.resolve("cache"), null)) {
            Map<String, Object> status = engine.trustedListStatus();
            Map<String, Object> lotl = list(status, "lotls").get(0);
            assertFalse("TOTAL_PASSED".equals(map(lotl, "validation").get("indication")),
                    "LOTL signature must not validate: " + lotl);
            assertEquals(Boolean.FALSE, lotl.get("used_for_trust"));
            // The TLs it points to are themselves well signed, but are reachable only through the bad LOTL.
            assertEquals(Boolean.FALSE, status.get("loaded"));
            assertEquals(0, status.get("trusted_certificates"));
            list(status, "tls").forEach(tl -> assertEquals(Boolean.FALSE, tl.get("used_for_trust")));
            DssError e = assertThrows(DssError.class,
                    () -> engine.validate(Fixtures.read("cades/attached-der.p7m"), ValidationOptions.DEFAULT));
            assertEquals(DssError.Code.TRUSTED_LISTS_NOT_LOADED, e.code());
        }
        // DSS's own default behaviour, still available by configuration.
        try (DssEngine lax = t.onlineLoaded(tmp.resolve("cache-lax"), "\"tl_sync\":{\"accept_invalid_signature\":true}")) {
            assertEquals(3, lax.trustedListStatus().get("trusted_certificates"));
        }
    }

    @Test
    void tlWithBrokenSignatureIsNotUsed() {
        TestEngines t = new TestEngines(tmp);
        // Sign the IT TL with the LOTL signer instead of the certificate the LOTL announces for it.
        SyntheticTrustedLists lists = new SyntheticTrustedLists(t.pki, 1);
        t.http.route(SyntheticTrustedLists.IT_TL_URL,
                lists.tlSignedBy("IT", TestPki.Entity.ROOT_CA, TestPki.Entity.TSA, TestPki.Entity.LOTL_SIGNER));
        try (DssEngine engine = t.onlineLoaded(tmp.resolve("cache"), null)) {
            Map<String, Object> status = engine.trustedListStatus();
            Map<String, Map<String, Object>> byTerritory = new java.util.HashMap<>();
            list(status, "tls").forEach(tl -> byTerritory.put((String) tl.get("territory"), tl));
            assertEquals(Boolean.FALSE, byTerritory.get("IT").get("used_for_trust"));
            assertEquals(Boolean.TRUE, byTerritory.get("DE").get("used_for_trust"));
            assertEquals(1, status.get("trusted_certificates"));
            assertEquals("INDETERMINATE/NO_CERTIFICATE_CHAIN_FOUND", FixtureValidationTest.verdicts(
                    engine.validate(Fixtures.read("cades/attached-der.p7m"), ValidationOptions.DEFAULT)).get(0));
        }
    }

    /**
     * National lists signed with other schemes than the RSA used elsewhere. On the JVM this checks DSS; in the
     * native image it checks that xmlsec's algorithm implementations are registered (DssFeature), since the
     * implementation is chosen from the algorithm URI inside the XML.
     */
    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"ECDSA", "RSASSA_PSS"})
    void nationalListsSignedWithOtherSchemesAreAccepted(String scheme) {
        TestEngines t = new TestEngines(tmp);
        SyntheticTrustedLists.ListSigner signer = scheme.equals("ECDSA")
                ? TestPki.ephemeralListSigner("Test TL Signer ECDSA", 0, null)
                : TestPki.ephemeralListSigner("Test TL Signer RSA-PSS", 2048, EncryptionAlgorithm.RSASSA_PSS);
        new SyntheticTrustedLists(t.pki, 1).withNationalSigner(signer).serveOn(t.http);
        try (DssEngine engine = t.onlineLoaded(tmp.resolve("cache"), null)) {
            Map<String, Object> status = engine.trustedListStatus();
            for (Map<String, Object> tl : list(status, "tls")) {
                assertEquals("TOTAL_PASSED", map(tl, "validation").get("indication"), Json.write(tl));
                assertEquals(Boolean.TRUE, tl.get("used_for_trust"));
            }
            assertEquals("TOTAL_PASSED/-", FixtureValidationTest.verdicts(
                    engine.validate(Fixtures.read("cades/attached-der.p7m"), ValidationOptions.DEFAULT)).get(0));
        }
    }

    @Test
    void secondOnlineRefreshIsRejectedWhileOneRuns() throws Exception {
        TestEngines t = new TestEngines(tmp);
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        try (DssEngine engine = t.engine(tmp.resolve("cache"), null)) {
            t.http.beforeEachRequest(() -> {
                entered.countDown();
                await(release);
            });
            ExecutorService pool = Executors.newSingleThreadExecutor();
            try {
                Future<TrustedListManager.RefreshRecord> first = pool.submit(engine::refreshTrustedListsOnline);
                assertTrue(entered.await(10, TimeUnit.SECONDS));

                DssError e = assertThrows(DssError.class, engine::refreshTrustedListsOnline);
                assertEquals(DssError.Code.REFRESH_IN_PROGRESS, e.code());

                // Status must answer immediately even though the refresh holds DSS's job lock.
                Map<String, Object> status = assertTimeoutPreemptively(Duration.ofSeconds(2),
                        engine::trustedListStatus);
                assertEquals(Boolean.TRUE, status.get("refresh_in_progress"));

                release.countDown();
                assertTrue(first.get(30, TimeUnit.SECONDS).completed());
                assertEquals(Boolean.FALSE, engine.trustedListStatus().get("refresh_in_progress"));
            } finally {
                release.countDown();
                pool.shutdownNow();
            }
        }
    }

    @Test
    void failedOnlineRefreshKeepsPreviouslyLoadedLists() {
        TestEngines t = new TestEngines(tmp);
        try (DssEngine engine = t.onlineLoaded(tmp.resolve("cache"), null)) {
            t.http.offline(true);
            TrustedListManager.RefreshRecord rec = engine.refreshTrustedListsOnline();
            assertTrue(rec.completed());
            Map<String, Object> status = engine.trustedListStatus();
            assertEquals(Boolean.TRUE, status.get("loaded"));
            assertEquals(3, status.get("trusted_certificates"));
            Map<String, Object> lotl = list(status, "lotls").get(0);
            assertNotNull(map(lotl, "download").get("error"), "download error must be reported: " + lotl);
            assertEquals("TOTAL_PASSED/-", FixtureValidationTest.verdicts(
                    engine.validate(Fixtures.read("pades/b-lta.pdf"), ValidationOptions.DEFAULT)).get(0));
        }
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await(30, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> list(Map<String, Object> m, String key) {
        return (List<Map<String, Object>>) m.get(key);
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> map(Map<String, Object> m, String key) {
        return (Map<String, Object>) m.get(key);
    }
}
