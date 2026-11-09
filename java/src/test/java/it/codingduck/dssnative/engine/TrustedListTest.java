/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.spi.DSSUtils;

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
            assertEquals(rec.durationMs(), map(status, "last_online_refresh").get("duration_ms"));
            assertTrue(rec.durationMs() >= 0, "duration_ms must never be negative");

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
    void statusReportsTheOjKeystoreInUse() {
        TestEngines t = new TestEngines(tmp);
        try (DssEngine engine = t.engine(tmp.resolve("cache"), null)) {
            // Before any refresh: the root of trust is known from init.
            Map<String, Object> keystore = map(engine.trustedListStatus(), "oj_keystore");
            assertEquals(t.ojKeystore.toString(), keystore.get("path"));
            String sha256 = (String) keystore.get("sha256");
            assertTrue(sha256.matches("[0-9a-f]{64}"), sha256);

            engine.refreshTrustedListsOnline();
            // The same digest a snapshot records, so a snapshot's provenance can be checked against the status.
            Map<String, Object> settings = map(engine.exportTlSnapshot().info(), "settings");
            assertEquals(sha256, settings.get("oj_keystore_sha256"));
            assertEquals(keystore, map(engine.trustedListStatus(), "oj_keystore"));
        }
    }

    @Test
    void refreshDurationIsNeverNegative() {
        Instant later = Instant.parse("2026-01-01T00:00:10Z");
        Instant earlier = Instant.parse("2026-01-01T00:00:00Z");
        // A backwards clock step between the two wall-clock reads: the measured duration wins, never below zero.
        TrustedListManager.RefreshRecord measured = new TrustedListManager.RefreshRecord("online", later, earlier,
                true, null, 3, 1_234L);
        assertEquals(1_234L, measured.toMap().get("duration_ms"));
        TrustedListManager.RefreshRecord wallClock = new TrustedListManager.RefreshRecord("online", later, earlier,
                true, null, 3);
        assertEquals(0L, wallClock.toMap().get("duration_ms"));
        assertEquals(later.toString(), wallClock.toMap().get("started_at"));
        assertEquals(earlier.toString(), wallClock.toMap().get("finished_at"));
        TrustedListManager.RefreshRecord negative = new TrustedListManager.RefreshRecord("online", earlier, later,
                false, "x", 0, -5L);
        assertEquals(0L, negative.durationMs());
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

    /** A LOTL signed by a key outside the OJ keystore must not empty the trust pool, nor the cache. */
    @Test
    void badlySignedLotlKeepsThePreviousListsAndTheCache() throws IOException {
        TestEngines t = new TestEngines(tmp);
        Path cache = tmp.resolve("cache");
        try (DssEngine engine = t.onlineLoaded(cache, null)) {
            assertEquals(3, engine.trustedListStatus().get("trusted_certificates"));
            byte[] cachedLotl = Files.readAllBytes(cacheFile(cache, SyntheticTrustedLists.LOTL_URL));
            byte[] cachedIt = Files.readAllBytes(cacheFile(cache, SyntheticTrustedLists.IT_TL_URL));

            t.http.route(SyntheticTrustedLists.LOTL_URL,
                    new SyntheticTrustedLists(t.pki, 2).lotlSignedBy(TestPki.Entity.TL_SIGNER));
            TrustedListManager.RefreshRecord rec = engine.refreshTrustedListsOnline();
            assertFalse(rec.completed(), "a refresh that would drop every anchor is not published");
            assertTrue(rec.error().contains("LOTL"), rec.error());
            assertEquals(3, rec.trustedCertificates());

            Map<String, Object> status = engine.trustedListStatus();
            assertEquals(Boolean.TRUE, status.get("loaded"));
            assertEquals(3, status.get("trusted_certificates"));
            assertEquals("TOTAL_PASSED/-", FixtureValidationTest.verdicts(
                    engine.validate(Fixtures.read("pades/b-lta.pdf"), ValidationOptions.DEFAULT)).get(0));
            assertTrue(alertTypes(status).contains("refresh_not_published"), status.get("alerts").toString());
            assertArrayEquals(cachedLotl, Files.readAllBytes(cacheFile(cache, SyntheticTrustedLists.LOTL_URL)),
                    "the bad LOTL must not replace the good one in the cache");
            assertArrayEquals(cachedIt, Files.readAllBytes(cacheFile(cache, SyntheticTrustedLists.IT_TL_URL)),
                    "lists reached through a bad LOTL are not stored on its word");

            // Back to a good LOTL: the next refresh publishes again.
            new SyntheticTrustedLists(t.pki, 3).serveOn(t.http);
            assertTrue(engine.refreshTrustedListsOnline().completed());
            assertEquals(3, engine.trustedListStatus().get("trusted_certificates"));
        }
        t.http.offline(true);
        try (DssEngine restarted = t.engine(cache, null)) {
            assertEquals(3, restarted.trustedListStatus().get("trusted_certificates"));
        }
    }

    /** A 200 with an error page (captive portal, CDN) must not reach the cache: the next start would lose the list. */
    @Test
    void nonXmlResponseIsReportedAndDoesNotReachTheCache() throws IOException {
        TestEngines t = new TestEngines(tmp);
        Path cache = tmp.resolve("cache");
        try (DssEngine engine = t.onlineLoaded(cache, null)) {
            byte[] cachedIt = Files.readAllBytes(cacheFile(cache, SyntheticTrustedLists.IT_TL_URL));
            t.http.route(SyntheticTrustedLists.IT_TL_URL, "not xml at all: 502 Bad Gateway".getBytes(StandardCharsets.UTF_8));
            TrustedListManager.RefreshRecord rec = engine.refreshTrustedListsOnline();
            assertTrue(rec.completed(), "one bad list is a per-list problem");
            Map<String, Object> status = engine.trustedListStatus();
            assertEquals(3, status.get("trusted_certificates"), "DSS keeps the last good parse of the list");
            Map<String, Object> it = byTerritory(status).get("IT");
            assertEquals("ERROR", map(it, "download").get("status"));
            assertTrue(String.valueOf(map(it, "download").get("error")).contains("not an acceptable trusted list"),
                    it.toString());
            assertArrayEquals(cachedIt, Files.readAllBytes(cacheFile(cache, SyntheticTrustedLists.IT_TL_URL)));

            // The LOTL itself: same thing, nothing is lost.
            t.http.route(SyntheticTrustedLists.LOTL_URL, "<html><body>portal</body></html>".getBytes(StandardCharsets.UTF_8));
            assertTrue(engine.refreshTrustedListsOnline().completed());
            assertEquals(3, engine.trustedListStatus().get("trusted_certificates"));
        }
        t.http.offline(true);
        try (DssEngine restarted = t.engine(cache, null)) {
            assertEquals(3, restarted.trustedListStatus().get("trusted_certificates"));
        }
    }

    /** Lists are renamed into the cache whole; nothing half-written or temporary is left behind. */
    @Test
    void cacheFilesAreWrittenWholeAndStagingIsCleanedUp() throws IOException {
        TestEngines t = new TestEngines(tmp);
        Path cache = tmp.resolve("cache");
        Path tl = cache.resolve("tl");
        try (DssEngine engine = t.onlineLoaded(cache, null)) {
            try (Stream<Path> files = Files.list(tl)) {
                Set<String> names = files.map(p -> p.getFileName().toString()).collect(java.util.stream.Collectors.toSet());
                assertEquals(Set.of(DSSUtils.getNormalizedString(SyntheticTrustedLists.DE_TL_URL),
                        DSSUtils.getNormalizedString(SyntheticTrustedLists.IT_TL_URL),
                        DSSUtils.getNormalizedString(SyntheticTrustedLists.LOTL_URL)), names, "lists only, no temporary files");
            }
            // A pre-existing garbage file (a torn write by an older version) is reported, not trusted, and replaced.
            Files.writeString(cacheFile(cache, SyntheticTrustedLists.DE_TL_URL), "<tsl:Trust");
            assertTrue(engine.refreshTrustedListsOnline().completed());
            assertArrayEquals(t.http.get(SyntheticTrustedLists.DE_TL_URL),
                    Files.readAllBytes(cacheFile(cache, SyntheticTrustedLists.DE_TL_URL)));
        }
        try (Stream<Path> staging = Files.list(cache.resolve("tl-staging"))) {
            assertEquals(0, staging.count(), "the staging directory is emptied on close");
        }
        // Torn or garbage files in the cache are a download error for that list, nothing more.
        Files.writeString(cacheFile(cache, SyntheticTrustedLists.IT_TL_URL), "<?xml version=\"1.0\"?><tsl:TrustServiceStatusList");
        t.http.offline(true);
        try (DssEngine restarted = t.engine(cache, null)) {
            Map<String, Object> status = restarted.trustedListStatus();
            assertEquals(1, status.get("trusted_certificates"), "DE still loads");
            assertEquals("ERROR", map(byUrl(status, SyntheticTrustedLists.IT_TL_URL), "download").get("status"));
        }
    }

    @Test
    void alertsAreKeyedByTypeAndUrlAndCounted() {
        TestEngines t = new TestEngines(tmp);
        new SyntheticTrustedLists(t.pki, 1).withNextUpdateIn(Duration.ofSeconds(-60)).serveOn(t.http);
        try (DssEngine engine = t.onlineLoaded(tmp.resolve("cache"), null)) {
            for (int i = 0; i < 3; i++) {
                assertTrue(engine.refreshTrustedListsOnline().completed());
            }
            List<Map<String, Object>> alerts = list(engine.trustedListStatus(), "alerts");
            List<Map<String, Object>> expired = alerts.stream().filter(a -> a.get("type").toString().endsWith("_expired")).toList();
            assertEquals(3, expired.size(), "one entry per list, however many refreshes: " + alerts);
            for (Map<String, Object> a : expired) {
                assertEquals(4, a.get("count"), a.toString());
                assertNotNull(a.get("first_seen"));
                assertEquals(a.get("last_seen"), a.get("at"));
            }
            assertEquals(Set.of("lotl_expired", "tl_expired"),
                    expired.stream().map(a -> (String) a.get("type")).collect(java.util.stream.Collectors.toSet()));
        }
    }

    @Test
    void unmatchedCountriesAreReported() {
        TestEngines t = new TestEngines(tmp);
        try (DssEngine engine = t.onlineLoaded(tmp.resolve("cache"), TestEngines.countries(List.of("IT", "XX")))) {
            Map<String, Object> status = engine.trustedListStatus();
            assertEquals(Boolean.TRUE, status.get("loaded"));
            assertEquals(List.of("XX"), status.get("countries_unmatched"));
            Map<String, Object> alert = list(status, "alerts").stream()
                    .filter(a -> "countries_unmatched".equals(a.get("type"))).findFirst().orElseThrow();
            assertTrue(alert.get("message").toString().contains("XX"), alert.toString());
        }
        try (DssEngine engine = t.onlineLoaded(tmp.resolve("cache-ok"), TestEngines.countries(List.of("IT")))) {
            assertEquals(List.of(), engine.trustedListStatus().get("countries_unmatched"));
        }
    }

    /** {@code tl_versions} only makes DSS flag the structure; the flag is now visible and can exclude the list. */
    @Test
    void structureMessagesAreReportedAndCanExcludeLists() {
        TestEngines t = new TestEngines(tmp);
        new SyntheticTrustedLists(t.pki, 1).withVersion(5).serveOn(t.http);
        try (DssEngine lenient = t.onlineLoaded(tmp.resolve("lenient"), null)) {
            Map<String, Object> status = lenient.trustedListStatus();
            assertEquals(3, status.get("trusted_certificates"), "DSS's default: flagged lists are still used");
            for (Map<String, Object> tl : list(status, "tls")) {
                assertEquals(5, tl.get("version"));
                assertEquals(Boolean.TRUE, tl.get("used_for_trust"));
                assertFalse(((List<?>) tl.get("structure_messages")).isEmpty(), tl.toString());
            }
            assertTrue(alertTypes(status).containsAll(Set.of("tl_structure_error", "lotl_structure_error")),
                    status.get("alerts").toString());
        }
        try (DssEngine strict = t.onlineLoaded(tmp.resolve("strict"), "\"tl_sync\":{\"accept_structure_errors\":false}")) {
            Map<String, Object> status = strict.trustedListStatus();
            assertEquals(0, status.get("trusted_certificates"));
            list(status, "tls").forEach(tl -> assertEquals(Boolean.FALSE, tl.get("used_for_trust")));
        }
        // [] is DSS's own default, versions 5 and 6: the version is accepted (DSS then checks the list against the
        // v5 schema, which this v6-shaped list does not quite fit; that message is DSS's, and stays visible).
        try (DssEngine both = t.onlineLoaded(tmp.resolve("both"), "\"tl_versions\":[]")) {
            Map<String, Object> status = both.trustedListStatus();
            assertEquals(3, status.get("trusted_certificates"));
            for (Map<String, Object> tl : list(status, "tls")) {
                assertFalse(tl.get("structure_messages").toString().contains("not acceptable"), tl.toString());
            }
        }
        try (DssEngine lenient = t.onlineLoaded(tmp.resolve("lenient-check"), null)) {
            for (Map<String, Object> tl : list(lenient.trustedListStatus(), "tls")) {
                assertTrue(tl.get("structure_messages").toString().contains("The TL Version '5' is not acceptable"),
                        tl.toString());
            }
        }
    }

    /**
     * {@code use_sunset_date} (F-266): a CA whose service was granted, then withdrawn, is a trust anchor only for the
     * granted period. The fixtures were signed in October 2026; the IT CA's service history says granted since
     * 2020 and withdrawn since {@code withdrawn}.
     */
    @Test
    void sunsetDateLimitsTrustToTheServiceHistory() {
        TestEngines t = new TestEngines(tmp);
        // Withdrawn after the signatures were made: B, T and LT have no proof of existence before the withdrawal
        // that DSS accepts at validation time, so they are INDETERMINATE; the LTA archive timestamp is that proof.
        new SyntheticTrustedLists(t.pki, 1).withItCaWithdrawnSince(Instant.now().minus(Duration.ofHours(1))).serveOn(t.http);
        try (DssEngine sunset = t.onlineLoaded(tmp.resolve("sunset"), null)) {
            assertEquals(3, sunset.trustedListStatus().get("trusted_certificates"),
                    "the withdrawn CA is still listed (and used for the periods it was granted)");
            assertEquals(Map.of(
                    "pades/b-b.pdf", "INDETERMINATE/NO_CERTIFICATE_CHAIN_FOUND_NO_POE",
                    "pades/b-t.pdf", "INDETERMINATE/NO_CERTIFICATE_CHAIN_FOUND_NO_POE",
                    "pades/b-lt.pdf", "INDETERMINATE/NO_CERTIFICATE_CHAIN_FOUND_NO_POE",
                    "pades/b-lta.pdf", "TOTAL_PASSED/-"), padesVerdicts(sunset));
        }
        // Withdrawn before the signatures were made: nothing, not even the archive timestamp, places a signature
        // in the granted period, so every level is INDETERMINATE.
        new SyntheticTrustedLists(t.pki, 1).withItCaWithdrawnSince(Instant.parse("2020-06-01T00:00:00Z")).serveOn(t.http);
        try (DssEngine earlier = t.onlineLoaded(tmp.resolve("earlier"), null)) {
            for (Map.Entry<String, String> e : padesVerdicts(earlier).entrySet()) {
                assertEquals("INDETERMINATE/NO_CERTIFICATE_CHAIN_FOUND_NO_POE", e.getValue(), e.getKey());
            }
        }
        // use_sunset_date=false: a listed certificate is a trust anchor at all times, whatever its service status.
        try (DssEngine permanent = t.onlineLoaded(tmp.resolve("permanent"), "\"use_sunset_date\":false")) {
            for (Map.Entry<String, String> e : padesVerdicts(permanent).entrySet()) {
                assertEquals("TOTAL_PASSED/-", e.getValue(), e.getKey() + ": without sunset dates a listed CA is an anchor whatever its status");
            }
        }
    }

    /** First-signature verdict ({@code INDICATION/SUB_INDICATION}) of each PAdES baseline fixture, by fixture. */
    private static Map<String, String> padesVerdicts(DssEngine engine) {
        Map<String, String> out = new LinkedHashMap<>();
        for (String fixture : List.of("pades/b-b.pdf", "pades/b-t.pdf", "pades/b-lt.pdf", "pades/b-lta.pdf")) {
            out.put(fixture, FixtureValidationTest.verdicts(engine.validate(Fixtures.read(fixture), ValidationOptions.DEFAULT)).get(0));
        }
        return out;
    }

    @Test
    void closeReportsWhetherTheListThreadsStopped() throws Exception {
        TestEngines t = new TestEngines(tmp);
        TrustedListManager idle = new TrustedListManager(tmp.resolve("cache"), EngineConfig.fromJson(t.configJson(null)), t.http);
        assertTrue(idle.offlineRefresh().completed());
        idle.close();
        assertTrue(idle.threadsStopped());

        // A download that does not end (here: one that ignores the interrupt, as a socket read does) outlasts
        // the wait: close() says so, and the thread ends with the download.
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        t.http.beforeEachRequest(() -> {
            entered.countDown();
            boolean interrupted = false;
            while (release.getCount() > 0) {
                try {
                    release.await(30, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    interrupted = true;
                }
            }
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
        });
        TrustedListManager busy = new TrustedListManager(tmp.resolve("cache-busy"),
                EngineConfig.fromJson(t.configJson(null)), t.http, Duration.ofMillis(200));
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<TrustedListManager.RefreshRecord> refresh = pool.submit(busy::onlineRefresh);
            assertTrue(entered.await(10, TimeUnit.SECONDS));
            busy.close();
            assertFalse(busy.threadsStopped(), "a thread was still inside the download");
            release.countDown();
            refresh.get(30, TimeUnit.SECONDS);
        } finally {
            release.countDown();
            pool.shutdownNow();
        }
    }

    /** A refresh under a closed (or replaced) engine says so, not what a ThreadPoolExecutor looks like. */
    @Test
    void refreshAfterCloseReportsTheInterruption() {
        TestEngines t = new TestEngines(tmp);
        TrustedListManager manager = new TrustedListManager(tmp.resolve("cache"), EngineConfig.fromJson(t.configJson(null)), t.http);
        assertTrue(manager.onlineRefresh().completed());
        manager.close();
        TrustedListManager.RefreshRecord rec = manager.onlineRefresh();
        assertFalse(rec.completed());
        assertEquals("the refresh was interrupted: the engine was closed or replaced while it ran", rec.error());
        assertEquals(3, rec.trustedCertificates(), "the published lists stay");
        assertEquals(3, manager.status().get("trusted_certificates"));
    }

    /**
     * Rollback protection: TL downloads are not TLS-authenticated by default, so a replayed, validly signed older
     * list (one still listing a withdrawn CA) must not displace the newer one, in memory or in the cache, and not
     * after a restart either.
     */
    @Test
    void anOlderListIsRefusedAsARollback() throws IOException {
        TestEngines t = new TestEngines(tmp);
        Path cache = tmp.resolve("cache");
        new SyntheticTrustedLists(t.pki, 7).serveOn(t.http);
        SyntheticTrustedLists older = new SyntheticTrustedLists(t.pki, 6).withDeCa(TestPki.Entity.ROOT_CA);
        try (DssEngine engine = t.onlineLoaded(cache, null)) {
            assertEquals(3, engine.trustedListStatus().get("trusted_certificates"));
            byte[] cachedDe = Files.readAllBytes(cacheFile(cache, SyntheticTrustedLists.DE_TL_URL));
            for (Map<String, Object> l : list(engine.trustedListStatus(), "tls")) {
                assertEquals(7L, l.get("last_published_sequence_number"), l.toString());
            }
            assertTrue(Files.isRegularFile(cache.resolve(TrustedListManager.SEQUENCE_FILE)));

            // DE replayed at sequence 6 (which would make the test root CA a DE anchor too): refused for that list.
            t.http.route(SyntheticTrustedLists.DE_TL_URL, older.tl("DE", TestPki.Entity.ROOT_CA, null));
            TrustedListManager.RefreshRecord rec = engine.refreshTrustedListsOnline();
            assertTrue(rec.completed(), "one list is a per-list problem");
            Map<String, Object> status = engine.trustedListStatus();
            assertEquals(3, status.get("trusted_certificates"), "DE keeps its sequence-7 result");
            Map<String, Object> de = byTerritory(status).get("DE");
            assertEquals(7, de.get("sequence_number"));
            assertEquals("ERROR", map(de, "download").get("status"));
            assertTrue(String.valueOf(map(de, "download").get("error")).contains("rollback"), de.toString());
            Map<String, Object> alert = list(status, "alerts").stream()
                    .filter(a -> "tl_rollback".equals(a.get("type"))).findFirst().orElseThrow(() -> new AssertionError(status));
            assertEquals(SyntheticTrustedLists.DE_TL_URL, alert.get("url"));
            assertEquals(7L, alert.get("previous_sequence_number"));
            assertEquals(6L, alert.get("sequence_number"));
            assertNotNull(alert.get("previous_issue_date"));
            assertNotNull(alert.get("issue_date"));
            assertArrayEquals(cachedDe, Files.readAllBytes(cacheFile(cache, SyntheticTrustedLists.DE_TL_URL)),
                    "the replayed list never reaches the cache");
            try (DssEngine noFloor = t.onlineLoaded(tmp.resolve("de-only"), TestEngines.countries(List.of("DE")))) {
                assertEquals("TOTAL_PASSED/-", FixtureValidationTest.verdicts(
                        noFloor.validate(Fixtures.read("cades/attached-der.p7m"), ValidationOptions.DEFAULT)).get(0),
                        "sanity: without a floor the replayed DE list makes the test root CA an anchor");
            }

            // The LOTL too: refused, and DSS keeps the lists it had.
            t.http.route(SyntheticTrustedLists.LOTL_URL, older.lotl());
            assertTrue(engine.refreshTrustedListsOnline().completed());
            assertEquals(3, engine.trustedListStatus().get("trusted_certificates"));
            assertEquals("ERROR", map(list(engine.trustedListStatus(), "lotls").get(0), "download").get("status"));

            // Sequence 8 is newer: accepted, and the floor moves up.
            new SyntheticTrustedLists(t.pki, 8).serveOn(t.http);
            assertTrue(engine.refreshTrustedListsOnline().completed());
            assertEquals(8, byTerritory(engine.trustedListStatus()).get("DE").get("sequence_number"));
            assertEquals(8L, byTerritory(engine.trustedListStatus()).get("DE").get("last_published_sequence_number"));
        }

        // A restart with the cache file itself replaced by the older list: the persisted floor refuses it.
        Files.write(cacheFile(cache, SyntheticTrustedLists.DE_TL_URL), older.tl("DE", TestPki.Entity.ROOT_CA, null));
        t.http.offline(true);
        try (DssEngine restarted = t.engine(cache, null)) {
            Map<String, Object> status = restarted.trustedListStatus();
            assertEquals(2, status.get("trusted_certificates"), "IT loads, the rolled-back DE file does not");
            Map<String, Object> de = byUrl(status, SyntheticTrustedLists.DE_TL_URL);
            assertTrue(String.valueOf(map(de, "download").get("error")).contains("rollback"), de.toString());
            assertTrue(alertTypes(status).contains("tl_rollback"));
            assertEquals(8L, de.get("last_published_sequence_number"));
        }
        // Without the persisted floor the same file would load: the record is what protects a restart.
        Files.delete(cache.resolve(TrustedListManager.SEQUENCE_FILE));
        try (DssEngine unprotected = t.engine(cache, null)) {
            Map<String, Object> de = byUrl(unprotected.trustedListStatus(), SyntheticTrustedLists.DE_TL_URL);
            assertEquals(6, de.get("sequence_number"));
            assertEquals(Boolean.TRUE, de.get("used_for_trust"));
        }
    }

    /** Only lists the refresh trusts raise the floor: a forged list with a huge number cannot block the real one. */
    @Test
    void untrustedListsDoNotRaiseTheRollbackFloor() {
        TestEngines t = new TestEngines(tmp);
        SyntheticTrustedLists lists = new SyntheticTrustedLists(t.pki, 1);
        t.http.route(SyntheticTrustedLists.IT_TL_URL, new SyntheticTrustedLists(t.pki, 1_000_000)
                .tlSignedBy("IT", TestPki.Entity.ROOT_CA, TestPki.Entity.TSA, TestPki.Entity.LOTL_SIGNER));
        try (DssEngine engine = t.onlineLoaded(tmp.resolve("cache"), null)) {
            Map<String, Object> it = byTerritory(engine.trustedListStatus()).get("IT");
            assertEquals(Boolean.FALSE, it.get("used_for_trust"));
            assertEquals(null, it.get("last_published_sequence_number"), it.toString());
            t.http.route(SyntheticTrustedLists.IT_TL_URL, lists.tl("IT", TestPki.Entity.ROOT_CA, TestPki.Entity.TSA));
            assertTrue(engine.refreshTrustedListsOnline().completed());
            assertEquals(3, engine.trustedListStatus().get("trusted_certificates"));
            assertEquals(1L, byTerritory(engine.trustedListStatus()).get("IT").get("last_published_sequence_number"));
            assertFalse(alertTypes(engine.trustedListStatus()).contains("tl_rollback"));
        }
    }

    /** With {@code online_cache_expiration_ms}, a fresh but unusable cache file is replaced, not waited out. */
    @Test
    void garbageInAFreshCacheFileIsReplacedDespiteTheCacheExpiration() throws IOException {
        TestEngines t = new TestEngines(tmp);
        Path cache = tmp.resolve("cache");
        try (DssEngine engine = t.onlineLoaded(cache, "\"online_cache_expiration_ms\":3600000")) {
            int hits = t.http.hits(SyntheticTrustedLists.DE_TL_URL);
            assertTrue(engine.refreshTrustedListsOnline().completed());
            assertEquals(hits, t.http.hits(SyntheticTrustedLists.DE_TL_URL), "a fresh cached copy is not re-downloaded");

            Files.writeString(cacheFile(cache, SyntheticTrustedLists.DE_TL_URL), "<tsl:Trust");
            assertTrue(engine.refreshTrustedListsOnline().completed());
            assertEquals(hits + 1, t.http.hits(SyntheticTrustedLists.DE_TL_URL), "the garbage file is replaced by a download");
            assertArrayEquals(t.http.get(SyntheticTrustedLists.DE_TL_URL),
                    Files.readAllBytes(cacheFile(cache, SyntheticTrustedLists.DE_TL_URL)));
            Map<String, Object> de = byTerritory(engine.trustedListStatus()).get("DE");
            assertEquals("SYNCHRONIZED", map(de, "download").get("status"), de.toString());
            assertEquals(3, engine.trustedListStatus().get("trusted_certificates"));
        }
    }

    /** Cache write failures are reported per list, and a cache directory that cannot be created says why. */
    @Test
    void cacheWriteFailuresNameTheListAndTheCause() throws IOException {
        TestEngines t = new TestEngines(tmp);
        Path blocked = Files.createDirectories(tmp.resolve("blocked"));
        Files.writeString(blocked.resolve("tl"), "a file where the directory should be");
        DssError e = assertThrows(DssError.class, () -> t.engine(blocked, null).close());
        assertEquals(DssError.Code.INVALID_CONFIG, e.code());
        assertTrue(e.getMessage().contains("cannot create cache directory"), e.getMessage());
        assertTrue(e.getMessage().contains("Exception"), "the cause is in the message: " + e.getMessage());

        org.junit.jupiter.api.Assumptions.assumeTrue(
                Files.getFileStore(tmp).supportsFileAttributeView("posix") && !"root".equals(System.getProperty("user.name")),
                "needs POSIX permissions that bind the current user");
        Path cache = tmp.resolve("cache");
        Path tl = cache.resolve("tl");
        try (DssEngine engine = t.onlineLoaded(cache, null)) {
            new SyntheticTrustedLists(t.pki, 2).serveOn(t.http);
            Files.setPosixFilePermissions(tl, java.nio.file.attribute.PosixFilePermissions.fromString("r-x------"));
            try {
                assertTrue(engine.refreshTrustedListsOnline().completed());
            } finally {
                Files.setPosixFilePermissions(tl, java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
            }
            List<Map<String, Object>> errors = list(engine.trustedListStatus(), "alerts").stream()
                    .filter(a -> "cache_write_error".equals(a.get("type"))).toList();
            assertEquals(Set.of(SyntheticTrustedLists.LOTL_URL, SyntheticTrustedLists.IT_TL_URL, SyntheticTrustedLists.DE_TL_URL),
                    errors.stream().map(a -> (String) a.get("url")).collect(java.util.stream.Collectors.toSet()), errors.toString());
            errors.forEach(a -> assertTrue(a.get("message").toString().contains("Exception"), a.toString()));
            assertEquals(2, byTerritory(engine.trustedListStatus()).get("DE").get("sequence_number"), "the lists are in use anyway");
        }
    }

    static Path cacheFile(Path cacheDir, String url) {
        return cacheDir.resolve("tl").resolve(DSSUtils.getNormalizedString(url));
    }

    static Set<String> alertTypes(Map<String, Object> status) {
        return list(status, "alerts").stream().map(a -> (String) a.get("type")).collect(java.util.stream.Collectors.toSet());
    }

    static Map<String, Map<String, Object>> byTerritory(Map<String, Object> status) {
        Map<String, Map<String, Object>> out = new java.util.HashMap<>();
        list(status, "tls").forEach(tl -> out.put((String) tl.get("territory"), tl));
        return out;
    }

    static Map<String, Object> byUrl(Map<String, Object> status, String url) {
        return Stream.concat(list(status, "lotls").stream(), list(status, "tls").stream())
                .filter(l -> url.equals(l.get("url"))).findFirst().orElseThrow();
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
