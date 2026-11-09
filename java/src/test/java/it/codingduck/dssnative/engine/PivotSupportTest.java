/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import it.codingduck.dssnative.testsupport.Fixtures;
import it.codingduck.dssnative.testsupport.SyntheticTrustedLists;
import it.codingduck.dssnative.testsupport.SyntheticTrustedLists.ListSigner;
import it.codingduck.dssnative.testsupport.TestEngines;
import it.codingduck.dssnative.testsupport.TestPki;

/**
 * {@code pivot_support}: the LOTL is signed by a key the OJ keystore does not hold, and a chain of pivot LOTLs
 * leads from the OJ-announced signer to it (OJ signer signs pivot 1, which announces signer A; A signs pivot 2,
 * which announces B; B signs the LOTL). DSS follows the chain only with {@code pivot_support} on (the default),
 * and only when its first link is signed by the OJ keystore.
 */
class PivotSupportTest {

    @TempDir
    Path tmp;
    private TestEngines t;
    private SyntheticTrustedLists lists;

    @BeforeEach
    void serveAPivotChain() {
        t = new TestEngines(tmp);
        ListSigner a = TestPki.ephemeralListSigner("Pivot LOTL Signer A", 0, null);
        ListSigner b = TestPki.ephemeralListSigner("Pivot LOTL Signer B", 0, null);
        lists = new SyntheticTrustedLists(t.pki, 1).withPivots(a, b);
        lists.serveOn(t.http); // replaces the plain LOTL TestEngines serves
    }

    @Test
    void pivotSupportFollowsTheChainToASignerOutsideTheOjKeystore() {
        try (DssEngine engine = t.onlineLoaded(tmp.resolve("cache"), null)) {
            Map<String, Object> status = engine.trustedListStatus();
            Map<String, Object> lotl = TrustedListTest.list(status, "lotls").get(0);
            assertEquals("TOTAL_PASSED", TrustedListTest.map(lotl, "validation").get("indication"), lotl.toString());
            String signedBy = String.valueOf(TrustedListTest.map(lotl, "validation").get("signed_by"));
            assertTrue(signedBy.contains("CN=Pivot LOTL Signer B"), signedBy);
            assertEquals(Boolean.TRUE, lotl.get("used_for_trust"));

            List<Map<String, Object>> pivots = TrustedListTest.list(lotl, "pivots");
            assertEquals(List.of(lists.pivotUrl(1), lists.pivotUrl(2)),
                    pivots.stream().map(p -> (String) p.get("url")).sorted().toList());
            for (Map<String, Object> pivot : pivots) {
                assertEquals("TOTAL_PASSED", TrustedListTest.map(pivot, "validation").get("indication"),
                        pivot.toString());
            }
            assertEquals(1, t.http.hits(lists.pivotUrl(1)));
            assertEquals(1, t.http.hits(lists.pivotUrl(2)));

            assertEquals(3, status.get("trusted_certificates"));
            assertEquals("TOTAL_PASSED/-", FixtureValidationTest.verdicts(
                    engine.validate(Fixtures.read("pades/b-lta.pdf"), ValidationOptions.DEFAULT)).get(0));
        }
    }

    @Test
    void theChainIsKeptInTheCacheAndFollowedOffline() {
        Path cache = tmp.resolve("cache");
        t.onlineLoaded(cache, null).close();
        assertTrue(Files.isRegularFile(TrustedListTest.cacheFile(cache, lists.pivotUrl(1))));
        assertTrue(Files.isRegularFile(TrustedListTest.cacheFile(cache, lists.pivotUrl(2))));
        t.http.offline(true);
        int hits = t.http.totalHits();
        try (DssEngine engine = t.engine(cache, null)) {
            assertEquals(hits, t.http.totalHits(), "startup from the cache must not touch the network");
            assertEquals(3, engine.trustedListStatus().get("trusted_certificates"));
        }
    }

    @Test
    void withoutPivotSupportTheLotlSignerIsNotTrusted() {
        try (DssEngine engine = t.onlineLoaded(tmp.resolve("cache"), "\"pivot_support\":false")) {
            Map<String, Object> status = engine.trustedListStatus();
            Map<String, Object> lotl = TrustedListTest.list(status, "lotls").get(0);
            assertFalse("TOTAL_PASSED".equals(TrustedListTest.map(lotl, "validation").get("indication")),
                    lotl.toString());
            assertEquals(Boolean.FALSE, lotl.get("used_for_trust"));
            assertEquals(List.of(), TrustedListTest.list(lotl, "pivots"));
            assertEquals(0, t.http.hits(lists.pivotUrl(1)), "the pivots are not even downloaded");
            assertEquals(0, t.http.hits(lists.pivotUrl(2)));
            assertEquals(Boolean.FALSE, status.get("loaded"));
            assertEquals(0, status.get("trusted_certificates"));
        }
    }

    @Test
    void aChainNotStartingAtTheOjKeystoreIsNotFollowed() {
        // Pivot 1 signed by a key of the attacker's: everything after it is the attacker's word.
        ListSigner a = TestPki.ephemeralListSigner("Pivot LOTL Signer A", 0, null);
        ListSigner forger = TestPki.ephemeralListSigner("Forged Pivot Signer", 0, null);
        SyntheticTrustedLists forged = new SyntheticTrustedLists(t.pki, 1).withPivots(a).withFirstPivotSignedBy(forger);
        forged.serveOn(t.http);
        try (DssEngine engine = t.onlineLoaded(tmp.resolve("cache"), null)) {
            Map<String, Object> status = engine.trustedListStatus();
            Map<String, Object> lotl = TrustedListTest.list(status, "lotls").get(0);
            Map<String, Object> pivot = TrustedListTest.list(lotl, "pivots").get(0);
            assertFalse("TOTAL_PASSED".equals(TrustedListTest.map(pivot, "validation").get("indication")),
                    pivot.toString());
            assertFalse("TOTAL_PASSED".equals(TrustedListTest.map(lotl, "validation").get("indication")),
                    lotl.toString());
            assertEquals(Boolean.FALSE, lotl.get("used_for_trust"));
            assertEquals(0, status.get("trusted_certificates"));
            assertFalse(Files.exists(TrustedListTest.cacheFile(tmp.resolve("cache"), forged.pivotUrl(1))),
                    "an unusable pivot is not cached");
        }
    }
}
