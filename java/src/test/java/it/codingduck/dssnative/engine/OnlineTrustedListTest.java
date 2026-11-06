/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import it.codingduck.dssnative.testsupport.Fixtures;

/**
 * Against the real EU LOTL. Needs internet access: excluded from the default build, run with
 * {@code ./mvnw test -Pintegration}.
 */
@Tag("online")
class OnlineTrustedListTest {

    @TempDir
    Path tmp;

    private static String config(String extra) {
        Path keystore = Fixtures.repoRoot().resolve("trust/oj-keystore.p12");
        return "{\"oj_keystore\":{\"path\":\"" + keystore.toString().replace("\\", "\\\\") + "\"}"
                + (extra.isEmpty() ? "" : "," + extra) + "}";
    }

    /**
     * The real servers have hiccups: AgID's TSL-IT.xml has answered HTTP 504 in CI. Refreshes again, at most 3
     * times 30 s apart, while a list failed to download. A list that downloads but fails parsing or validation is
     * left to the assertions.
     */
    private static TrustedListManager.RefreshRecord refreshUntilDownloaded(DssEngine engine)
            throws InterruptedException {
        for (int attempt = 1; ; attempt++) {
            TrustedListManager.RefreshRecord rec = engine.refreshTrustedListsOnline();
            if (attempt == 3 || !downloadFailed(engine.trustedListStatus())) {
                return rec;
            }
            System.out.println("A list failed to download (attempt " + attempt + "), refreshing again in 30 s");
            Thread.sleep(30_000);
        }
    }

    /** A list whose download failed has no territory yet (it comes from parsing), so look at every list. */
    private static boolean downloadFailed(Map<String, Object> status) {
        return Stream.concat(TrustedListTest.list(status, "lotls").stream(),
                        TrustedListTest.list(status, "tls").stream())
                .anyMatch(l -> "ERROR".equals(TrustedListTest.map(l, "download").get("status")));
    }

    @Test
    void italianTrustedListLoadsAndValidates() throws InterruptedException {
        try (DssEngine engine = DssEngine.create(tmp, EngineConfig.fromJson(config("\"countries\":[\"IT\"]")))) {
            TrustedListManager.RefreshRecord rec = refreshUntilDownloaded(engine);
            Map<String, Object> status = engine.trustedListStatus();
            System.out.println("IT refresh: " + Json.write(rec.toMap()));
            assertTrue(rec.completed());
            assertEquals(Boolean.TRUE, status.get("loaded"));

            Map<String, Object> lotl = TrustedListTest.list(status, "lotls").get(0);
            assertEquals("TOTAL_PASSED", TrustedListTest.map(lotl, "validation").get("indication"),
                    "LOTL signature (is the OJ keystore / oj_url current?): " + Json.write(lotl));
            List<Map<String, Object>> tls = TrustedListTest.list(status, "tls");
            assertEquals(List.of("IT"), tls.stream().map(m -> m.get("territory")).toList());
            assertEquals("TOTAL_PASSED", TrustedListTest.map(tls.get(0), "validation").get("indication"));
        }
        // And again from the cache, offline.
        try (DssEngine engine = DssEngine.create(tmp, EngineConfig.fromJson(config("\"countries\":[\"IT\"]")))) {
            assertEquals(Boolean.TRUE, engine.trustedListStatus().get("loaded"));
        }
    }

    @Test
    void fullLotlLoads() {
        try (DssEngine engine = DssEngine.create(tmp, EngineConfig.fromJson(config("")))) {
            TrustedListManager.RefreshRecord rec = engine.refreshTrustedListsOnline();
            Map<String, Object> status = engine.trustedListStatus();
            System.out.println("Full refresh: " + Json.write(rec.toMap()));
            List<Map<String, Object>> tls = TrustedListTest.list(status, "tls");
            long valid = tls.stream()
                    .filter(m -> "TOTAL_PASSED".equals(TrustedListTest.map(m, "validation").get("indication")))
                    .count();
            System.out.println("Full LOTL: " + tls.size() + " TLs, " + valid + " valid, "
                    + status.get("trusted_certificates") + " trusted certificates");
            for (Map<String, Object> tl : tls) {
                if (!"TOTAL_PASSED".equals(TrustedListTest.map(tl, "validation").get("indication"))) {
                    System.out.println("  not valid: " + tl.get("territory") + " " + tl.get("url") + " "
                            + Json.write(TrustedListTest.map(tl, "validation")) + " "
                            + Json.write(TrustedListTest.map(tl, "download")));
                }
            }
            assertTrue(tls.size() >= 27, "expected every EU/EEA TL, got " + tls.size());
            // TL downloads skip TLS server checks (tl_verify_tls=false), so certificate-path errors must not occur.
            for (Map<String, Object> tl : tls) {
                Object error = TrustedListTest.map(tl, "download").get("error");
                assertTrue(error == null || !error.toString().contains("PKIX"), tl.get("url") + ": " + error);
            }
            assertTrue(valid >= tls.size() - 3, "too many invalid TLs");
        }
    }
}
