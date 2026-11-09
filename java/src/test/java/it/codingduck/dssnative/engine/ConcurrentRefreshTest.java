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
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import it.codingduck.dssnative.testsupport.Fixtures;
import it.codingduck.dssnative.testsupport.SyntheticTrustedLists;
import it.codingduck.dssnative.testsupport.TestEngines;
import it.codingduck.dssnative.testsupport.TestPki;

/**
 * Validations keep running, with unchanged verdicts, while online refreshes replace the trusted lists. Each
 * refresh serves lists with a new sequence number, so DSS really re-synchronizes its certificate source every
 * time (the case where an in-place update would expose a half-built trust pool), and every other refresh drops
 * the DE list's CA, so the published pools really differ: a half-built or empty pool fails the fixtures (they
 * all hang off the IT list), and the trusted-certificate count a validator can observe is only ever one of the
 * two complete pools' counts.
 */
class ConcurrentRefreshTest {

    private static final int VALIDATOR_THREADS = 4;
    private static final int REFRESHES = 6;
    private static final long DOWNLOAD_DELAY_MS = 100;

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @TempDir
    Path tmp;

    @Test
    void validationsDuringRefreshesKeepTheirVerdicts() throws Exception {
        TestEngines t = new TestEngines(tmp);
        Map<String, String> expected = Map.of(
                "cades/attached-der.p7m", "TOTAL_PASSED/-",
                "cades/attached-ber.p7m", "TOTAL_PASSED/-",
                "pades/b-t.pdf", "TOTAL_PASSED/-",
                "pades/b-lta.pdf", "TOTAL_PASSED/-",
                "tampered/cades/attached-der.p7m", "TOTAL_FAILED/HASH_FAILURE");
        Map<String, byte[]> docs = new java.util.HashMap<>();
        expected.keySet().forEach(f -> docs.put(f, Fixtures.read(f)));
        List<String> names = new ArrayList<>(expected.keySet());

        try (DssEngine engine = t.onlineLoaded(tmp.resolve("cache"), null)) {
            AtomicBoolean stop = new AtomicBoolean();
            AtomicInteger validations = new AtomicInteger();
            ConcurrentLinkedQueue<String> failures = new ConcurrentLinkedQueue<>();
            ExecutorService pool = Executors.newFixedThreadPool(VALIDATOR_THREADS);
            List<Future<?>> workers = new ArrayList<>();
            for (int w = 0; w < VALIDATOR_THREADS; w++) {
                int offset = w;
                workers.add(pool.submit(() -> {
                    int i = offset;
                    while (!stop.get()) {
                        String name = names.get(i++ % names.size());
                        try {
                            ValidationResult r = engine.validate(docs.get(name), ValidationOptions.DEFAULT);
                            String got = FixtureValidationTest.verdicts(r).get(0);
                            if (!expected.get(name).equals(got)) {
                                failures.add(name + " -> " + got);
                            }
                            Object count = engine.trustedListStatus().get("trusted_certificates");
                            if (!Integer.valueOf(2).equals(count) && !Integer.valueOf(3).equals(count)) {
                                failures.add("trust pool with " + count + " certificates observed");
                            }
                        } catch (Throwable e) {
                            failures.add(name + " threw " + e);
                        }
                        validations.incrementAndGet();
                    }
                }));
            }

            // Slow each download down so refreshes last long enough for many validations to overlap them.
            t.http.beforeEachRequest(() -> sleep(DOWNLOAD_DELAY_MS));
            int before = validations.get();
            for (int seq = 2; seq < 2 + REFRESHES; seq++) {
                boolean withDeCa = seq % 2 == 0;
                new SyntheticTrustedLists(t.pki, seq).withDeCa(withDeCa ? TestPki.Entity.OTHER_CA : null).serveOn(t.http);
                TrustedListManager.RefreshRecord rec = engine.refreshTrustedListsOnline();
                assertTrue(rec.completed());
                assertEquals(withDeCa ? 3 : 2, rec.trustedCertificates(), "refresh " + seq);
            }
            int during = validations.get() - before;
            stop.set(true);
            for (Future<?> f : workers) {
                f.get(60, TimeUnit.SECONDS);
            }
            pool.shutdown();

            System.out.println("Concurrent run: " + validations.get() + " validations, " + during
                    + " of them while " + REFRESHES + " refreshes ran");
            assertTrue(failures.isEmpty(), "wrong verdicts or errors during refresh: " + failures);
            assertTrue(during >= VALIDATOR_THREADS * REFRESHES,
                    "only " + during + " validations overlapped the refreshes");

            @SuppressWarnings("unchecked")
            Map<String, Object> lotl = ((List<Map<String, Object>>) engine.trustedListStatus().get("lotls")).get(0);
            assertEquals(1 + REFRESHES, lotl.get("sequence_number"));
        }
    }
}
