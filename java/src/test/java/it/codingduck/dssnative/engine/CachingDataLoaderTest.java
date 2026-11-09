/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;

import it.codingduck.dssnative.testsupport.FakeHttp;
import it.codingduck.dssnative.testsupport.TestPki;
import it.codingduck.dssnative.testsupport.TestPki.Entity;

/** GET responses (CRLs, AIA) are reused across calls for a while; POSTs never; bounds hold. */
class CachingDataLoaderTest {

    private static final String CRL = "http://crl.example.test/ca.crl";

    @Test
    void getsAreServedFromTheCacheWithinTheTtl() {
        FakeHttp http = new FakeHttp().route(CRL, "crl-1".getBytes());
        CachingDataLoader cache = new CachingDataLoader(http, 60_000);
        assertArrayEquals("crl-1".getBytes(), cache.get(CRL));
        http.route(CRL, "crl-2".getBytes());
        assertArrayEquals("crl-1".getBytes(), cache.get(CRL), "still the cached body");
        assertEquals(1, http.hits(CRL));
        DataLoader.DataAndUrl several = cache.get(List.of("http://other.example.test/x", CRL));
        assertEquals(CRL, several.getUrlString(), "a cached URL in the list wins without a request");
        assertEquals(1, http.totalHits());
    }

    @Test
    void expiredEntriesAreFetchedAgain() throws InterruptedException {
        FakeHttp http = new FakeHttp().route(CRL, "crl-1".getBytes());
        CachingDataLoader cache = new CachingDataLoader(http, 50);
        cache.get(CRL);
        http.route(CRL, "crl-2".getBytes());
        Thread.sleep(80);
        assertArrayEquals("crl-2".getBytes(), cache.get(CRL));
        assertEquals(2, http.hits(CRL));
    }

    @Test
    void postsAndFailuresAreNotCached() {
        FakeHttp http = new FakeHttp().postRoute("http://ocsp.example.test", request -> "resp".getBytes());
        CachingDataLoader cache = new CachingDataLoader(http, 60_000);
        cache.post("http://ocsp.example.test", new byte[] {1});
        cache.post("http://ocsp.example.test", new byte[] {1});
        assertEquals(2, http.hits("http://ocsp.example.test"));
        assertThrows(DSSExternalResourceException.class, () -> cache.get("http://missing.example.test/crl"));
        assertEquals(0, cache.size());
    }

    @Test
    void boundsEvictTheLeastRecentlyUsed() {
        FakeHttp http = new FakeHttp();
        for (int i = 0; i < 5; i++) {
            http.route("http://crl.example.test/" + i, new byte[10]);
        }
        CachingDataLoader cache = new CachingDataLoader(http, 60_000, 3, 1_000);
        for (int i = 0; i < 4; i++) {
            cache.get("http://crl.example.test/" + i);
        }
        assertEquals(List.of("http://crl.example.test/1", "http://crl.example.test/2", "http://crl.example.test/3"),
                cache.urls());
        cache.get("http://crl.example.test/1"); // now the most recent
        cache.get("http://crl.example.test/4");
        assertEquals(List.of("http://crl.example.test/3", "http://crl.example.test/1", "http://crl.example.test/4"),
                cache.urls());

        CachingDataLoader small = new CachingDataLoader(http, 60_000, 10, 25);
        small.get("http://crl.example.test/0");
        small.get("http://crl.example.test/1");
        small.get("http://crl.example.test/2");
        assertEquals(2, small.size(), "30 bytes do not fit in 25");
        http.route("http://big.example.test", new byte[26]);
        small.get("http://big.example.test");
        assertEquals(2, small.size(), "a body above the whole budget is passed through, not kept");
    }

    // ------------------------------------------------------------------ what a body is decides how long it stays

    @Test
    void theTtlDependsOnWhatTheBodyIs() throws Exception {
        TestPki pki = TestPki.load();
        long now = System.currentTimeMillis();
        long hour = 3_600_000;
        assertEquals(hour, CachingDataLoader.ttlFor(pki.freshCrl(), hour, now), "a CRL good for a week: the TTL");
        assertEquals(hour, CachingDataLoader.ttlFor(pki.x509(Entity.ROOT_CA).getEncoded(), hour, now), "a DER certificate");
        assertEquals(hour, CachingDataLoader.ttlFor(pki.pem(Entity.ROOT_CA).getBytes(StandardCharsets.US_ASCII), hour, now),
                "a PEM certificate");
        assertEquals(CachingDataLoader.UNPARSEABLE_TTL_MS, CachingDataLoader.ttlFor(
                "<html><body>Welcome to the hotel wifi</body></html>".getBytes(StandardCharsets.UTF_8), hour, now),
                "a captive portal's page is not a CRL: kept for seconds, not an hour");
        assertEquals(CachingDataLoader.UNPARSEABLE_TTL_MS, CachingDataLoader.ttlFor(new byte[0], hour, now));
        assertEquals(CachingDataLoader.UNPARSEABLE_TTL_MS, CachingDataLoader.ttlFor(new byte[] {0x30, (byte) 0x82}, hour, now),
                "a truncated DER header");
        assertEquals(50, CachingDataLoader.ttlFor("not a crl".getBytes(StandardCharsets.UTF_8), 50, now),
                "a TTL shorter than the unparseable bound wins");

        long tenSeconds = 10_000;
        byte[] soon = crlExpiringIn(tenSeconds);
        long ttl = CachingDataLoader.ttlFor(soon, hour, System.currentTimeMillis());
        assertTrue(ttl > 0 && ttl <= tenSeconds + 1_000, "a CRL is never kept past its nextUpdate (to the second): " + ttl);
        assertEquals(0, CachingDataLoader.ttlFor(crlExpiringIn(-tenSeconds), hour, System.currentTimeMillis()),
                "already stale: not reused");
    }

    @Test
    void aCrlIsFetchedAgainOnceItsNextUpdateHasPassed() throws Exception {
        FakeHttp http = new FakeHttp().route(CRL, crlExpiringIn(120));
        CachingDataLoader cache = new CachingDataLoader(http, 60_000);
        cache.get(CRL);
        cache.get(CRL);
        assertEquals(1, http.hits(CRL), "within nextUpdate: cached");
        Thread.sleep(200);
        cache.get(CRL);
        assertEquals(2, http.hits(CRL), "past nextUpdate: fetched again although the TTL has a minute left");
    }

    /** A syntactically valid CRL (parsing does not check its signature) whose nextUpdate is {@code ms} from now. */
    private static byte[] crlExpiringIn(long ms) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair kp = g.generateKeyPair();
        Date now = new Date();
        X509v2CRLBuilder b = new X509v2CRLBuilder(new X500Name("CN=Some CA"), now);
        b.setNextUpdate(new Date(now.getTime() + ms));
        b.addCRLEntry(BigInteger.ONE, now, 0);
        return b.build(new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate())).getEncoded();
    }
}
