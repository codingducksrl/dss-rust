/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;

/** The outbound-fetch policy in front of an in-memory loader: what it refuses, what it lets through. */
class OutboundFetchPolicyTest {

    /** Records calls and answers a fixed body, optionally slowly; URLs in {@link #redirects} answer a redirect. */
    static final class Recording implements DataLoader {
        private static final long serialVersionUID = 1L;
        final List<String> calls = new CopyOnWriteArrayList<>();
        /** URL -> "status location": the client stopped at a redirect there (as the handler installed by wrap signals it). */
        final Map<String, String> redirects = new java.util.concurrent.ConcurrentHashMap<>();
        byte[] body = "ok".getBytes();
        long delayMs;

        @Override
        public byte[] get(String url) {
            calls.add("GET " + url);
            sleep();
            redirect(url);
            return body;
        }

        @Override
        public DataAndUrl get(List<String> urls) {
            calls.add("GET " + urls);
            sleep();
            return new DataAndUrl(urls.get(0), body);
        }

        @Override
        public byte[] post(String url, byte[] content) {
            calls.add("POST " + url);
            sleep();
            redirect(url);
            return body;
        }

        private void redirect(String url) {
            String r = redirects.get(url);
            if (r != null) {
                int space = r.indexOf(' ');
                OutboundFetchPolicy.Redirect cause = new OutboundFetchPolicy.Redirect(
                        Integer.parseInt(r.substring(0, space)), r.substring(space + 1));
                // As CommonsDataLoader wraps a handler's IOException.
                throw new DSSExternalResourceException("Unable to process GET call for url [" + url + "]", cause);
            }
        }

        @Override
        public void setContentType(String contentType) {
            calls.add("TYPE " + contentType);
        }

        private void sleep() {
            try {
                Thread.sleep(delayMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static final Map<String, String> DNS = Map.of(
            "public.example.test", "93.184.216.34",
            "metadata.example.test", "169.254.169.254",
            "intranet.example.test", "10.1.2.3",
            "v6private.example.test", "fd00::1");

    private static final OutboundFetchPolicy.Resolver RESOLVER = host -> {
        String ip = DNS.get(host);
        if (ip == null) {
            throw new UnknownHostException(host);
        }
        return List.of(InetAddress.getByName(ip));
    };

    private final Recording delegate = new Recording();

    private OutboundFetchPolicy policy(OutboundFetchPolicy.Settings settings) {
        return new OutboundFetchPolicy(delegate, settings, RESOLVER);
    }

    private OutboundFetchPolicy defaults() {
        return policy(new OutboundFetchPolicy.Settings(List.of("http", "https"), true, 1024, 0));
    }

    private static String refused(OutboundFetchPolicy p, String url) {
        DSSExternalResourceException e = assertThrows(DSSExternalResourceException.class, () -> p.get(url), url);
        assertTrue(e.getMessage().contains("refused by policy"), e.getMessage());
        return e.getMessage();
    }

    @Test
    void schemesOutsideTheAllowListAreRefused() {
        OutboundFetchPolicy p = defaults();
        assertTrue(refused(p, "ldap://ldap.example.test/cn=crl").contains("scheme 'ldap'"));
        refused(p, "ftp://ftp.example.test/crl.der");
        refused(p, "file:///etc/passwd");
        refused(p, "not a url at all");
        assertTrue(delegate.calls.isEmpty(), "nothing reached the client: " + delegate.calls);

        OutboundFetchPolicy withLdap = policy(new OutboundFetchPolicy.Settings(List.of("http", "https", "ldap"), true, 1024, 0));
        withLdap.get("ldap://ldap.example.test/cn=crl");
        assertEquals(List.of("GET ldap://ldap.example.test/cn=crl"), delegate.calls);
    }

    @Test
    void privateLiteralAddressesAreRefused() {
        OutboundFetchPolicy p = defaults();
        for (String url : List.of("http://127.0.0.1/crl", "http://localhost:8080/ocsp", "http://foo.localhost/x",
                "http://10.0.0.1/", "http://172.16.5.5/", "http://192.168.1.1/", "http://169.254.169.254/latest/meta-data",
                "http://100.64.0.1/", "http://0.0.0.0/", "http://[::1]/", "http://[fe80::1]/", "http://[fc00::1]/",
                "http://224.0.0.1/", "http://user:pw@93.184.216.34/")) {
            refused(p, url);
        }
        assertTrue(delegate.calls.isEmpty(), delegate.calls.toString());
        p.get("http://93.184.216.34/crl");
        assertEquals(1, delegate.calls.size());
    }

    @Test
    void namesAreResolvedBeforeTheyAreAllowed() {
        OutboundFetchPolicy p = defaults();
        assertTrue(refused(p, "http://metadata.example.test/latest/meta-data").contains("link-local"));
        assertTrue(refused(p, "https://intranet.example.test/ocsp").contains("private"));
        assertTrue(refused(p, "https://v6private.example.test/").contains("unique-local"));
        assertTrue(delegate.calls.isEmpty(), delegate.calls.toString());
        p.get("https://public.example.test/crl");
        // A name that does not resolve is let through: the client fails on it with its own error.
        p.get("https://nowhere.example.test/crl");
        assertEquals(2, delegate.calls.size());
    }

    @Test
    void privateAddressBlockingCanBeTurnedOff() {
        OutboundFetchPolicy p = policy(new OutboundFetchPolicy.Settings(List.of("http", "https"), false, 1024, 0));
        p.get("http://127.0.0.1/crl");
        p.get("http://intranet.example.test/ocsp");
        assertEquals(2, delegate.calls.size());
        refused(p, "ldap://127.0.0.1/"); // the scheme list still applies
    }

    @Test
    void oversizedResponsesFail() {
        OutboundFetchPolicy p = policy(new OutboundFetchPolicy.Settings(List.of("http"), false, 10, 0));
        delegate.body = new byte[11];
        DSSExternalResourceException e = assertThrows(DSSExternalResourceException.class,
                () -> p.get("http://public.example.test/big"));
        assertTrue(e.getMessage().contains("max_response_bytes"), e.getMessage());
        delegate.body = new byte[10];
        assertArrayEquals(new byte[10], p.get("http://public.example.test/ok"));
        assertArrayEquals(new byte[10], p.post("http://public.example.test/ocsp", new byte[] {1}));
    }

    @Test
    void deadlineBoundsTheWholeRequest() {
        OutboundFetchPolicy p = policy(new OutboundFetchPolicy.Settings(List.of("http"), false, 1024, 200));
        delegate.delayMs = 3_000;
        long start = System.nanoTime();
        DSSExternalResourceException e = assertThrows(DSSExternalResourceException.class,
                () -> p.get("http://public.example.test/slow"));
        long ms = (System.nanoTime() - start) / 1_000_000;
        assertTrue(e.getMessage().contains("deadline"), e.getMessage());
        assertTrue(ms < 2_000, "returned after " + ms + " ms");
        delegate.delayMs = 0;
        assertArrayEquals("ok".getBytes(), p.get("http://public.example.test/fast"));
    }

    @Test
    void multiUrlGetDropsRefusedUrlsOnly() {
        OutboundFetchPolicy p = defaults();
        DataLoader.DataAndUrl r = p.get(List.of("http://127.0.0.1/crl", "http://public.example.test/crl"));
        assertEquals("http://public.example.test/crl", r.getUrlString());
        assertEquals(List.of("GET http://public.example.test/crl"), delegate.calls);
        assertThrows(DSSExternalResourceException.class, () -> p.get(List.of("http://10.0.0.1/a", "ldap://x/b")));
        assertThrows(DSSExternalResourceException.class, () -> p.get(new ArrayList<>()));

        // The first URL that answers wins, as in DSS's clients; a redirect on the way is followed under the policy.
        delegate.calls.clear();
        delegate.redirects.put("http://public.example.test/a", "302 http://metadata.example.test/a");
        delegate.redirects.put("http://public.example.test/b", "301 /moved/b");
        r = p.get(List.of("http://public.example.test/a", "http://public.example.test/b"));
        assertEquals("http://public.example.test/b", r.getUrlString());
        assertEquals(List.of("GET http://public.example.test/a", "GET http://public.example.test/b",
                "GET http://public.example.test/moved/b"), delegate.calls);
    }

    /** A redirect is a new URL: the policy sees it and checks it like the first one. */
    @Test
    void redirectsAreFollowedOnlyWhereThePolicyAllows() {
        OutboundFetchPolicy p = defaults();
        delegate.redirects.put("http://public.example.test/crl", "302 http://169.254.169.254/latest/meta-data");
        DSSExternalResourceException e = assertThrows(DSSExternalResourceException.class,
                () -> p.get("http://public.example.test/crl"));
        assertTrue(e.getMessage().contains("redirect from http://public.example.test/crl refused"), e.getMessage());
        assertTrue(e.getMessage().contains("link-local"), e.getMessage());
        assertEquals(List.of("GET http://public.example.test/crl"), delegate.calls, "the private target was never fetched");

        delegate.calls.clear();
        delegate.redirects.put("http://public.example.test/crl", "301 https://intranet.example.test/crl");
        assertTrue(refusedMessage(p, "http://public.example.test/crl").contains("private"));
        delegate.redirects.put("http://public.example.test/crl", "302 ldap://ldap.example.test/cn=crl");
        assertTrue(refusedMessage(p, "http://public.example.test/crl").contains("scheme 'ldap'"));
        delegate.redirects.put("http://public.example.test/crl", "302 http://user:pw@public.example.test/crl");
        assertTrue(refusedMessage(p, "http://public.example.test/crl").contains("credentials"));
        delegate.redirects.put("http://public.example.test/crl", "302 http://[::1/crl");
        assertTrue(refusedMessage(p, "http://public.example.test/crl").contains("not a valid URL"));
        assertEquals(4, delegate.calls.size(), delegate.calls.toString());

        // Allowed targets are followed, relative ones resolved against the redirecting URL, across several hops.
        delegate.calls.clear();
        delegate.redirects.put("http://public.example.test/crl", "301 https://public.example.test/x/crl");
        delegate.redirects.put("https://public.example.test/x/crl", "307 ../moved/crl");
        assertArrayEquals("ok".getBytes(), p.get("http://public.example.test/crl"));
        assertEquals(List.of("GET http://public.example.test/crl", "GET https://public.example.test/x/crl",
                "GET https://public.example.test/moved/crl"), delegate.calls);
    }

    @Test
    void redirectLoopsAndPostRedirectsAreBounded() {
        OutboundFetchPolicy p = defaults();
        delegate.redirects.put("http://public.example.test/loop", "302 http://public.example.test/loop");
        DSSExternalResourceException e = assertThrows(DSSExternalResourceException.class,
                () -> p.get("http://public.example.test/loop"));
        assertTrue(e.getMessage().contains("more than " + OutboundFetchPolicy.MAX_REDIRECTS), e.getMessage());
        assertEquals(OutboundFetchPolicy.MAX_REDIRECTS + 1, delegate.calls.size());

        // A POST (OCSP, TSA) follows only the redirects that keep the method and body.
        delegate.calls.clear();
        delegate.redirects.put("http://public.example.test/ocsp", "302 http://public.example.test/ocsp2");
        e = assertThrows(DSSExternalResourceException.class, () -> p.post("http://public.example.test/ocsp", new byte[] {1}));
        assertTrue(e.getMessage().contains("POST") && e.getMessage().contains("302"), e.getMessage());
        assertEquals(List.of("POST http://public.example.test/ocsp"), delegate.calls);
        delegate.redirects.put("http://public.example.test/ocsp", "307 http://public.example.test/ocsp2");
        assertArrayEquals("ok".getBytes(), p.post("http://public.example.test/ocsp", new byte[] {1}));
        assertEquals(List.of("POST http://public.example.test/ocsp", "POST http://public.example.test/ocsp",
                "POST http://public.example.test/ocsp2"), delegate.calls);
        delegate.redirects.put("http://public.example.test/ocsp", "308 http://10.0.0.9/ocsp");
        assertTrue(refusedMessage(p, "http://public.example.test/ocsp").contains("private"));
    }

    /** Redirects on the deadline pool count against the same deadline as the first request. */
    @Test
    void redirectsShareTheDeadline() {
        OutboundFetchPolicy p = policy(new OutboundFetchPolicy.Settings(List.of("http"), false, 1024, 500));
        delegate.delayMs = 200;
        delegate.redirects.put("http://public.example.test/a", "302 http://public.example.test/b");
        delegate.redirects.put("http://public.example.test/b", "302 http://public.example.test/c");
        delegate.redirects.put("http://public.example.test/c", "302 http://public.example.test/d");
        DSSExternalResourceException e = assertThrows(DSSExternalResourceException.class,
                () -> p.get("http://public.example.test/a"));
        assertTrue(e.getMessage().contains("deadline"), e.getMessage());
    }

    /** DSS's Apache client is told to stop at redirects and hand them to the policy; any other delegate is left alone. */
    @Test
    void apacheClientsLeaveRedirectsToThePolicy() {
        eu.europa.esig.dss.service.http.commons.CommonsDataLoader client =
                new eu.europa.esig.dss.service.http.commons.CommonsDataLoader();
        assertTrue(client.isRedirectsEnabled(), "DSS's default");
        OutboundFetchPolicy p = new OutboundFetchPolicy(client, new OutboundFetchPolicy.Settings(List.of("http", "https"), true, 1024, 0), RESOLVER);
        assertFalse(client.isRedirectsEnabled());
        assertTrue(client.getHttpClientResponseHandler() instanceof OutboundFetchPolicy.RedirectInterceptingHandler);
        new OutboundFetchPolicy(client, p.settings(), RESOLVER); // wrapping twice does not stack handlers
        assertTrue(client.getHttpClientResponseHandler() instanceof OutboundFetchPolicy.RedirectInterceptingHandler);

        eu.europa.esig.dss.service.http.commons.CommonsDataLoader noRedirects =
                new eu.europa.esig.dss.service.http.commons.CommonsDataLoader();
        noRedirects.setRedirectsEnabled(false); // http.follow_redirects=false: the client fails on a 3xx itself
        Object handler = noRedirects.getHttpClientResponseHandler();
        new OutboundFetchPolicy(noRedirects, p.settings(), RESOLVER);
        assertSame(handler, noRedirects.getHttpClientResponseHandler());
    }

    @Test
    void redirectInterceptingHandlerStopsAtRedirectsWithALocation() throws Exception {
        OutboundFetchPolicy.RedirectInterceptingHandler h = new OutboundFetchPolicy.RedirectInterceptingHandler(
                response -> "handled".getBytes());
        org.apache.hc.core5.http.message.BasicClassicHttpResponse moved =
                new org.apache.hc.core5.http.message.BasicClassicHttpResponse(302);
        moved.addHeader("Location", " http://169.254.169.254/ ");
        OutboundFetchPolicy.Redirect r = assertThrows(OutboundFetchPolicy.Redirect.class, () -> h.handleResponse(moved));
        assertEquals(302, r.status());
        assertEquals("http://169.254.169.254/", r.location());
        // Without a Location, or not a redirect: the loader's own handler decides.
        assertArrayEquals("handled".getBytes(), h.handleResponse(new org.apache.hc.core5.http.message.BasicClassicHttpResponse(302)));
        org.apache.hc.core5.http.message.BasicClassicHttpResponse ok = new org.apache.hc.core5.http.message.BasicClassicHttpResponse(200);
        ok.addHeader("Location", "http://169.254.169.254/");
        assertArrayEquals("handled".getBytes(), h.handleResponse(ok));
    }

    private String refusedMessage(OutboundFetchPolicy p, String url) {
        DSSExternalResourceException e = assertThrows(DSSExternalResourceException.class, () -> {
            if (url.endsWith("/ocsp")) {
                p.post(url, new byte[] {1});
            } else {
                p.get(url);
            }
        });
        assertTrue(e.getMessage().contains("refused"), e.getMessage());
        return e.getMessage();
    }

    @Test
    void settingsComeFromTheEngineConfig() {
        assertNull(OutboundFetchPolicy.privateReason(addr("93.184.216.34")));
        assertEquals("loopback", OutboundFetchPolicy.privateReason(addr("127.0.0.1")));
        assertEquals("carrier-grade NAT", OutboundFetchPolicy.privateReason(addr("100.127.255.255")));
        assertEquals("link-local", OutboundFetchPolicy.privateReason(addr("169.254.0.1")));
        OutboundFetchPolicy.Settings s = new OutboundFetchPolicy.Settings(List.of("HTTP"), true, 5, 7);
        assertEquals(List.of("http"), s.allowedSchemes());
        assertThrows(IllegalArgumentException.class, () -> new OutboundFetchPolicy.Settings(List.of(), true, 5, 7));
        assertThrows(IllegalArgumentException.class, () -> new OutboundFetchPolicy.Settings(List.of("http"), true, 0, 7));
        assertThrows(IllegalArgumentException.class, () -> new OutboundFetchPolicy.Settings(List.of("http"), true, 5, -1));
    }

    private static InetAddress addr(String literal) {
        try {
            return InetAddress.getByName(literal);
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }
}
