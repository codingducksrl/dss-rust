/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import it.codingduck.dssnative.testsupport.FakeHttp;
import it.codingduck.dssnative.testsupport.Fixtures;
import it.codingduck.dssnative.testsupport.SyntheticTrustedLists;
import it.codingduck.dssnative.testsupport.TestEngines;
import it.codingduck.dssnative.testsupport.TestPki;

/**
 * The real HTTP stack (DSS's CommonsDataLoader, Apache HttpClient, JSSE) against an HTTPS server on 127.0.0.1
 * whose certificate is issued by the synthetic test root. No external network. Covers TLS server verification
 * for trusted-list downloads, the {@code http.trust_store} override, redirects, a TSA behind HTTP Basic auth,
 * and, in the native test image, the reachability metadata of that stack, which the in-memory loader used
 * elsewhere never touches.
 */
class HttpsLoopbackTest {

    @TempDir
    Path tmp;
    private HttpsServer server;
    private String base;
    private TestEngines t;
    private Path rootTrustStore;
    private final AtomicInteger tsaGranted = new AtomicInteger();
    private final AtomicInteger tsaUnauthorized = new AtomicInteger();
    private volatile String tsaContentType;
    /** When set, /DE.xml answers a 302 to this URL. */
    private volatile String deRedirect;

    @BeforeEach
    void startServer() throws Exception {
        t = new TestEngines(tmp);
        rootTrustStore = t.pki.writeRootTrustStore(tmp.resolve("root-truststore.p12"));

        server = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        KeyStore keyStore = t.pki.tlsServerKeyStore();
        kmf.init(keyStore, TestPki.PASSWORD);
        SSLContext ssl = SSLContext.getInstance("TLS");
        ssl.init(kmf.getKeyManagers(), null, null);
        server.setHttpsConfigurator(new HttpsConfigurator(ssl));
        base = "https://127.0.0.1:" + server.getAddress().getPort();

        // The synthetic lists, published under this server; /IT.xml redirects to show redirects are followed.
        FakeHttp content = new FakeHttp();
        new SyntheticTrustedLists(t.pki, 1).withBaseUrl(base).serveOn(content);
        content.route(base + "/it-moved.xml", content.get(base + "/IT.xml"));
        server.createContext("/", exchange -> serve(exchange, content));
        server.createContext("/tsa", this::serveTsa);
        server.start();
    }

    /** An RFC 3161 TSA that wants HTTP Basic credentials tsa-user / tsa-secret. */
    private void serveTsa(HttpExchange exchange) throws IOException {
        try (exchange) {
            String expected = "Basic " + Base64.getEncoder().encodeToString(
                    "tsa-user:tsa-secret".getBytes(StandardCharsets.UTF_8));
            if (!expected.equals(exchange.getRequestHeaders().getFirst("Authorization"))) {
                tsaUnauthorized.incrementAndGet();
                exchange.getResponseHeaders().add("WWW-Authenticate", "Basic realm=\"tsa\"");
                exchange.sendResponseHeaders(401, -1);
                return;
            }
            tsaContentType = exchange.getRequestHeaders().getFirst("Content-Type");
            byte[] body = t.pki.timestampResponse(exchange.getRequestBody().readAllBytes());
            tsaGranted.incrementAndGet();
            exchange.getResponseHeaders().add("Content-Type", "application/timestamp-reply");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        }
    }

    private void serve(HttpExchange exchange, FakeHttp content) throws IOException {
        try (exchange) {
            String path = exchange.getRequestURI().getPath();
            if (path.equals("/IT.xml")) {
                exchange.getResponseHeaders().add("Location", base + "/it-moved.xml");
                exchange.sendResponseHeaders(302, -1);
                return;
            }
            if (path.equals("/DE.xml") && deRedirect != null) {
                exchange.getResponseHeaders().add("Location", deRedirect);
                exchange.sendResponseHeaders(302, -1);
                return;
            }
            byte[] body;
            try {
                body = content.get(base + path);
            } catch (RuntimeException e) {
                exchange.sendResponseHeaders(404, -1);
                return;
            }
            exchange.getResponseHeaders().add("Content-Type", "application/xml");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        }
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    private DssEngine engine(String http) {
        return engine(http, null);
    }

    private DssEngine engine(String http, String tsa) {
        return engine(http, tsa, tmp.resolve("cache"));
    }

    private DssEngine engine(String http, String tsa, Path cache) {
        String config = "{\"lotl_url\":\"" + base + "/eu-lotl.xml\","
                + "\"oj_url\":\"" + SyntheticTrustedLists.OJ_URL + "\","
                + "\"oj_keystore\":{\"path\":\"" + json(t.ojKeystore) + "\",\"password\":\"dss-password\"},"
                + "\"revocation\":\"offline\",\"aia\":false,"
                + (tsa == null ? "" : "\"tsa\":" + tsa + ",")
                // The server is on 127.0.0.1, which the outbound policy refuses by default.
                + "\"http\":{\"block_private_addresses\":false" + (http.isEmpty() ? "" : "," + http) + "}}";
        return DssEngine.create(cache, EngineConfig.fromJson(config));
    }

    @Test
    void extensionToLtaUsesAnAuthenticatedHttpsTsa() {
        String trustStore = "\"trust_store\":{\"path\":\"" + json(rootTrustStore) + "\",\"password\":\"changeit\"}";
        String tsa = "{\"url\":\"" + base + "/tsa\",\"username\":\"tsa-user\",\"password\":\"";
        ExtensionOptions lta = new ExtensionOptions(ExtensionOptions.Level.LTA, null);
        try (DssEngine engine = engine(trustStore, tsa + "tsa-secret\"}")) {
            engine.refreshTrustedListsOnline();
            ExtensionResult r = engine.extend(Fixtures.read("pades/b-lt.pdf"), lta);
            assertEquals(1, tsaGranted.get());
            assertEquals(0, tsaUnauthorized.get(), "credentials are sent with the first request");
            assertEquals("application/timestamp-query", tsaContentType);
            ValidationResult v = engine.validate(r.document(), ValidationOptions.DEFAULT);
            assertEquals("TOTAL_PASSED/-", FixtureValidationTest.verdicts(v).get(0));
            assertEquals("PAdES-BASELINE-LTA", v.signatures.get(0).format().toString());
        }
        try (DssEngine engine = engine(trustStore, tsa + "wrong\"}")) {
            engine.refreshTrustedListsOnline();
            DssError e = assertThrows(DssError.class, () -> engine.extend(Fixtures.read("pades/b-lt.pdf"), lta));
            assertEquals(DssError.Code.TSA_FAILED, e.code(), e.getMessage());
            assertTrue(e.getMessage().contains("401"), e.getMessage());
            assertTrue(tsaUnauthorized.get() > 0);
        }
    }

    @Test
    void verifiedTlsWithTrustStoreOverrideLoadsTheLists() {
        try (DssEngine engine = engine("\"tl_verify_tls\":true,\"trust_store\":{\"path\":\"" + json(rootTrustStore)
                + "\",\"password\":\"changeit\"}")) {
            TrustedListManager.RefreshRecord rec = engine.refreshTrustedListsOnline();
            assertTrue(rec.completed());
            assertEquals(3, rec.trustedCertificates(), Json.write(engine.trustedListStatus()));
            assertEquals("TOTAL_PASSED/-", FixtureValidationTest.verdicts(
                    engine.validate(Fixtures.read("pades/b-lta.pdf"), ValidationOptions.DEFAULT)).get(0));
        }
    }

    /**
     * Redirects go through the real Apache client, which is told to stop at them so that the outbound policy
     * can check each target: /IT.xml's redirect (same scheme) is followed, one to a scheme outside
     * {@code allowed_schemes} is not, and {@code follow_redirects: false} follows none.
     */
    @Test
    void redirectsAreCheckedByTheOutboundPolicy() {
        deRedirect = "http://127.0.0.1:1/de-moved.xml"; // never contacted: the scheme is refused first
        try (DssEngine engine = engine("\"allowed_schemes\":[\"https\"]")) {
            TrustedListManager.RefreshRecord rec = engine.refreshTrustedListsOnline();
            assertTrue(rec.completed());
            assertEquals(2, rec.trustedCertificates(), "IT (through its redirect) loads, DE does not");
            Map<String, Object> status = engine.trustedListStatus();
            Map<String, Object> de = TrustedListTest.byUrl(status, base + "/DE.xml");
            String error = String.valueOf(TrustedListTest.map(de, "download").get("error"));
            assertTrue(error.contains("redirect from " + base + "/DE.xml refused"), error);
            assertTrue(error.contains("scheme 'http'"), error);
            assertEquals("TOTAL_PASSED", TrustedListTest.map(TrustedListTest.byUrl(status, base + "/IT.xml"), "validation")
                    .get("indication"));
        }
        deRedirect = null;
        try (DssEngine engine = engine("\"follow_redirects\":false", null, tmp.resolve("cache-no-redirects"))) {
            TrustedListManager.RefreshRecord rec = engine.refreshTrustedListsOnline();
            assertTrue(rec.completed());
            assertEquals(1, rec.trustedCertificates(), "only DE: IT sits behind a redirect");
            String error = String.valueOf(TrustedListTest.map(TrustedListTest.byUrl(engine.trustedListStatus(),
                    base + "/IT.xml"), "download").get("error"));
            assertTrue(error.contains("302"), error);
        }
    }

    @Test
    void builtInCaBundleRejectsAnUnknownServerCa() {
        try (DssEngine engine = engine("\"tl_verify_tls\":true")) {
            engine.refreshTrustedListsOnline();
            Map<String, Object> status = engine.trustedListStatus();
            assertEquals(Boolean.FALSE, status.get("loaded"));
            Object error = TrustedListTest.map(TrustedListTest.list(status, "lotls").get(0), "download").get("error");
            assertTrue(String.valueOf(error).contains("PKIX"), String.valueOf(error));
        }
    }

    @Test
    void trustedListDownloadsSkipTlsVerificationByDefault() {
        // tl_verify_tls defaults to false: list integrity comes from the XML signatures (see docs/DECISIONS.md).
        try (DssEngine engine = engine("")) {
            assertEquals(3, engine.refreshTrustedListsOnline().trustedCertificates());
            List<Map<String, Object>> tls = TrustedListTest.list(engine.trustedListStatus(), "tls");
            tls.forEach(tl -> assertEquals("TOTAL_PASSED", TrustedListTest.map(tl, "validation").get("indication")));
        }
    }

    private static String json(Path p) {
        return p.toString().replace("\\", "\\\\");
    }
}
