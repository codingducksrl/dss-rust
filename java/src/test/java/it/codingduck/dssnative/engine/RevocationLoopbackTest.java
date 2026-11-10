/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import it.codingduck.dssnative.testsupport.FakeHttp;
import it.codingduck.dssnative.testsupport.Fixtures;
import it.codingduck.dssnative.testsupport.SyntheticTrustedLists;
import it.codingduck.dssnative.testsupport.TestEngines;
import it.codingduck.dssnative.testsupport.TestPki;
import it.codingduck.dssnative.testsupport.TestPki.Entity;
import it.codingduck.dssnative.testsupport.TestPki.Issued;
import it.codingduck.dssnative.testsupport.TestPki.Nonce;
import it.codingduck.dssnative.testsupport.TestPki.Pointers;
import it.codingduck.dssnative.testsupport.TestPki.Profile;

/**
 * Revocation and AIA through the engine's real outbound stack ({@link DssEngine#create}: DSS's CommonsDataLoader
 * and OCSPDataLoader behind the outbound policy and the CRL/AIA cache), against an OCSP responder, CRL
 * distribution points and CA-issuer URLs on 127.0.0.1, in the default {@code revocation: "online"} mode. No
 * external network. The rest of the suite injects an in-memory loader and has no OCSP at all; this class is what
 * covers {@code OnlineOCSPSource} (request, nonce, response parsing), CRL and AIA downloads over HTTP, and, in the
 * native test image, the reachability metadata of that path.
 *
 * <p>The chain: test root (on the synthetic IT trusted list) issues an intermediate CA that is in no list and in
 * no document, so validation must fetch it over AIA; the intermediate issues the signer, whose certificate names
 * the OCSP responder (answering for the intermediate) and the intermediate's CRL; the intermediate and a TSA
 * issued for this test name only the root's CRL.
 */
class RevocationLoopbackTest {

    @TempDir
    Path tmp;
    private TestEngines t;
    private HttpServer server;
    private String base;
    private Issued intermediate;
    private Issued signer;
    private Issued tsa;
    private final Map<String, AtomicInteger> hits = new ConcurrentHashMap<>();
    /** Serial number → revocation time, as the OCSP responder reports it. */
    private final Map<BigInteger, Instant> revokedOnOcsp = new ConcurrentHashMap<>();
    /** Serial number → revocation time, as the intermediate's CRL lists it. */
    private final Map<BigInteger, Instant> revokedOnCrl = new ConcurrentHashMap<>();
    private volatile Nonce ocspNonce = Nonce.ECHO;
    private volatile boolean ocspFailing;
    private volatile boolean ocspRequestHadNonce;
    private volatile String ocspContentType;
    private int engines;

    @BeforeEach
    void startServer() throws Exception {
        t = new TestEngines(tmp);
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        base = "http://127.0.0.1:" + server.getAddress().getPort();

        X509Certificate root = t.pki.x509(Entity.ROOT_CA);
        intermediate = TestPki.issueNow("CN=dss-native Test Intermediate CA,O=dss-native test PKI,C=IT", Profile.CA,
                root, t.pki.key(Entity.ROOT_CA), new Pointers(base + "/root-ca.crl", null, base + "/root-ca.cer"));
        signer = TestPki.issueNow("CN=Anna Verdi (TEST),GIVENNAME=Anna,SURNAME=Verdi,"
                        + "SERIALNUMBER=TINIT-TEST00000000003,O=dss-native test PKI,C=IT", Profile.SIGNER,
                intermediate.cert(), intermediate.key(),
                new Pointers(base + "/intermediate.crl", base + "/ocsp", base + "/intermediate.cer"));
        tsa = TestPki.issueNow("CN=dss-native Loopback TSA,O=dss-native test PKI,C=IT", Profile.TSA, root,
                t.pki.key(Entity.ROOT_CA), new Pointers(base + "/root-ca.crl", null, null));

        FakeHttp lists = new FakeHttp();
        new SyntheticTrustedLists(t.pki, 1).withBaseUrl(base).serveOn(lists);
        route("/root-ca.crl", body -> TestPki.crl(root, t.pki.key(Entity.ROOT_CA), Map.of()));
        route("/intermediate.crl", body -> TestPki.crl(intermediate.cert(), intermediate.key(), revokedOnCrl));
        route("/root-ca.cer", body -> encoded(root));
        route("/intermediate.cer", body -> encoded(intermediate.cert()));
        route("/ocsp", body -> {
            Extension nonce;
            try {
                nonce = new OCSPReq(body).getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
            ocspRequestHadNonce = nonce != null;
            if (ocspFailing) {
                return TestPki.ocspError(OCSPRespBuilder.INTERNAL_ERROR);
            }
            // As ArubaPEC's responders do: a nonce over 30 bytes is "unauthorized".
            if (nonce != null && ASN1OctetString.getInstance(nonce.getParsedValue()).getOctets().length > 30) {
                return TestPki.ocspError(OCSPRespBuilder.UNAUTHORIZED);
            }
            return TestPki.ocspResponse(body, intermediate.cert(), intermediate.key(), revokedOnOcsp, ocspNonce);
        });
        route("/tsa", body -> TestPki.timestampResponse(body, tsa.key(), List.of(tsa.cert(), root)));
        server.createContext("/", exchange -> {
            try (exchange) {
                String path = exchange.getRequestURI().getPath();
                hits.computeIfAbsent(path, k -> new AtomicInteger()).incrementAndGet();
                byte[] body;
                try {
                    body = lists.get(base + path);
                } catch (RuntimeException e) {
                    exchange.sendResponseHeaders(404, -1);
                    return;
                }
                reply(exchange, "application/xml", body);
            }
        });
        server.start();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    private void route(String path, Function<byte[], byte[]> handler) {
        server.createContext(path, exchange -> {
            try (exchange) {
                hits.computeIfAbsent(path, k -> new AtomicInteger()).incrementAndGet();
                if (path.equals("/ocsp")) {
                    ocspContentType = exchange.getRequestHeaders().getFirst("Content-Type");
                }
                reply(exchange, "application/octet-stream", handler.apply(exchange.getRequestBody().readAllBytes()));
            }
        });
    }

    private static void reply(HttpExchange exchange, String contentType, byte[] body) throws IOException {
        exchange.getResponseHeaders().add("Content-Type", contentType);
        exchange.sendResponseHeaders(200, body.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
        }
    }

    private int hits(String path) {
        AtomicInteger n = hits.get(path);
        return n == null ? 0 : n.get();
    }

    /** Built like the native library builds it (real loaders), trusted lists loaded from this server. */
    private DssEngine engine(String extra) {
        String config = "{\"lotl_url\":\"" + base + "/eu-lotl.xml\","
                + "\"oj_url\":\"" + SyntheticTrustedLists.OJ_URL + "\","
                + "\"oj_keystore\":{\"path\":\"" + t.ojKeystore.toString().replace("\\", "\\\\")
                + "\",\"password\":\"dss-password\"},"
                + "\"tsa\":{\"url\":\"" + base + "/tsa\"},"
                + (extra.isEmpty() ? "" : extra + ",")
                // The server is on 127.0.0.1, which the outbound policy refuses by default.
                + "\"http\":{\"block_private_addresses\":false}}";
        DssEngine engine = DssEngine.create(tmp.resolve("cache-" + (++engines)), EngineConfig.fromJson(config));
        TrustedListManager.RefreshRecord rec = engine.refreshTrustedListsOnline();
        assertEquals(3, rec.trustedCertificates(), Json.write(engine.trustedListStatus()));
        return engine;
    }

    /** A PAdES-BASELINE-B signature by {@link #signer}, carrying its certificate only (no chain). */
    private byte[] signedPdf(DssEngine engine) {
        SigningOptions o = SigningOptions.fromJson("{\"mode\":\"signature_value\",\"level\":\"B\","
                + "\"signing_certificate\":\"" + Base64.getEncoder().encodeToString(encoded(signer.cert())) + "\"}");
        byte[] pdf = Fixtures.read("content/document.pdf");
        PreparedSignature prepared = engine.prepareSignature(pdf, o);
        try {
            Signature ecdsa = Signature.getInstance("SHA256withECDSA");
            ecdsa.initSign(signer.key());
            ecdsa.update(prepared.dataToSign());
            return engine.completeSignature(pdf, o.withSigningTime(prepared.signingTime()), ecdsa.sign()).document();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] encoded(X509Certificate cert) {
        try {
            return cert.getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static ValidationResult.SignatureSummary validateOne(DssEngine engine, byte[] document) {
        ValidationResult r = engine.validate(document, ValidationOptions.DEFAULT);
        assertEquals(1, r.signatures.size());
        return r.signatures.get(0);
    }

    private static String verdict(ValidationResult.SignatureSummary s) {
        return FixtureValidationTest.verdict(s.indication(), s.subIndication());
    }

    @Test
    void ocspCrlAndAiaAreFetchedOverHttpAndEmbeddedByTheExtension() {
        try (DssEngine online = engine("");
             DssEngine offline = engine("\"revocation\":\"offline\",\"aia\":false")) {
            byte[] signed = signedPdf(online);

            ValidationResult.SignatureSummary s = validateOne(online, signed);
            assertEquals("TOTAL_PASSED/-", verdict(s), s.errors().toString());
            assertTrue(hits("/intermediate.cer") > 0, "the intermediate CA is only reachable over AIA");
            assertTrue(hits("/ocsp") > 0, "the signer's revocation comes from its OCSP responder");
            assertTrue(ocspRequestHadNonce, "the OCSP request carries a nonce");
            assertEquals("application/ocsp-request", ocspContentType);
            assertTrue(hits("/root-ca.crl") > 0, "the intermediate's revocation comes from the root's CRL");
            assertEquals(0, hits("/intermediate.crl"), "a good OCSP answer makes the signer's CRL unnecessary");

            // Without network access to revocation data or AIA, the B signature cannot be validated.
            assertNotEquals("TOTAL_PASSED/-", verdict(validateOne(offline, signed)));

            // B to LT: a timestamp from the TSA, then the OCSP response, the CRL and the intermediate CA embedded.
            ExtensionResult lt = online.extend(signed, new ExtensionOptions(ExtensionOptions.Level.LT, null));
            assertTrue(hits("/tsa") > 0);
            ValidationResult.SignatureSummary embedded = validateOne(offline, lt.document());
            assertEquals("TOTAL_PASSED/-", verdict(embedded), embedded.errors().toString());
            assertEquals("PAdES-BASELINE-LT", embedded.format().toString());
        }
    }

    @Test
    void aSignerRevokedOnOcspIsReportedRevoked() {
        revokedOnOcsp.put(signer.cert().getSerialNumber(), Instant.now().minus(1, ChronoUnit.HOURS));
        try (DssEngine online = engine("")) {
            ValidationResult.SignatureSummary s = validateOne(online, signedPdf(online));
            assertTrue(hits("/ocsp") > 0);
            assertNotEquals("TOTAL_PASSED", s.indication().name());
            assertTrue(String.valueOf(s.subIndication()).startsWith("REVOKED"), verdict(s));
        }
    }

    @Test
    void anOcspAnswerWithAnotherNonceIsRefusedAndTheCrlDecides() {
        // A "good" answer that is not bound to the request (a replay) must not hide a revocation on the CRL.
        ocspNonce = Nonce.WRONG;
        revokedOnCrl.put(signer.cert().getSerialNumber(), Instant.now().minus(1, ChronoUnit.HOURS));
        try (DssEngine online = engine("")) {
            ValidationResult.SignatureSummary s = validateOne(online, signedPdf(online));
            assertTrue(hits("/ocsp") > 0);
            assertTrue(hits("/intermediate.crl") > 0, "the CRL is the fallback");
            assertTrue(String.valueOf(s.subIndication()).startsWith("REVOKED"), verdict(s));
        }
    }

    @Test
    void anOcspAnswerWithoutANonceIsAccepted() {
        // Many responders ignore the request's nonce. The engine only warns (DSS's alertOnNonexistentNonce): the
        // answer is used, so the CRL, which would report the signer revoked, is not consulted.
        ocspNonce = Nonce.OMIT;
        revokedOnCrl.put(signer.cert().getSerialNumber(), Instant.now().minus(1, ChronoUnit.HOURS));
        try (DssEngine online = engine("")) {
            ValidationResult.SignatureSummary s = validateOne(online, signedPdf(online));
            assertTrue(hits("/ocsp") > 0);
            assertTrue(ocspRequestHadNonce, "the request carried a nonce the answer left out");
            assertEquals(0, hits("/intermediate.crl"), "the nonce-less OCSP answer was used");
            assertEquals("TOTAL_PASSED/-", verdict(s), s.errors().toString());
        }
    }

    @Test
    void anOcspResponderErrorFallsBackToTheCrl() {
        ocspFailing = true;
        try (DssEngine online = engine("")) {
            ValidationResult.SignatureSummary s = validateOne(online, signedPdf(online));
            assertTrue(hits("/ocsp") > 0);
            assertTrue(hits("/intermediate.crl") > 0, "the CRL is the fallback");
            assertEquals("TOTAL_PASSED/-", verdict(s), s.errors().toString());
        }
    }

    @Test
    void revocationOfflineMakesNoRequest() {
        try (DssEngine online = engine("");
             DssEngine offline = engine("\"revocation\":\"offline\",\"aia\":false")) {
            byte[] signed = signedPdf(online);
            hits.clear();
            validateOne(offline, signed);
            assertEquals(Map.of(), Map.copyOf(hits), "no CRL, OCSP or AIA request");
        }
    }
}
