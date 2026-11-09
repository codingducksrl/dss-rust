/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.sun.net.httpserver.HttpServer;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;

import it.codingduck.dssnative.testsupport.Signing;
import it.codingduck.dssnative.testsupport.TestEngines;
import it.codingduck.dssnative.testsupport.TestPki;
import it.codingduck.dssnative.testsupport.TestPki.Entity;

/**
 * A signature policy named by the document is never fetched (its URL is the signer's choice): DSS reports the
 * policy as present but not identified, with its "not available" message, and the URL sees no request even
 * though it would answer with the right document.
 */
class SignaturePolicyTest {

    private static final String POLICY_URL = "http://policy.dss-native.test/policy.der";
    private static final String POLICY_OID = "1.3.6.1.4.1.99999.2.1";
    private static final byte[] POLICY_DOCUMENT = "dss-native test signature policy".getBytes(StandardCharsets.US_ASCII);

    @TempDir
    Path tmp;

    @Test
    void theDocumentsPolicyUrlIsNeverFetched() {
        TestEngines t = new TestEngines(tmp);
        t.http.route(POLICY_URL, POLICY_DOCUMENT); // what a fetch would get: the genuine policy, digest matching
        byte[] cades = signWithPolicy(t.pki, POLICY_URL);
        try (DssEngine engine = t.onlineLoaded(tmp.resolve("cache"), null)) {
            ValidationResult r = engine.validate(cades, ValidationOptions.DEFAULT);
            assertEquals(0, t.http.hits(POLICY_URL), "the policy URL must not be contacted");
            assertEquals(1, r.signatures.size());
            ValidationResult.SignatureSummary s = r.signatures.get(0);
            Map<String, Object> policy = s.policy();
            assertNotNull(policy, "the signature claims a policy");
            assertTrue(String.valueOf(policy.get("id")).contains(POLICY_OID), policy.toString());
            assertEquals(POLICY_URL, policy.get("url"));
            assertEquals(Boolean.FALSE, policy.get("identified"));
            assertNull(policy.get("digest_valid"));
            assertTrue(s.info().contains("The signature policy is not available!"), s.info().toString());
            assertEquals("TOTAL_PASSED", s.indication().name(), s.errors().toString());
        }
    }

    /**
     * The same with the policy on a real HTTP server on 127.0.0.1: catches a provider given any loader of its own
     * (a fresh CommonsDataLoader, DSS's default), which the in-memory loader above would not see.
     */
    @Test
    void noLoaderFetchesThePolicyUrl() throws IOException {
        AtomicInteger hits = new AtomicInteger();
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/policy.der", exchange -> {
            try (exchange) {
                hits.incrementAndGet();
                exchange.sendResponseHeaders(200, POLICY_DOCUMENT.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(POLICY_DOCUMENT);
                }
            }
        });
        server.start();
        try {
            String url = "http://127.0.0.1:" + server.getAddress().getPort() + "/policy.der";
            TestEngines t = new TestEngines(tmp);
            byte[] cades = signWithPolicy(t.pki, url);
            try (DssEngine engine = t.onlineLoaded(tmp.resolve("cache"), null)) {
                ValidationResult r = engine.validate(cades, ValidationOptions.DEFAULT);
                assertEquals(0, hits.get(), "the policy URL must not be contacted");
                ValidationResult.SignatureSummary s = r.signatures.get(0);
                assertEquals(url, s.policy().get("url"));
                assertEquals(Boolean.FALSE, s.policy().get("identified"));
                assertEquals("TOTAL_PASSED", s.indication().name(), s.errors().toString());
            }
        } finally {
            server.stop(0);
        }
    }

    private static byte[] signWithPolicy(TestPki pki, String url) {
        Policy policy = new Policy();
        policy.setId(POLICY_OID);
        policy.setDigestAlgorithm(DigestAlgorithm.SHA256);
        policy.setDigestValue(DSSUtils.digest(DigestAlgorithm.SHA256, POLICY_DOCUMENT));
        policy.setSpuri(url);

        CAdESSignatureParameters p = new CAdESSignatureParameters();
        p.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        p.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        p.setDigestAlgorithm(DigestAlgorithm.SHA256);
        p.setSigningCertificate(pki.token(Entity.SIGNER_RSA));
        p.setCertificateChain(pki.chain(Entity.SIGNER_RSA));
        p.bLevel().setSigningDate(new Date());
        p.bLevel().setSignaturePolicy(policy);
        DSSDocument content = new InMemoryDocument("signed under a policy".getBytes(StandardCharsets.US_ASCII), "content");
        CAdESService service = new CAdESService(new CommonCertificateVerifier());
        ToBeSigned tbs = service.getDataToSign(content, p);
        return DSSUtils.toByteArray(service.signDocument(content, p,
                Signing.sign(tbs, p.getDigestAlgorithm(), pki.key(Entity.SIGNER_RSA))));
    }
}
