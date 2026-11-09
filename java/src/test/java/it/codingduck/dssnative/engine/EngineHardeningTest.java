/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.encryption.AccessPermission;
import org.apache.pdfbox.pdmodel.encryption.StandardProtectionPolicy;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionJavaScript;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationLink;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;

import it.codingduck.dssnative.testsupport.ExternalSigner;
import it.codingduck.dssnative.testsupport.ExternalSigner.Cms;
import it.codingduck.dssnative.testsupport.FakeHttp;
import it.codingduck.dssnative.testsupport.Fixtures;
import it.codingduck.dssnative.testsupport.TestEngines;
import it.codingduck.dssnative.testsupport.TestPki;
import it.codingduck.dssnative.testsupport.TestPki.Entity;

/**
 * The engine's defences and the richer result shape: outbound loaders behind the fetch policy, structural limits
 * and encrypted PDFs refused up front, tokens from the TSA checked before they are embedded, mixed-level
 * augmentation, the offline pre-check before a timestamp is spent, PDFs inside CAdES envelopes, and the
 * per-signature fields ({@code all_passed}, trust anchor, split errors, timestamps, changes after signing).
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EngineHardeningTest {

    private static final String PASSED = "TOTAL_PASSED/-";

    private Path tmp;
    private TestEngines t;
    /** Trusted lists loaded, revocation online (the in-memory CRL), TSA configured. */
    private DssEngine engine;
    /** Embedded revocation data only, TSA configured. */
    private DssEngine offline;
    private ExternalSigner rsa;
    private ExternalSigner ec;

    @BeforeAll
    void setUp(@TempDir Path tmp) {
        this.tmp = tmp;
        t = new TestEngines(tmp);
        engine = t.onlineLoaded(tmp.resolve("cache"), TestEngines.tsa());
        offline = t.onlineLoaded(tmp.resolve("cache-offline"), "\"revocation\":\"offline\",\"aia\":false,"
                + TestEngines.tsa());
        rsa = new ExternalSigner(t.pki, Entity.SIGNER_RSA);
        ec = new ExternalSigner(t.pki, Entity.SIGNER_EC);
    }

    @AfterAll
    void tearDown() {
        engine.close();
        offline.close();
    }

    // ------------------------------------------------------------------ outbound loaders

    @Test
    void realLoadersSitBehindThePolicyAndTheCache() {
        EngineConfig config = EngineConfig.fromJson(t.configJson(null));
        DssEngine.Loaders l = DssEngine.Loaders.of(config);

        CachingDataLoader cache = assertInstanceOf(CachingDataLoader.class, l.http(), "CRL/AIA: cache outermost");
        OutboundFetchPolicy http = assertInstanceOf(OutboundFetchPolicy.class, cache.delegate());
        CommonsDataLoader client = assertInstanceOf(CommonsDataLoader.class, http.delegate());
        // follow_redirects (default true): the client itself never follows a 3xx; the policy checks each hop.
        assertFalse(client.isRedirectsEnabled(), "the policy takes redirects over");
        assertInstanceOf(OutboundFetchPolicy.RedirectInterceptingHandler.class, client.getHttpClientResponseHandler());
        assertNull(client.getProxyConfig());
        assertEquals(OutboundFetchPolicy.Settings.of(config), http.settings());

        assertInstanceOf(OCSPDataLoader.class, assertInstanceOf(OutboundFetchPolicy.class, l.ocsp()).delegate());
        assertInstanceOf(TimestampDataLoader.class, assertInstanceOf(OutboundFetchPolicy.class, l.tsa()).delegate());
        CommonsDataLoader tl = assertInstanceOf(CommonsDataLoader.class,
                assertInstanceOf(OutboundFetchPolicy.class, l.tl()).delegate());
        assertNotNull(tl.getTrustStrategy(), "tl_verify_tls defaults to false");

        EngineConfig custom = EngineConfig.fromJson(t.configJson("\"http\":{\"follow_redirects\":false,\"cache_ms\":0,"
                + "\"proxy\":{\"host\":\"proxy.example.test\",\"port\":3128,\"username\":\"u\",\"password\":\"p\","
                + "\"no_proxy\":[\"intranet.example.test\"]}}"));
        DssEngine.Loaders c = DssEngine.Loaders.of(custom);
        CommonsDataLoader direct = assertInstanceOf(CommonsDataLoader.class,
                assertInstanceOf(OutboundFetchPolicy.class, c.http(), "cache_ms 0: no cache").delegate());
        assertFalse(direct.isRedirectsEnabled());
        assertFalse(direct.getHttpClientResponseHandler() instanceof OutboundFetchPolicy.RedirectInterceptingHandler,
                "follow_redirects false: nothing follows a 3xx, neither the client nor the policy");
        assertEquals("proxy.example.test", direct.getProxyConfig().getHttpProperties().getHost());
        assertEquals(3128, direct.getProxyConfig().getHttpsProperties().getPort());
        assertEquals("u", direct.getProxyConfig().getHttpsProperties().getUser());
        assertEquals(List.of("intranet.example.test"), List.copyOf(direct.getProxyConfig().getHttpProperties()
                .getExcludedHosts()));
    }

    @Test
    void aiaFetchesOnlyHttpUrls() throws Exception {
        FakeHttp http = new FakeHttp();
        http.route("http://ca.example.test/issuer.cer", t.pki.x509(Entity.ROOT_CA).getEncoded());
        DefaultAIASource aia = DssEngine.aiaSource(http);
        for (String url : List.of("file:///etc/passwd", "ldap://ldap.example.test/cn=ca", "ftp://ftp.example.test/ca")) {
            aia.getCertificatesByAIA(new CertificateToken(withCaIssuers(url)));
            assertEquals(0, http.totalHits(), url + " must not be requested");
        }
        aia.getCertificatesByAIA(new CertificateToken(withCaIssuers("http://ca.example.test/issuer.cer")));
        assertEquals(1, http.totalHits());
    }

    /** A self-signed certificate whose AIA caIssuers points at {@code url}. */
    private static X509Certificate withCaIssuers(String url) throws Exception {
        KeyPair kp = rsaKeyPair();
        X500Name name = new X500Name("CN=aia-test,O=dss-native test PKI,C=IT");
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(7),
                Date.from(now.minus(1, ChronoUnit.DAYS)), Date.from(now.plus(1, ChronoUnit.DAYS)), name, kp.getPublic());
        b.addExtension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(
                new AccessDescription(AccessDescription.id_ad_caIssuers,
                        new GeneralName(GeneralName.uniformResourceIdentifier, url))));
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate())));
    }

    private static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048, new SecureRandom());
        return g.generateKeyPair();
    }

    // ------------------------------------------------------------------ limits and encrypted PDFs

    @Test
    void structuralLimitsRefuseBeforeDssRuns() throws Exception {
        String limits = "\"limits\":{\"max_pdf_pages\":20,\"max_pdf_annotations_per_page\":10,"
                + "\"max_cms_certificates\":3,\"max_pdf_signatures\":1}";
        try (DssEngine limited = t.onlineLoaded(tmp.resolve("cache-limits"), limits + "," + TestEngines.tsa())) {
            byte[] manyPages = blankPdf(21, 0);
            assertMessage(fails(DssError.Code.VALIDATION_FAILED, () -> limited.validate(manyPages, ValidationOptions.DEFAULT)),
                    "more than 20 pages", "limits.max_pdf_pages");
            assertMessage(fails(DssError.Code.EXTENSION_FAILED,
                    () -> limited.extend(manyPages, new ExtensionOptions(ExtensionOptions.Level.T, null))),
                    "limits.max_pdf_pages");
            assertMessage(fails(DssError.Code.SIGNING_FAILED, () -> limited.prepareSignature(manyPages,
                    SigningOptions.fromJson("{\"mode\":\"cms\",\"level\":\"B\"}"))), "limits.max_pdf_pages");
            assertEquals(0, limited.validate(blankPdf(20, 0), ValidationOptions.DEFAULT).signatures.size(),
                    "at the limit is fine");

            byte[] manyAnnotations = blankPdf(1, 11);
            assertMessage(fails(DssError.Code.VALIDATION_FAILED,
                    () -> limited.validate(manyAnnotations, ValidationOptions.DEFAULT)),
                    "11 annotations", "limits.max_pdf_annotations_per_page");

            byte[] cms = withExtraCertificates(Fixtures.read("cades/attached-der.p7m"),
                    List.of(Entity.ROOT_CA, Entity.TSA, Entity.OTHER_CA, Entity.LOTL_SIGNER));
            assertMessage(fails(DssError.Code.VALIDATION_FAILED, () -> limited.validate(cms, ValidationOptions.DEFAULT)),
                    "5 certificates", "limits.max_cms_certificates");
            assertEquals(List.of(PASSED), FixtureValidationTest.verdicts(engine.validate(cms, ValidationOptions.DEFAULT)),
                    "the default limit lets the same document through");

            // b-lta.pdf has a signature plus a document timestamp: two signature revisions.
            assertMessage(fails(DssError.Code.VALIDATION_FAILED,
                    () -> limited.validate(Fixtures.read("pades/b-lta.pdf"), ValidationOptions.DEFAULT)),
                    "signature revisions", "limits.max_pdf_signatures");
            assertEquals(List.of(PASSED), FixtureValidationTest.verdicts(
                    limited.validate(Fixtures.read("pades/b-b.pdf"), ValidationOptions.DEFAULT)));
        }
    }

    @Test
    void userPasswordEncryptedPdfIsUnsupportedForEveryOperation() throws Exception {
        byte[] encrypted = encrypted(Fixtures.read("content/document.pdf"));
        String expected = "encrypted with a user password";
        assertMessage(fails(DssError.Code.UNSUPPORTED_DOCUMENT,
                () -> engine.validate(encrypted, ValidationOptions.DEFAULT)), expected, "before validating it");
        assertMessage(fails(DssError.Code.UNSUPPORTED_DOCUMENT,
                () -> engine.extend(encrypted, new ExtensionOptions(ExtensionOptions.Level.T, null))),
                expected, "before extending it");
        SigningOptions o = SigningOptions.fromJson("{\"mode\":\"cms\",\"level\":\"B\"}");
        assertMessage(fails(DssError.Code.UNSUPPORTED_DOCUMENT, () -> engine.prepareSignature(encrypted, o)),
                expected, "before signing it");
        assertMessage(fails(DssError.Code.UNSUPPORTED_DOCUMENT, () -> engine.completeSignature(encrypted,
                o.withSigningTime(Instant.now()), new byte[] {1, 2, 3})), expected);
        // An owner password alone (empty user password) opens fine.
        assertEquals(0, engine.validate(Fixtures.read("content/protected.pdf"), ValidationOptions.DEFAULT)
                .signatures.size());
    }

    // ------------------------------------------------------------------ the validation result

    @Test
    void unsignedDocumentsNeverPass() {
        ValidationResult r = engine.validate(Fixtures.read("content/document.pdf"), ValidationOptions.DEFAULT);
        assertTrue(r.signatures.isEmpty());
        assertFalse(r.allPassed());
        assertEquals(Boolean.FALSE, r.toMap().get("all_passed"));
        assertEquals(Boolean.TRUE, engine.validate(Fixtures.read("pades/b-lta.pdf"), ValidationOptions.DEFAULT)
                .toMap().get("all_passed"));
        assertEquals(Boolean.FALSE, engine.validate(Fixtures.read("tampered/pades/b-lta.pdf"),
                ValidationOptions.DEFAULT).toMap().get("all_passed"));
    }

    @Test
    void qualificationErrorsAreNotValidationErrorsAndTheTrustAnchorIsNamed() throws Exception {
        Path root = tmp.resolve("root-ca.pem");
        java.nio.file.Files.writeString(root, t.pki.pem(Entity.ROOT_CA));
        try (DssEngine privatePki = t.engine(tmp.resolve("cache-private"), "\"require_trusted_lists\":false,"
                + "\"revocation\":\"offline\",\"aia\":false,\"extra_trusted_certificates\":[\""
                + root.toString().replace("\\", "\\\\") + "\"]")) {
            assertEquals(1, privatePki.trustedListStatus().get("extra_trusted_certificates"));
            ValidationResult r = privatePki.validate(Fixtures.read("pades/b-lta.pdf"), ValidationOptions.DEFAULT);
            ValidationResult.SignatureSummary s = r.signatures.get(0);
            assertEquals(PASSED, FixtureValidationTest.verdicts(r).get(0));
            assertEquals(List.of(), s.errors(), "a passing signature has no validation errors");
            assertTrue(s.qualificationErrors().stream().anyMatch(m -> m.contains("trusted list")),
                    s.qualificationErrors().toString());
            assertEquals(ValidationResult.TrustAnchor.EXTRA_TRUSTED_CERTIFICATES, s.trustAnchor());
            assertEquals("extra_trusted_certificates", sig(r.toMap()).get("trust_anchor"));
        }
        ValidationResult trusted = engine.validate(Fixtures.read("pades/b-lta.pdf"), ValidationOptions.DEFAULT);
        assertEquals(ValidationResult.TrustAnchor.TRUSTED_LIST, trusted.signatures.get(0).trustAnchor());
        assertEquals("trusted_list", sig(trusted.toMap()).get("trust_anchor"));
        try (DssEngine noAnchors = t.engine(tmp.resolve("cache-no-anchors"), "\"require_trusted_lists\":false,"
                + "\"revocation\":\"offline\",\"aia\":false")) {
            ValidationResult r = noAnchors.validate(Fixtures.read("pades/b-lta.pdf"), ValidationOptions.DEFAULT);
            assertEquals("INDETERMINATE", r.signatures.get(0).indication().name());
            assertEquals(ValidationResult.TrustAnchor.NONE, r.signatures.get(0).trustAnchor());
            assertFalse(r.signatures.get(0).errors().isEmpty(), "the chain problem is a validation error");
        }
    }

    @Test
    void timestampsAreSummarized() throws Exception {
        ValidationResult lta = engine.validate(Fixtures.read("pades/b-lta.pdf"), ValidationOptions.DEFAULT);
        List<ValidationResult.TimestampSummary> embedded = lta.signatures.get(0).timestamps();
        assertEquals(2, embedded.size(), "signature timestamp and archive timestamp");
        assertTrue(embedded.stream().anyMatch(ts -> "SIGNATURE_TIMESTAMP".equals(ts.type())), embedded.toString());
        assertTrue(embedded.stream().anyMatch(ts -> "DOCUMENT_TIMESTAMP".equals(ts.type())), embedded.toString());
        embedded.forEach(ts -> assertNotNull(ts.productionTime()));
        assertTrue(lta.timestamps.isEmpty(), "no standalone timestamp");
        assertEquals(0, engine.validate(Fixtures.read("pades/b-b.pdf"), ValidationOptions.DEFAULT)
                .signatures.get(0).timestamps().size());

        // A PDF carrying only a document timestamp is not "unsigned": the timestamp has its own verdict.
        PAdESService service = new PAdESService(new CommonCertificateVerifier());
        service.setTspSource(new OnlineTSPSource(TestPki.TSA_URL, t.http));
        service.setPdfObjFactory(new PdfBoxNativeObjectFactory());
        DSSDocument stamped = service.timestamp(new InMemoryDocument(Fixtures.read("content/document.pdf"), "d.pdf"),
                new PAdESTimestampParameters());
        ValidationResult r = engine.validate(DSSUtils.toByteArray(stamped), ValidationOptions.DEFAULT);
        assertTrue(r.signatures.isEmpty());
        assertEquals(1, r.timestamps.size());
        assertEquals("DOCUMENT_TIMESTAMP", r.timestamps.get(0).type());
        assertNotNull(r.timestamps.get(0).indication());
        assertFalse(r.allPassed());
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> json = (List<Map<String, Object>>) r.toMap().get("timestamps");
        assertEquals(1, json.size());
        assertNotNull(json.get(0).get("production_time"));
    }

    @Test
    void changesAfterSigningAreReported() throws Exception {
        ValidationResult clean = engine.validate(Fixtures.read("pades/b-lta.pdf"), ValidationOptions.DEFAULT);
        ValidationResult.Changes c = clean.signatures.get(0).changes();
        assertNotNull(c);
        assertFalse(c.modifiedAfterSigning());
        assertTrue(c.extension() > 0, "the LT/LTA revisions are extension changes: " + c);
        assertEquals(0, c.undefined());
        assertEquals(List.of(), c.activeContent());
        assertEquals(Boolean.FALSE, sig(clean.toMap()).get("modified_after_signing"));
        assertNull(engine.validate(Fixtures.read("cades/attached-der.p7m"), ValidationOptions.DEFAULT)
                .signatures.get(0).changes(), "not a PDF: no PDF changes");

        byte[] weaponised = withOpenActionJavaScript(Fixtures.read("pades/b-lta.pdf"));
        ValidationResult r = engine.validate(weaponised, ValidationOptions.DEFAULT);
        ValidationResult.SignatureSummary s = r.signatures.get(0);
        assertEquals(PASSED, FixtureValidationTest.verdicts(r).get(0), "DSS's default policy: a warning only");
        assertTrue(s.changes().modifiedAfterSigning(), s.changes().toString());
        assertTrue(s.changes().undefined() > 0, s.changes().toString());
        assertTrue(s.changes().activeContent().stream().anyMatch(p -> p.contains("OpenAction")),
                s.changes().activeContent().toString());
        assertTrue(s.warnings().stream().anyMatch(w -> w.contains("undefined object modifications")), s.warnings().toString());
        @SuppressWarnings("unchecked")
        Map<String, Object> json = (Map<String, Object>) sig(r.toMap()).get("changes_after_signing");
        assertEquals(Boolean.TRUE, sig(r.toMap()).get("modified_after_signing"));
        assertTrue(((List<?>) json.get("active_content")).size() > 0);
    }

    /**
     * DSS 6.5.1 flags the document timestamp its own extension adds as a change "restricted by" a signed field's
     * /Lock (FieldMDP and SigFieldLock warnings): an upstream inconsistency (certified DocMDP documents get no such
     * warning). The verdict stays TOTAL_PASSED and the structured flag must not call the library's own extension
     * a modification.
     */
    @Test
    void theLibrarysOwnExtensionIsNotAModificationEvenUnderAFieldLock() throws Exception {
        byte[] withLockedField = withLockedSignatureField(Fixtures.read("content/document.pdf"));
        SigningOptions o = SigningOptions.fromJson("{\"mode\":\"cms\",\"level\":\"B\",\"pades\":{\"visible\":"
                + "{\"field\":\"Firma1\",\"text\":\"Mario Rossi\"}}}");
        PreparedSignature p = engine.prepareSignature(withLockedField, o);
        byte[] signed = engine.completeSignature(withLockedField, o.withSigningTime(p.signingTime()),
                rsa.cms(p.digestAlgorithm(), p.digest(), EnumSet.noneOf(Cms.class))).document();
        byte[] extended = engine.extend(signed, new ExtensionOptions(ExtensionOptions.Level.T, null)).document();
        ValidationResult r = engine.validate(extended, ValidationOptions.DEFAULT);
        assertEquals(List.of(PASSED), FixtureValidationTest.verdicts(r));
        ValidationResult.Changes c = r.signatures.get(0).changes();
        assertFalse(c.modifiedAfterSigning(), c.toString());
        assertTrue(c.extension() > 0, c.toString());
        assertEquals(0, c.undefined() + c.annotation(), c.toString());
    }

    @Test
    void activeContentKeysAreRecognisedInObjectPaths() {
        assertTrue(ValidationResult.isActiveContent("/Root /OpenAction"));
        assertTrue(ValidationResult.isActiveContent("/Root /Pages 12R /Kids[0] /AA"));
        assertTrue(ValidationResult.isActiveContent("/Root /Names /EmbeddedFiles"));
        assertFalse(ValidationResult.isActiveContent("/Root /Pages 12R /Kids[0] /Contents"));
        assertFalse(ValidationResult.isActiveContent("/Root /AcroForm /Fields"));
        assertFalse(ValidationResult.isActiveContent(null));
    }

    @Test
    void aPdfInsideACadesEnvelopeIsValidatedToo() throws Exception {
        byte[] signedPdf = Fixtures.read("pades/b-b.pdf");
        ValidationResult r = engine.validate(envelope(signedPdf), ValidationOptions.DEFAULT);
        assertEquals(List.of(PASSED), FixtureValidationTest.verdicts(r));
        assertEquals(1, r.nested.size());
        assertEquals("PDF", r.nested.get(0).containerType);
        assertEquals(List.of(PASSED), FixtureValidationTest.verdicts(r.nested.get(0)));
        assertTrue(r.allPassed());

        ValidationResult tampered = engine.validate(envelope(Fixtures.read("tampered/pades/b-b.pdf")),
                ValidationOptions.DEFAULT);
        assertEquals(List.of(PASSED), FixtureValidationTest.verdicts(tampered), "the envelope itself is fine");
        assertEquals(List.of("TOTAL_FAILED/HASH_FAILURE"), FixtureValidationTest.verdicts(tampered.nested.get(0)));
        assertFalse(tampered.allPassed(), "the inner signature counts");

        ValidationResult plain = engine.validate(envelope(Fixtures.read("content/document.pdf")), ValidationOptions.DEFAULT);
        assertTrue(plain.nested.isEmpty(), "an unsigned PDF inside has nothing to report");
        assertTrue(plain.allPassed());
        assertTrue(engine.validate(envelope(signedPdf), ValidationOptions.fromJson("{\"unwrap_nested\":false}"))
                .nested.isEmpty());
    }

    // ------------------------------------------------------------------ extension

    @Test
    void mixedLevelsAreRaisedTogether() {
        for (String fixture : List.of("pades/b-lta.pdf", "pades/b-lt.pdf")) {
            byte[] mixed = withSecondSignature(Fixtures.read(fixture));
            ValidationResult before = offline.validate(mixed, ValidationOptions.DEFAULT);
            assertEquals(2, before.signatures.size());
            ExtensionOptions.Level level = fixture.contains("lta") ? ExtensionOptions.Level.LTA : ExtensionOptions.Level.LT;
            ExtensionResult r = engine.extend(mixed, new ExtensionOptions(level, null));
            ValidationResult after = offline.validate(r.document(), ValidationOptions.DEFAULT);
            assertEquals(List.of(PASSED, PASSED), FixtureValidationTest.verdicts(after), fixture);
            // The document timestamp added for the B signature covers the earlier one too, so that one may end
            // one level above the target (LT + document timestamp = LTA): at or above, never below.
            after.signatures.forEach(s -> assertTrue(s.format().toString().compareTo("PAdES-BASELINE-" + level) >= 0
                    && s.format().toString().startsWith("PAdES-BASELINE-L"), fixture + ": " + s.signedBy() + " " + s.format()));
        }
        // Still refused: nothing to raise when every signature is above the target.
        DssError e = fails(DssError.Code.EXTENSION_FAILED,
                () -> engine.extend(Fixtures.read("pades/b-lta.pdf"), new ExtensionOptions(ExtensionOptions.Level.LT, null)));
        assertMessage(e, "already extended with a higher level");
    }

    @Test
    void offlineExtensionToLtRefusesBeforeAskingTheTsa() {
        for (ExtensionOptions.Level level : List.of(ExtensionOptions.Level.LT, ExtensionOptions.Level.LTA)) {
            int hits = t.http.hits(TestPki.TSA_URL);
            DssError e = fails(DssError.Code.EXTENSION_FAILED,
                    () -> offline.extend(Fixtures.read("pades/b-b.pdf"), new ExtensionOptions(level, null)));
            assertMessage(e, "Revocation data is missing", "revocation is \"offline\"");
            assertEquals(hits, t.http.hits(TestPki.TSA_URL), "no timestamp was requested for " + level);
        }
        // What the document already holds is enough: no TSA involved for LT to LT.
        offline.extend(Fixtures.read("pades/b-lt.pdf"), new ExtensionOptions(ExtensionOptions.Level.LT, null));
    }

    // ------------------------------------------------------------------ the TSA's tokens

    @Test
    void tokensFromAnUntrustedTsaAreRefused() throws Exception {
        KeyPair kp = rsaKeyPair();
        X509Certificate rogue = selfSignedTsa(kp);
        Tsa tsa = new Tsa(kp.getPrivate(), rogue, List.of(rogue));
        withTsa(tsa, () -> {
            DssError e = fails(DssError.Code.TSA_FAILED, () -> engine.extend(Fixtures.read("pades/b-b.pdf"),
                    new ExtensionOptions(ExtensionOptions.Level.T, null)));
            assertMessage(e, "does not chain to a trusted certificate");
            // Signing at T spends the external signature first, so the refusal reaches the caller the same way.
            SigningOptions o = SigningOptions.fromJson("{\"mode\":\"cms\",\"level\":\"T\"}");
            PreparedSignature p = engine.prepareSignature(Fixtures.read("content/document.pdf"), o);
            fails(DssError.Code.TSA_FAILED, () -> engine.completeSignature(Fixtures.read("content/document.pdf"),
                    o.withSigningTime(p.signingTime()), rsa.cms(p.digestAlgorithm(), p.digest(), EnumSet.noneOf(Cms.class))));
        });
        // The opt-out accepts it; so does an engine without any trust anchor (nothing to check against). An engine
        // that requires trusted lists but has not loaded them yet refuses to extend (TRUSTED_LISTS_NOT_LOADED) but
        // signs at T, which needs no lists, with the token unchecked (F-219: documented, the warning is the signal).
        try (DssEngine lenient = t.onlineLoaded(tmp.resolve("cache-lenient"), "\"tsa\":{\"url\":\"" + TestPki.TSA_URL
                + "\",\"require_trusted\":false}");
             DssEngine noTrust = t.engine(tmp.resolve("cache-empty"), "\"require_trusted_lists\":false,"
                     + TestEngines.tsa());
             DssEngine notYetLoaded = t.engine(tmp.resolve("cache-not-yet-loaded"), "\"require_trusted_lists\":true,"
                     + "\"tsa\":{\"url\":\"" + TestPki.TSA_URL + "\",\"require_trusted\":true}")) {
            assertEquals(Boolean.FALSE, notYetLoaded.trustedListStatus().get("loaded"));
            withTsa(tsa, () -> {
                assertEquals("PAdES-BASELINE-T", lenient.extend(Fixtures.read("pades/b-b.pdf"),
                        new ExtensionOptions(ExtensionOptions.Level.T, null)).level().toString());
                assertEquals("PAdES-BASELINE-T", noTrust.extend(Fixtures.read("pades/b-b.pdf"),
                        new ExtensionOptions(ExtensionOptions.Level.T, null)).level().toString());
                fails(DssError.Code.TRUSTED_LISTS_NOT_LOADED, () -> notYetLoaded.extend(Fixtures.read("pades/b-b.pdf"),
                        new ExtensionOptions(ExtensionOptions.Level.T, null)));
                SigningOptions o = SigningOptions.fromJson("{\"mode\":\"cms\",\"level\":\"T\"}");
                PreparedSignature p = notYetLoaded.prepareSignature(Fixtures.read("content/document.pdf"), o);
                assertNotNull(notYetLoaded.completeSignature(Fixtures.read("content/document.pdf"),
                        o.withSigningTime(p.signingTime()), rsa.cms(p.digestAlgorithm(), p.digest(), EnumSet.noneOf(Cms.class))),
                        "before the first refresh there is nothing to chain to: the token is embedded unchecked");
            });
            // Once the lists are in, the same engine refuses the same TSA for the same signature.
            notYetLoaded.refreshTrustedListsOnline();
            withTsa(tsa, () -> {
                SigningOptions o = SigningOptions.fromJson("{\"mode\":\"cms\",\"level\":\"T\"}");
                PreparedSignature p = notYetLoaded.prepareSignature(Fixtures.read("content/document.pdf"), o);
                assertMessage(fails(DssError.Code.TSA_FAILED, () -> notYetLoaded.completeSignature(
                        Fixtures.read("content/document.pdf"), o.withSigningTime(p.signingTime()),
                        rsa.cms(p.digestAlgorithm(), p.digest(), EnumSet.noneOf(Cms.class)))),
                        "does not chain to a trusted certificate");
            });
        }
    }

    @Test
    void dssExceptionsWithoutAMessageAreDescribedByTheirClass() {
        assertEquals("DSSException", DssEngine.describe(new eu.europa.esig.dss.model.DSSException((String) null)));
        assertEquals("no such thing", DssEngine.describe(new eu.europa.esig.dss.model.DSSException("no such thing")));
        assertEquals("ArrayIndexOutOfBoundsException: 3",
                DssEngine.describe(new ArrayIndexOutOfBoundsException("3")));
        assertEquals("NullPointerException", DssEngine.describe(new NullPointerException()));
    }

    @Test
    void tokensWithAWrongClockWeakAlgorithmOrWrongNonceAreRefused() throws Exception {
        Tsa skewed = new Tsa(t.pki.key(Entity.TSA), t.pki.x509(Entity.TSA),
                List.of(t.pki.x509(Entity.TSA), t.pki.x509(Entity.ROOT_CA)));
        skewed.skewMs = -3_600_000;
        withTsa(skewed, () -> assertMessage(fails(DssError.Code.TSA_FAILED, () -> engine.extend(
                Fixtures.read("pades/b-b.pdf"), new ExtensionOptions(ExtensionOptions.Level.T, null))),
                "away from this host's clock", "tsa.max_clock_skew_ms"));
        try (DssEngine tolerant = t.onlineLoaded(tmp.resolve("cache-tolerant"), "\"tsa\":{\"url\":\"" + TestPki.TSA_URL
                + "\",\"max_clock_skew_ms\":7200000}")) {
            withTsa(skewed, () -> tolerant.extend(Fixtures.read("pades/b-b.pdf"),
                    new ExtensionOptions(ExtensionOptions.Level.T, null)));
        }

        Tsa sha1 = new Tsa(t.pki.key(Entity.TSA), t.pki.x509(Entity.TSA), List.of(t.pki.x509(Entity.TSA)));
        sha1.signatureAlgorithm = "SHA1withRSA";
        withTsa(sha1, () -> assertMessage(fails(DssError.Code.TSA_FAILED, () -> engine.extend(
                Fixtures.read("pades/b-b.pdf"), new ExtensionOptions(ExtensionOptions.Level.T, null))), "too weak"));

        Tsa wrongNonce = new Tsa(t.pki.key(Entity.TSA), t.pki.x509(Entity.TSA), List.of(t.pki.x509(Entity.TSA)));
        wrongNonce.replaceNonce = true;
        withTsa(wrongNonce, () -> assertMessage(fails(DssError.Code.TSA_FAILED, () -> engine.extend(
                Fixtures.read("pades/b-b.pdf"), new ExtensionOptions(ExtensionOptions.Level.T, null))), "nonce"));

        // The good TSA still works after all that.
        assertEquals("PAdES-BASELINE-T", engine.extend(Fixtures.read("pades/b-b.pdf"),
                new ExtensionOptions(ExtensionOptions.Level.T, null)).level().toString());
    }

    @Test
    void aTsaThatCannotBeReachedIsATsaFailure() {
        t.http.postRoute(TestPki.TSA_URL, request -> {
            throw new eu.europa.esig.dss.spi.exception.DSSExternalResourceException("connection refused");
        });
        try {
            assertMessage(fails(DssError.Code.TSA_FAILED, () -> engine.extend(Fixtures.read("pades/b-b.pdf"),
                    new ExtensionOptions(ExtensionOptions.Level.T, null))), "could not be used", "connection refused");
        } finally {
            t.http.postRoute(TestPki.TSA_URL, t.pki::timestampResponse);
        }
    }

    /** Serves {@code tsa} at the test TSA's URL while {@code body} runs. */
    private void withTsa(Tsa tsa, Executable body) throws Exception {
        t.http.postRoute(TestPki.TSA_URL, tsa::respond);
        try {
            body.execute();
        } catch (Throwable e) {
            if (e instanceof Exception ex) {
                throw ex;
            }
            throw (Error) e;
        } finally {
            t.http.postRoute(TestPki.TSA_URL, t.pki::timestampResponse);
        }
    }

    /** An RFC 3161 responder with a key of the test's choosing and, optionally, something wrong. */
    static final class Tsa {
        private final PrivateKey key;
        private final X509Certificate certificate;
        private final List<X509Certificate> included;
        String signatureAlgorithm = "SHA256withRSA";
        long skewMs;
        boolean replaceNonce;

        Tsa(PrivateKey key, X509Certificate certificate, List<X509Certificate> included) {
            this.key = key;
            this.certificate = certificate;
            this.included = included;
        }

        byte[] respond(byte[] request) {
            try {
                TimeStampTokenGenerator tokens = new TimeStampTokenGenerator(
                        new JcaSimpleSignerInfoGeneratorBuilder().build(signatureAlgorithm, key, certificate),
                        new JcaDigestCalculatorProviderBuilder().build()
                                .get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)),
                        new ASN1ObjectIdentifier(TestPki.TSA_POLICY));
                tokens.addCertificates(new JcaCertStore(included));
                TimeStampRequest req = new TimeStampRequest(request);
                if (replaceNonce) {
                    TimeStampRequestGenerator g = new TimeStampRequestGenerator();
                    g.setCertReq(true);
                    req = g.generate(req.getMessageImprintAlgOID(), req.getMessageImprintDigest(), BigInteger.TEN);
                }
                return new TimeStampResponseGenerator(tokens, TSPAlgorithms.ALLOWED)
                        .generate(req, new BigInteger(64, new SecureRandom()),
                                new Date(System.currentTimeMillis() + skewMs)).getEncoded();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    private static X509Certificate selfSignedTsa(KeyPair kp) throws Exception {
        X500Name name = new X500Name("CN=Rogue TSA,O=nobody,C=XX");
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(99),
                Date.from(now.minus(1, ChronoUnit.DAYS)), Date.from(now.plus(30, ChronoUnit.DAYS)), name, kp.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        b.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate())));
    }

    // ------------------------------------------------------------------ helpers

    /** A second, B-level signature by the EC signer on an already signed PDF. */
    private byte[] withSecondSignature(byte[] pdf) {
        SigningOptions o = SigningOptions.fromJson("{\"mode\":\"cms\",\"level\":\"B\"}");
        PreparedSignature p = engine.prepareSignature(pdf, o);
        byte[] cms = ec.cms(p.digestAlgorithm(), p.digest(), EnumSet.noneOf(Cms.class));
        return engine.completeSignature(pdf, o.withSigningTime(p.signingTime()), cms).document();
    }

    /** An attached CAdES envelope (by the RSA signer) around {@code content}. */
    private byte[] envelope(byte[] content) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(content);
        byte[] detached = rsa.cms(DigestAlgorithm.SHA256, digest, EnumSet.of(Cms.SIGNING_TIME));
        return ExternalSigning.encapsulate(detached, content);
    }

    private static byte[] blankPdf(int pages, int annotationsOnFirstPage) throws IOException {
        try (PDDocument doc = new PDDocument()) {
            for (int i = 0; i < pages; i++) {
                PDPage page = new PDPage(PDRectangle.A4);
                doc.addPage(page);
                if (i == 0) {
                    for (int a = 0; a < annotationsOnFirstPage; a++) {
                        PDAnnotationLink link = new PDAnnotationLink();
                        link.setRectangle(new PDRectangle(10 + a, 10, 20, 20));
                        page.getAnnotations().add(link);
                    }
                }
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.save(out);
            return out.toByteArray();
        }
    }

    /** A PDF with an empty signature field "Firma1" whose /Lock forbids every change once it is signed. */
    private static byte[] withLockedSignatureField(byte[] pdf) throws IOException {
        try (PDDocument doc = Loader.loadPDF(pdf)) {
            org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm form =
                    new org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm(doc);
            doc.getDocumentCatalog().setAcroForm(form);
            org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField field =
                    new org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField(form);
            field.setPartialName("Firma1");
            org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget widget = field.getWidgets().get(0);
            PDPage page = doc.getPage(0);
            widget.setRectangle(new PDRectangle(50, 50, 200, 60));
            widget.setPage(page);
            page.getAnnotations().add(widget);
            org.apache.pdfbox.cos.COSDictionary lock = new org.apache.pdfbox.cos.COSDictionary();
            lock.setItem(org.apache.pdfbox.cos.COSName.TYPE, org.apache.pdfbox.cos.COSName.getPDFName("SigFieldLock"));
            lock.setName("Action", "All");
            lock.setInt("P", 1);
            field.getCOSObject().setItem("Lock", lock);
            form.getFields().add(field);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.save(out);
            return out.toByteArray();
        }
    }

    private static byte[] encrypted(byte[] pdf) throws IOException {
        try (PDDocument doc = Loader.loadPDF(pdf)) {
            doc.protect(new StandardProtectionPolicy("owner-secret", "user-secret", new AccessPermission()));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.save(out);
            return out.toByteArray();
        }
    }

    /** An incremental update adding a JavaScript /OpenAction to the catalog: the signature stays intact. */
    private static byte[] withOpenActionJavaScript(byte[] signed) throws IOException {
        try (PDDocument doc = Loader.loadPDF(signed)) {
            doc.getDocumentCatalog().setOpenAction(new PDActionJavaScript("app.alert('hi');"));
            doc.getDocumentCatalog().getCOSObject().setNeedToBeUpdated(true);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.saveIncremental(out);
            return out.toByteArray();
        }
    }

    /** The CMS with the given test-PKI certificates added to its certificate set. */
    private byte[] withExtraCertificates(byte[] cms, List<Entity> extra) throws Exception {
        org.bouncycastle.asn1.cms.ContentInfo ci = org.bouncycastle.asn1.cms.ContentInfo.getInstance(cms);
        org.bouncycastle.asn1.cms.SignedData sd = org.bouncycastle.asn1.cms.SignedData.getInstance(ci.getContent());
        ASN1EncodableVector certs = new ASN1EncodableVector();
        for (ASN1Encodable c : sd.getCertificates()) {
            certs.add(c);
        }
        for (Entity e : extra) {
            certs.add(Certificate.getInstance(t.pki.x509(e).getEncoded()));
        }
        org.bouncycastle.asn1.cms.SignedData padded = new org.bouncycastle.asn1.cms.SignedData(sd.getDigestAlgorithms(),
                sd.getEncapContentInfo(), new DERSet(certs), sd.getCRLs(), sd.getSignerInfos());
        return new org.bouncycastle.asn1.cms.ContentInfo(ci.getContentType(), padded).getEncoded(ASN1Encoding.DER);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> sig(Map<String, Object> result) {
        return ((List<Map<String, Object>>) result.get("signatures")).get(0);
    }

    private static DssError fails(DssError.Code code, Executable call) {
        DssError e = assertThrows(DssError.class, call);
        assertEquals(code, e.code(), e.getMessage());
        return e;
    }

    private static void assertMessage(DssError e, String... parts) {
        for (String part : parts) {
            assertTrue(e.getMessage().contains(part), part + " not in: " + e.getMessage());
        }
    }
}
