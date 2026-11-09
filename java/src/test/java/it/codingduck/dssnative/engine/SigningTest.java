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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.cert.CertificateEncodingException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.TimeZone;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;

import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;

import it.codingduck.dssnative.testsupport.ExternalSigner;
import it.codingduck.dssnative.testsupport.ExternalSigner.Cms;
import it.codingduck.dssnative.testsupport.ExternalSigner.Tamper;
import it.codingduck.dssnative.testsupport.Fixtures;
import it.codingduck.dssnative.testsupport.TestEngines;
import it.codingduck.dssnative.testsupport.TestPki;
import it.codingduck.dssnative.testsupport.TestPki.Entity;

/**
 * {@link DssEngine#prepareSignature} and {@link DssEngine#completeSignature} with an {@link ExternalSigner} holding
 * the key: in mode {@code cms} it returns a CMS around the digest, in mode {@code signature_value} a bare signature.
 * Every signed document is validated again; LT and LTA ones also by an engine that fetches no revocation data.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SigningTest {

    private static final String PASSED = "TOTAL_PASSED/-";

    private TestEngines t;
    /** Trusted lists loaded, revocation online (the in-memory CRL), TSA configured. */
    private DssEngine engine;
    /** As {@link #engine}, without a TSA. */
    private DssEngine noTsa;
    /** Embedded revocation data only. */
    private DssEngine offline;
    /** No trusted list loaded (empty cache, never refreshed). */
    private DssEngine noTrust;
    private ExternalSigner rsa;
    private ExternalSigner ec;
    /** Signers holding keys whose certificates are not for signing documents: the root CA's and the TSA's. */
    private ExternalSigner ca;
    private ExternalSigner tsa;
    private byte[] pdf;
    private byte[] text;

    @BeforeAll
    void setUp(@TempDir Path tmp) {
        t = new TestEngines(tmp);
        engine = t.onlineLoaded(tmp.resolve("cache"), TestEngines.tsa());
        noTsa = t.onlineLoaded(tmp.resolve("cache-no-tsa"), null);
        offline = t.onlineLoaded(tmp.resolve("cache-offline"), "\"revocation\":\"offline\",\"aia\":false");
        noTrust = t.engine(tmp.resolve("cache-empty"), TestEngines.tsa());
        rsa = new ExternalSigner(t.pki, Entity.SIGNER_RSA);
        ec = new ExternalSigner(t.pki, Entity.SIGNER_EC);
        ca = new ExternalSigner(t.pki, Entity.ROOT_CA);
        tsa = new ExternalSigner(t.pki, Entity.TSA);
        pdf = Fixtures.read("content/document.pdf");
        text = Fixtures.read("content/document.txt");
    }

    @AfterAll
    void tearDown() {
        engine.close();
        noTsa.close();
        offline.close();
        noTrust.close();
    }

    // ------------------------------------------------------------------ helpers

    private String certificate(Entity e) {
        try {
            return Base64.getEncoder().encodeToString(t.pki.x509(e).getEncoded());
        } catch (CertificateEncodingException ex) {
            throw new IllegalStateException(ex);
        }
    }

    /** {@code "signing_certificate":...,"certificate_chain":[root]} for {@code e}. */
    private String certificates(Entity e) {
        return "\"signing_certificate\":\"" + certificate(e) + "\",\"certificate_chain\":[\""
                + certificate(Entity.ROOT_CA) + "\"]";
    }

    private static SigningOptions options(String json) {
        return SigningOptions.fromJson(json);
    }

    /** prepare, then the external signer on its result, then complete with the signing time prepare returned. */
    private static SigningResult sign(DssEngine e, byte[] document, SigningOptions o,
                                      Function<PreparedSignature, byte[]> signer) {
        PreparedSignature prepared = e.prepareSignature(document, o);
        return e.completeSignature(document, o.withSigningTime(prepared.signingTime()), signer.apply(prepared));
    }

    private Function<PreparedSignature, byte[]> cmsFrom(ExternalSigner signer, Set<Cms> shape) {
        return p -> signer.cms(p.digestAlgorithm(), p.digest(), shape);
    }

    private Function<PreparedSignature, byte[]> valueFrom(ExternalSigner signer) {
        return p -> signer.signatureValue(p.digestAlgorithm(), p.digest(), false);
    }

    private static ValidationResult validate(DssEngine e, byte[] signed, byte[] detached) {
        List<eu.europa.esig.dss.model.DSSDocument> contents = detached == null ? List.of()
                : List.of(new InMemoryDocument(detached, "document.txt"));
        return e.validate(signed, new ValidationOptions(null, contents, null, null, false));
    }

    private static void assertValidatesAs(DssEngine e, byte[] signed, byte[] detached, String format) {
        ValidationResult v = validate(e, signed, detached);
        assertEquals(List.of(PASSED), FixtureValidationTest.verdicts(v), () -> v.reports.get(ReportKind.SIMPLE));
        assertEquals(format, v.signatures.get(0).format().toString());
    }

    private static DssError fails(DssError.Code code, Executable call) {
        DssError e = assertThrows(DssError.class, call);
        assertEquals(code, e.code(), e.getMessage());
        return e;
    }

    private static void assertMessage(DssError e, String part) {
        assertTrue(e.getMessage().contains(part), e.getMessage());
    }

    private int tsaHits() {
        return t.http.hits(TestPki.TSA_URL);
    }

    // ------------------------------------------------------------------ mode "cms", PAdES

    @Test
    void padesFromATimestampedCmsExtendsToLt() throws InterruptedException {
        SigningOptions o = options("{\"mode\":\"cms\",\"level\":\"LT\"}");
        PreparedSignature prepared = engine.prepareSignature(pdf, o);
        assertEquals(SigningOptions.Format.PADES, prepared.format());
        assertEquals(32, prepared.digest().length);
        assertNull(prepared.dataToSign());
        byte[] cms = rsa.cms(prepared.digestAlgorithm(), prepared.digest(), EnumSet.of(Cms.TIMESTAMP, Cms.BER));
        Thread.sleep(1100); // the CRL the extension embeds must be issued after the signature timestamp
        int hits = tsaHits();

        SigningResult r = engine.completeSignature(pdf, o.withSigningTime(prepared.signingTime()), cms);
        assertEquals(hits, tsaHits(), "the CMS brings its own signature timestamp");
        assertEquals("PAdES-BASELINE-LT", r.level().toString());
        assertEquals("ENVELOPED", r.packaging());
        assertArrayEquals(pdf, Arrays.copyOf(r.document(), pdf.length), "signing appends to the original bytes");
        assertValidatesAs(engine, r.document(), null, "PAdES-BASELINE-LT");
        assertValidatesAs(offline, r.document(), null, "PAdES-BASELINE-LT");
    }

    @Test
    void padesFromATimestampedCmsAtLevelBIsT() {
        int hits = tsaHits();
        SigningResult r = sign(engine, pdf, options("{\"mode\":\"cms\",\"level\":\"B\"}"),
                cmsFrom(rsa, EnumSet.of(Cms.TIMESTAMP)));
        assertEquals(hits, tsaHits());
        assertEquals("PAdES-BASELINE-T", r.level().toString(), "the level the document actually has");
        assertValidatesAs(engine, r.document(), null, "PAdES-BASELINE-T");
    }

    @Test
    void padesFromACmsWithoutTimestamp() {
        SigningResult b = sign(engine, pdf, options("{\"mode\":\"cms\",\"level\":\"B\"}"),
                cmsFrom(rsa, EnumSet.noneOf(Cms.class)));
        assertEquals("PAdES-BASELINE-B", b.level().toString());
        assertValidatesAs(engine, b.document(), null, "PAdES-BASELINE-B");

        int hits = tsaHits();
        SigningResult tl = sign(engine, pdf, options("{\"mode\":\"cms\",\"level\":\"T\"}"),
                cmsFrom(rsa, EnumSet.noneOf(Cms.class)));
        assertEquals(hits + 1, tsaHits(), "T adds a document timestamp");
        assertValidatesAs(engine, tl.document(), null, "PAdES-BASELINE-T");

        SigningResult lta = sign(engine, pdf, options("{\"mode\":\"cms\",\"level\":\"LTA\"}"),
                cmsFrom(rsa, EnumSet.of(Cms.TIMESTAMP, Cms.CHAIN)));
        assertValidatesAs(engine, lta.document(), null, "PAdES-BASELINE-LTA");
    }

    @Test
    void padesDictionaryEntriesAndDigestAlgorithm() {
        SigningOptions o = options("{\"mode\":\"cms\",\"level\":\"B\",\"digest_algorithm\":\"SHA-512\","
                + "\"filename\":\"contract.pdf\",\"pades\":{\"reason\":\"Approval\",\"location\":\"Rome\","
                + "\"contact_info\":\"signer@example.test\",\"signer_name\":\"Mario Rossi\",\"content_size\":12000}}");
        PreparedSignature prepared = engine.prepareSignature(pdf, o);
        assertEquals("SHA512", prepared.digestAlgorithm().getName());
        assertEquals(64, prepared.digest().length);
        SigningResult r = engine.completeSignature(pdf, o.withSigningTime(prepared.signingTime()),
                rsa.cms(prepared.digestAlgorithm(), prepared.digest(), EnumSet.noneOf(Cms.class)));
        String tail = new String(r.document(), pdf.length, r.document().length - pdf.length, StandardCharsets.ISO_8859_1);
        for (String entry : List.of("/Reason (Approval)", "/Location (Rome)", "/ContactInfo (signer@example.test)",
                "/Name (Mario Rossi)", "/SubFilter /ETSI.CAdES.detached")) {
            assertTrue(tail.contains(entry), entry);
        }
        assertValidatesAs(engine, r.document(), null, "PAdES-BASELINE-B");
    }

    @Test
    void preparingIsRepeatable() {
        SigningOptions o = options("{\"mode\":\"cms\",\"level\":\"B\",\"signing_time\":\"2026-06-01T10:00:00Z\"}");
        PreparedSignature a = engine.prepareSignature(pdf, o);
        PreparedSignature b = noTrust.prepareSignature(pdf, o);
        assertArrayEquals(a.digest(), b.digest(), "same document and options, same digest, on any engine");
        assertEquals(Instant.parse("2026-06-01T10:00:00Z"), a.signingTime());
        for (String other : List.of("\"signing_time\":\"2026-06-01T10:00:01Z\"", "\"filename\":\"other.pdf\"",
                "\"pades\":{\"content_size\":20000}", "\"pades\":{\"reason\":\"x\"}")) {
            // The JSON parser refuses duplicate keys, so another signing time replaces the first one.
            String time = other.startsWith("\"signing_time\"") ? "" : "\"signing_time\":\"2026-06-01T10:00:00Z\",";
            SigningOptions changed = options("{\"mode\":\"cms\",\"level\":\"B\"," + time + other + "}");
            assertFalse(Arrays.equals(a.digest(), engine.prepareSignature(pdf, changed).digest()), other);
        }
        Instant now = engine.prepareSignature(pdf, options("{\"mode\":\"cms\",\"level\":\"B\"}")).signingTime();
        assertEquals(0, now.getNano(), "a signing time prepare picks is in whole seconds");
    }

    @Test
    void preparingDoesNotDependOnTheHostTimeZone() {
        SigningOptions o = options("{\"mode\":\"cms\",\"level\":\"B\",\"signing_time\":\"2026-06-01T10:00:00Z\"}");
        TimeZone host = TimeZone.getDefault();
        try {
            TimeZone.setDefault(TimeZone.getTimeZone("Pacific/Kiritimati"));
            byte[] east = engine.prepareSignature(pdf, o).digest();
            TimeZone.setDefault(TimeZone.getTimeZone("America/Los_Angeles"));
            byte[] west = engine.prepareSignature(pdf, o).digest();
            assertArrayEquals(east, west, "prepare and complete may run on hosts in different time zones");
        } finally {
            TimeZone.setDefault(host);
        }
    }

    // ------------------------------------------------------------------ mode "cms", CAdES

    @Test
    void cadesFromACmsDetachedAndEnveloping() {
        SigningOptions o = options("{\"mode\":\"cms\",\"level\":\"B\"}");
        PreparedSignature prepared = engine.prepareSignature(text, o);
        assertEquals(SigningOptions.Format.CADES, prepared.format());
        assertArrayEquals(DSSUtils.digest(prepared.digestAlgorithm(), text), prepared.digest(),
                "for CAdES the digest is the content's");
        byte[] cms = rsa.cms(prepared.digestAlgorithm(), prepared.digest(),
                EnumSet.of(Cms.SIGNING_TIME, Cms.TIMESTAMP, Cms.BER));

        SigningResult detached = engine.completeSignature(text, o, cms);
        assertEquals("CAdES-BASELINE-T", detached.level().toString());
        assertEquals("DETACHED", detached.packaging());
        assertEquals(0x30, detached.document()[0]);
        assertTrue((detached.document()[1] & 0xFF) != 0x80, "BER from the signer comes back as DER");
        assertValidatesAs(engine, detached.document(), text, "CAdES-BASELINE-T");

        SigningResult enveloping = engine.completeSignature(text,
                options("{\"mode\":\"cms\",\"level\":\"B\",\"packaging\":\"enveloping\"}"), cms);
        assertEquals("ENVELOPING", enveloping.packaging());
        assertValidatesAs(engine, enveloping.document(), null, "CAdES-BASELINE-T");
        SignedData sd = SignedData.getInstance(ContentInfo.getInstance(enveloping.document()).getContent());
        assertNotNull(sd.getEncapContentInfo().getContent(), "the content is inside the .p7m");
    }

    @Test
    void cadesFromACmsExtendsToLtAndLta() throws InterruptedException {
        SigningOptions lt = options("{\"mode\":\"cms\",\"level\":\"LT\"}");
        PreparedSignature prepared = engine.prepareSignature(text, lt);
        byte[] cms = rsa.cms(prepared.digestAlgorithm(), prepared.digest(), EnumSet.of(Cms.SIGNING_TIME,
                Cms.TIMESTAMP));
        Thread.sleep(1100);
        SigningResult r = engine.completeSignature(text, lt, cms);
        assertEquals("CAdES-BASELINE-LT", r.level().toString());
        assertValidatesAs(engine, r.document(), text, "CAdES-BASELINE-LT");
        assertValidatesAs(offline, r.document(), text, "CAdES-BASELINE-LT");

        SigningResult lta = engine.completeSignature(text,
                options("{\"mode\":\"cms\",\"level\":\"LTA\",\"packaging\":\"enveloping\"}"), cms);
        assertValidatesAs(offline, lta.document(), null, "CAdES-BASELINE-LTA");

        int hits = tsaHits();
        SigningResult t = sign(engine, text, options("{\"mode\":\"cms\",\"level\":\"T\"}"),
                cmsFrom(rsa, EnumSet.of(Cms.SIGNING_TIME)));
        assertEquals(hits + 1, tsaHits(), "T adds the signature timestamp the CMS lacks");
        assertValidatesAs(engine, t.document(), text, "CAdES-BASELINE-T");
    }

    // ------------------------------------------------------------------ mode "signature_value"

    @Test
    void padesFromASignatureValueAtEveryLevel() throws InterruptedException {
        for (String level : List.of("B", "T", "LT", "LTA")) {
            SigningOptions o = options("{\"mode\":\"signature_value\",\"level\":\"" + level + "\","
                    + certificates(Entity.SIGNER_RSA) + "}");
            PreparedSignature prepared = engine.prepareSignature(pdf, o);
            assertArrayEquals(DSSUtils.digest(prepared.digestAlgorithm(), prepared.dataToSign()), prepared.digest(),
                    "the digest is the signed attributes'");
            SigningResult r = engine.completeSignature(pdf, o.withSigningTime(prepared.signingTime()),
                    rsa.signatureValue(prepared.digestAlgorithm(), prepared.digest(), false));
            assertEquals("PAdES-BASELINE-" + level, r.level().toString());
            assertValidatesAs(engine, r.document(), null, "PAdES-BASELINE-" + level);
        }
    }

    @Test
    void ecdsaSignatureValuesAsDerOrPlain() {
        for (boolean plain : List.of(false, true)) {
            SigningOptions o = options("{\"mode\":\"signature_value\",\"level\":\"B\","
                    + certificates(Entity.SIGNER_EC) + "}");
            SigningResult r = sign(engine, pdf, o, p -> ec.signatureValue(p.digestAlgorithm(), p.digest(), plain));
            assertValidatesAs(engine, r.document(), null, "PAdES-BASELINE-B");
            SigningResult c = sign(engine, text, o, p -> ec.signatureValue(p.digestAlgorithm(), p.digest(), plain));
            assertValidatesAs(engine, c.document(), text, "CAdES-BASELINE-B");
        }
    }

    @Test
    void cadesFromASignatureValue() {
        SigningOptions detached = options("{\"mode\":\"signature_value\",\"level\":\"T\","
                + certificates(Entity.SIGNER_RSA) + "}");
        SigningResult r = sign(engine, text, detached, valueFrom(rsa));
        assertEquals("DETACHED", r.packaging());
        assertValidatesAs(engine, r.document(), text, "CAdES-BASELINE-T");

        SigningOptions enveloping = options("{\"mode\":\"signature_value\",\"level\":\"B\",\"packaging\":"
                + "\"enveloping\"," + certificates(Entity.SIGNER_RSA) + "}");
        SigningResult p7m = sign(engine, text, enveloping, valueFrom(rsa));
        assertValidatesAs(engine, p7m.document(), null, "CAdES-BASELINE-B");

        // A .p7m is signed as content (a .p7m.p7m), not co-signed.
        byte[] p7m2 = sign(engine, p7m.document(), enveloping, valueFrom(rsa)).document();
        ValidationResult v = engine.validate(p7m2, ValidationOptions.DEFAULT);
        assertEquals(1, v.signatures.size());
        assertEquals(1, v.nested.size(), "the inner envelope is the signed content");
    }

    @Test
    void base64ExternalSignaturesAreDecoded() {
        SigningOptions value = options("{\"mode\":\"signature_value\",\"level\":\"B\","
                + certificates(Entity.SIGNER_RSA) + "}");
        SigningResult a = sign(engine, text, value,
                p -> Base64.getEncoder().encode(rsa.signatureValue(p.digestAlgorithm(), p.digest(), false)));
        assertValidatesAs(engine, a.document(), text, "CAdES-BASELINE-B");
        SigningResult b = sign(engine, text, options("{\"mode\":\"cms\",\"level\":\"B\"}"),
                p -> Base64.getMimeEncoder().encode(rsa.cms(p.digestAlgorithm(), p.digest(), EnumSet.of(Cms.SIGNING_TIME))));
        assertValidatesAs(engine, b.document(), text, "CAdES-BASELINE-B");
    }

    // ------------------------------------------------------------------ refusals

    @Test
    void aCmsForAnotherPreparationIsRefused() {
        SigningOptions o = options("{\"mode\":\"cms\",\"level\":\"B\"}");
        PreparedSignature prepared = engine.prepareSignature(pdf, o);
        byte[] cms = rsa.cms(prepared.digestAlgorithm(), prepared.digest(), EnumSet.noneOf(Cms.class));
        Instant later = prepared.signingTime().plusSeconds(1);
        assertMessage(fails(DssError.Code.SIGNING_FAILED, () -> engine.completeSignature(pdf, o.withSigningTime(later),
                cms)), "not this document's");
        byte[] otherPdf = Fixtures.read("pades/b-b.pdf");
        assertMessage(fails(DssError.Code.SIGNING_FAILED, () -> engine.completeSignature(otherPdf,
                o.withSigningTime(prepared.signingTime()), cms)), "same document and options");
    }

    @Test
    void aSignatureValueForAnotherPreparationIsRefused() {
        SigningOptions o = options("{\"mode\":\"signature_value\",\"level\":\"B\","
                + certificates(Entity.SIGNER_RSA) + "}");
        PreparedSignature prepared = engine.prepareSignature(pdf, o);
        byte[] value = rsa.signatureValue(prepared.digestAlgorithm(), prepared.digest(), false);
        assertMessage(fails(DssError.Code.SIGNING_FAILED, () -> engine.completeSignature(pdf,
                o.withSigningTime(prepared.signingTime().plusSeconds(1)), value)), "does not verify");
        byte[] wrongKey = ec.signatureValue(prepared.digestAlgorithm(), prepared.digest(), false);
        fails(DssError.Code.SIGNING_FAILED, () -> engine.completeSignature(pdf,
                o.withSigningTime(prepared.signingTime()), wrongKey));
    }

    @Test
    void cmsThatIsNotBaselineIsRefused() {
        SigningOptions pades = options("{\"mode\":\"cms\",\"level\":\"B\"}");
        assertMessage(fails(DssError.Code.SIGNING_FAILED, () -> sign(engine, pdf, pades,
                cmsFrom(rsa, EnumSet.of(Cms.SIGNING_TIME)))), "signing-time attribute, which PAdES does not allow");
        assertMessage(fails(DssError.Code.SIGNING_FAILED, () -> sign(engine, text, pades,
                cmsFrom(rsa, EnumSet.noneOf(Cms.class)))), "no signing-time attribute");
        assertMessage(fails(DssError.Code.SIGNING_FAILED, () -> sign(engine, text, pades,
                p -> rsa.signatureValue(p.digestAlgorithm(), p.digest(), false))), "mode \"signature_value\"");
        assertMessage(fails(DssError.Code.SIGNING_FAILED, () -> sign(engine, text, pades,
                p -> Fixtures.read("cades/attached-der.p7m"))), "encapsulates content");
        assertMessage(fails(DssError.Code.SIGNING_FAILED, () -> sign(engine, text,
                options("{\"mode\":\"cms\",\"level\":\"B\",\"digest_algorithm\":\"SHA384\"}"),
                p -> rsa.cms(eu.europa.esig.dss.enumerations.DigestAlgorithm.SHA256, p.digest(),
                        EnumSet.of(Cms.SIGNING_TIME)))), "digest algorithm SHA256");
    }

    @Test
    void aCmsFromAnotherSignerIsRefusedWhenTheCertificateIsGiven() {
        SigningOptions o = options("{\"mode\":\"cms\",\"level\":\"B\",\"signing_certificate\":\""
                + certificate(Entity.SIGNER_RSA) + "\"}");
        assertMessage(fails(DssError.Code.SIGNING_FAILED, () -> sign(engine, pdf, o,
                cmsFrom(ec, EnumSet.noneOf(Cms.class)))), "not by the signing_certificate given");
        assertValidatesAs(engine, sign(engine, pdf, o, cmsFrom(rsa, EnumSet.noneOf(Cms.class))).document(), null,
                "PAdES-BASELINE-B");
    }

    @Test
    void aCmsLargerThanTheReservedSpaceIsRefused() {
        SigningOptions o = options("{\"mode\":\"cms\",\"level\":\"B\",\"pades\":{\"content_size\":2000}}");
        assertMessage(fails(DssError.Code.SIGNING_FAILED, () -> sign(engine, pdf, o,
                cmsFrom(rsa, EnumSet.of(Cms.TIMESTAMP, Cms.CHAIN)))), "larger 'pades.content_size'");
    }

    @Test
    void aSigningTimeOutsideTheCertificateIsRefusedAtPrepare() {
        SigningOptions o = options("{\"mode\":\"signature_value\",\"level\":\"B\",\"signing_time\":"
                + "\"2020-01-01T00:00:00Z\"," + certificates(Entity.SIGNER_RSA) + "}");
        fails(DssError.Code.SIGNING_FAILED, () -> engine.prepareSignature(pdf, o));
    }

    @Test
    void completeNeedsTheSigningTime() {
        SigningOptions o = options("{\"mode\":\"cms\",\"level\":\"B\"}");
        assertMessage(fails(DssError.Code.INVALID_ARGUMENT, () -> engine.completeSignature(pdf, o, new byte[] {1})),
                "'signing_time' is required");
        fails(DssError.Code.INVALID_ARGUMENT, () -> engine.completeSignature(pdf,
                o.withSigningTime(Instant.now()), new byte[0]));
    }

    @Test
    void timestampsNeedATsa() {
        SigningOptions o = options("{\"mode\":\"signature_value\",\"level\":\"T\","
                + certificates(Entity.SIGNER_RSA) + "}");
        assertMessage(fails(DssError.Code.SIGNING_FAILED, () -> sign(noTsa, pdf, o, valueFrom(rsa))),
                "no TSA is configured");
        // A CMS with its own signature timestamp needs none.
        SigningResult r = sign(noTsa, pdf, options("{\"mode\":\"cms\",\"level\":\"T\"}"),
                cmsFrom(rsa, EnumSet.of(Cms.TIMESTAMP)));
        assertValidatesAs(engine, r.document(), null, "PAdES-BASELINE-T");
    }

    @Test
    void onlyLtAndLtaNeedTheTrustedLists() {
        SigningOptions b = options("{\"mode\":\"signature_value\",\"level\":\"T\","
                + certificates(Entity.SIGNER_RSA) + "}");
        assertValidatesAs(engine, sign(noTrust, pdf, b, valueFrom(rsa)).document(), null, "PAdES-BASELINE-T");
        SigningOptions lt = options("{\"mode\":\"signature_value\",\"level\":\"LT\","
                + certificates(Entity.SIGNER_RSA) + "}");
        fails(DssError.Code.TRUSTED_LISTS_NOT_LOADED, () -> sign(noTrust, pdf, lt, valueFrom(rsa)));
    }

    @Test
    void unsuitableDocumentsAreRefused() {
        SigningOptions pades = options("{\"format\":\"PAdES\",\"mode\":\"cms\",\"level\":\"B\"}");
        fails(DssError.Code.UNSUPPORTED_DOCUMENT, () -> engine.prepareSignature(text, pades));
        fails(DssError.Code.INVALID_ARGUMENT, () -> engine.prepareSignature(new byte[0], pades));
        fails(DssError.Code.INVALID_ARGUMENT, () -> engine.prepareSignature(null, pades));
        // A PDF can be signed as CAdES too: detached, over its bytes.
        SigningResult r = sign(engine, pdf, options("{\"format\":\"cades\",\"mode\":\"cms\",\"level\":\"B\"}"),
                cmsFrom(rsa, EnumSet.of(Cms.SIGNING_TIME)));
        assertEquals("DETACHED", r.packaging());
        ValidationResult v = engine.validate(r.document(), new ValidationOptions(null,
                List.of(new InMemoryDocument(pdf, "document.pdf")), null, null, false));
        assertEquals(List.of(PASSED), FixtureValidationTest.verdicts(v));
    }

    @Test
    void optionsAreParsed() {
        SigningOptions o = options("{\"format\":\"cades\",\"mode\":\"SIGNATURE_VALUE\",\"level\":\"lta\","
                + "\"digest_algorithm\":\"sha384\",\"signing_time\":\"2026-06-01T10:00:00Z\",\"packaging\":"
                + "\"enveloping\",\"filename\":\"a.txt\"," + certificates(Entity.SIGNER_EC) + "}");
        assertEquals(SigningOptions.Format.CADES, o.format);
        assertEquals(SigningOptions.Mode.SIGNATURE_VALUE, o.mode);
        assertEquals(SigningOptions.Level.LTA, o.level);
        assertEquals("SHA384", o.digestAlgorithm.getName());
        assertEquals(SigningOptions.Packaging.ENVELOPING, o.packaging);
        assertEquals(t.pki.token(Entity.SIGNER_EC), o.signingCertificate);
        assertEquals(List.of(t.pki.token(Entity.ROOT_CA)), o.certificateChain);
        assertEquals(t.pki.token(Entity.SIGNER_EC), options("{\"mode\":\"cms\",\"level\":\"B\","
                + "\"signing_certificate\":\"" + t.pki.pem(Entity.SIGNER_EC).replace("\n", "\\n") + "\"}")
                .signingCertificate, "PEM works too");
        assertEquals(SigningOptions.DEFAULT_EXTERNAL_CMS_CONTENT_SIZE,
                options("{\"mode\":\"cms\",\"level\":\"B\"}").contentSizeOrDefault());

        for (String bad : List.of("{}", "{\"level\":\"B\"}", "{\"mode\":\"cms\"}", "{\"mode\":\"raw\",\"level\":\"B\"}",
                "{\"mode\":\"cms\",\"level\":\"C\"}", "{\"mode\":\"cms\",\"level\":\"B\",\"format\":\"XAdES\"}",
                "{\"mode\":\"cms\",\"level\":\"B\",\"digest_algorithm\":\"SHA1\"}",
                "{\"mode\":\"cms\",\"level\":\"B\",\"signing_time\":\"yesterday\"}",
                "{\"mode\":\"cms\",\"level\":\"B\",\"signing_time\":\"2026-06-01T10:00:00.5Z\"}",
                "{\"mode\":\"signature_value\",\"level\":\"B\"}",
                "{\"mode\":\"cms\",\"level\":\"B\",\"signing_certificate\":\"bm90IGEgY2VydA==\"}",
                "{\"mode\":\"cms\",\"level\":\"B\",\"format\":\"pades\",\"packaging\":\"detached\"}",
                "{\"mode\":\"cms\",\"level\":\"B\",\"format\":\"cades\",\"pades\":{}}",
                "{\"mode\":\"cms\",\"level\":\"B\",\"pades\":{\"content_size\":0}}",
                "{\"mode\":\"cms\",\"level\":\"B\",\"pades\":{\"visible\":true}}",
                "{\"mode\":\"cms\",\"level\":\"B\",\"reports\":[]}", "{mode")) {
            fails(DssError.Code.INVALID_ARGUMENT, () -> SigningOptions.fromJson(bad));
        }
        // Inferred format, explicit options that do not fit it.
        fails(DssError.Code.INVALID_ARGUMENT, () -> engine.prepareSignature(pdf,
                options("{\"mode\":\"cms\",\"level\":\"B\",\"packaging\":\"enveloping\"}")));
        fails(DssError.Code.INVALID_ARGUMENT, () -> engine.prepareSignature(text,
                options("{\"mode\":\"cms\",\"level\":\"B\",\"pades\":{\"reason\":\"x\"}}")));
    }

    // ------------------------------------------------------------------ what the external CMS must look like

    /** Every refusal of {@code complete} in mode "cms", each reported as SIGNING_FAILED with its reason. */
    @Test
    void everyFlawInAnExternalCmsIsRefusedWithItsReason() {
        SigningOptions o = options("{\"mode\":\"cms\",\"level\":\"B\"}");
        record Case(Tamper tamper, String reason) { }
        for (Case c : List.of(
                new Case(Tamper.UNPARSEABLE, "cannot be parsed"),
                new Case(Tamper.TWO_SIGNERS, "2 signers"),
                new Case(Tamper.NO_SIGNED_ATTRIBUTES, "no signed attributes"),
                new Case(Tamper.NO_CONTENT_TYPE, "content-type attribute with value id-data"),
                new Case(Tamper.EMPTY_CONTENT_TYPE, "content-type attribute has 0 values"),
                new Case(Tamper.NO_MESSAGE_DIGEST, "no message-digest attribute"),
                new Case(Tamper.EMPTY_MESSAGE_DIGEST, "message-digest attribute has 0 values"),
                new Case(Tamper.NO_SIGNING_CERTIFICATE, "no signing-certificate-v2 (or signing-certificate)"),
                new Case(Tamper.WRONG_SIGNING_CERTIFICATE_HASH, "certificate hash differs"),
                new Case(Tamper.NO_CERTIFICATE, "does not contain its signer's certificate"),
                new Case(Tamper.BROKEN_SIGNATURE, "does not verify with its signer's certificate"),
                new Case(Tamper.SHA1_SIGNATURE, "RSA with SHA1, the options say SHA256"),
                new Case(Tamper.BOGUS_TIMESTAMP, "does not hold a timestamp token"),
                new Case(Tamper.FOREIGN_TIMESTAMP, "message imprint does not match"),
                new Case(Tamper.EXTRA_UNSIGNED_ATTRIBUTE, "unsigned attribute certificate-values"),
                new Case(Tamper.WRONG_SERIAL, "names serial number"),
                new Case(Tamper.WRONG_ISSUER, "names another issuer"),
                new Case(Tamper.NO_CERTIFICATE_REFERENCED, "references no certificate"),
                new Case(Tamper.UNKNOWN_CERTIFICATE_HASH_ALGORITHM, "unsupported algorithm (1.2.3.4)"),
                new Case(Tamper.MALFORMED_SIGNING_CERTIFICATE, "the external CMS is malformed"),
                new Case(Tamper.DUPLICATE_ATTRIBUTE, "2 content-type attributes"),
                new Case(Tamper.WRONG_KEY, "but the signer's certificate holds a"),
                new Case(Tamper.UNKNOWN_SIGNATURE_ALGORITHM, "unsupported signature algorithm (1.2.3.4.5)"),
                new Case(Tamper.BROKEN_TIMESTAMP_SIGNATURE, "does not verify with any certificate in the token or the CMS"),
                new Case(Tamper.TIMESTAMP_WITHOUT_TSA_CERTIFICATE,
                        "does not verify with any certificate in the token or the CMS"),
                new Case(Tamper.TWO_TIMESTAMPS, "two signature-time-stamp attributes"))) {
            DssError e = fails(DssError.Code.SIGNING_FAILED, () -> sign(engine, pdf, o,
                    p -> rsa.cms(p.digestAlgorithm(), p.digest(), EnumSet.noneOf(Cms.class), c.tamper())));
            assertMessage(e, c.reason());
            // The same shapes from an ECDSA signer, over content (CAdES).
            DssError cades = fails(DssError.Code.SIGNING_FAILED, () -> sign(engine, text, o,
                    p -> ec.cms(p.digestAlgorithm(), p.digest(), EnumSet.of(Cms.SIGNING_TIME), c.tamper())));
            assertMessage(cades, c.tamper() == Tamper.SHA1_SIGNATURE ? "ECDSA with SHA1" : c.reason());
        }
    }

    @Test
    void aV1SigningCertificateAttributeIsAccepted() {
        SigningResult r = sign(engine, pdf, options("{\"mode\":\"cms\",\"level\":\"B\"}"),
                p -> rsa.cms(p.digestAlgorithm(), p.digest(), EnumSet.noneOf(Cms.class), Tamper.SIGNING_CERTIFICATE_V1));
        assertValidatesAs(engine, r.document(), null, "PAdES-BASELINE-B");
    }

    /** A signature timestamp the CMS brings is trusted only once it has been verified; a bad one is not T. */
    @Test
    void aBrokenSignatureTimestampInTheCmsIsRefusedBeforeAnyTimestampIsSpent() {
        for (String level : List.of("B", "T", "LT")) {
            SigningOptions o = options("{\"mode\":\"cms\",\"level\":\"" + level + "\"}");
            int hits = tsaHits();
            for (Tamper tamper : List.of(Tamper.BOGUS_TIMESTAMP, Tamper.FOREIGN_TIMESTAMP)) {
                fails(DssError.Code.SIGNING_FAILED, () -> sign(engine, pdf, o,
                        p -> rsa.cms(p.digestAlgorithm(), p.digest(), EnumSet.noneOf(Cms.class), tamper)));
                fails(DssError.Code.SIGNING_FAILED, () -> sign(engine, text, o,
                        p -> rsa.cms(p.digestAlgorithm(), p.digest(), EnumSet.of(Cms.SIGNING_TIME), tamper)));
            }
            assertEquals(hits, tsaHits(), "nothing was timestamped at level " + level);
        }
    }

    // ------------------------------------------------------------------ the signing certificate

    @Test
    void cmsModeChecksTheCertificateValidityAtTheSigningTime() {
        // Given up front, the certificate is checked at prepare, in both formats.
        for (byte[] document : List.of(pdf, text)) {
            SigningOptions given = options("{\"mode\":\"cms\",\"level\":\"B\",\"signing_time\":"
                    + "\"2020-01-01T00:00:00Z\",\"signing_certificate\":\"" + certificate(Entity.SIGNER_RSA) + "\"}");
            assertMessage(fails(DssError.Code.SIGNING_FAILED, () -> engine.prepareSignature(document, given)),
                    "not yet valid at the signing time 2020-01-01T00:00:00Z");
        }
        // Known only from the CMS, it is checked at complete: for PAdES at the options' signing time ...
        SigningOptions pades = options("{\"mode\":\"cms\",\"level\":\"B\",\"signing_time\":\"2020-01-01T00:00:00Z\"}");
        PreparedSignature prepared = engine.prepareSignature(pdf, pades);
        byte[] cms = rsa.cms(prepared.digestAlgorithm(), prepared.digest(), EnumSet.noneOf(Cms.class));
        assertMessage(fails(DssError.Code.SIGNING_FAILED, () -> engine.completeSignature(pdf, pades, cms)),
                "not yet valid at the signing time 2020-01-01T00:00:00Z");
        // ... for CAdES at the time the CMS's own signing-time attribute claims.
        SigningOptions cades = options("{\"mode\":\"cms\",\"level\":\"B\"}");
        assertMessage(fails(DssError.Code.SIGNING_FAILED, () -> sign(engine, text, cades,
                p -> rsa.cms(p.digestAlgorithm(), p.digest(), EnumSet.of(Cms.SIGNING_TIME), Tamper.OLD_SIGNING_TIME))),
                "not yet valid at the signing time 2020-01-01T00:00:00Z");
    }

    @Test
    void certificatesNotMeantForSigningDocumentsAreRefused() {
        // Mode "signature_value": at prepare, before the signer is asked anything.
        SigningOptions caValue = options("{\"mode\":\"signature_value\",\"level\":\"B\"," + certificates(Entity.ROOT_CA)
                + "}");
        assertMessage(fails(DssError.Code.SIGNING_FAILED, () -> engine.prepareSignature(pdf, caValue)),
                "is a CA certificate");
        SigningOptions tsaValue = options("{\"mode\":\"signature_value\",\"level\":\"B\"," + certificates(Entity.TSA)
                + "}");
        assertMessage(fails(DssError.Code.SIGNING_FAILED, () -> engine.prepareSignature(text, tsaValue)),
                "extended key usage (timeStamping)");
        // Mode "cms": at prepare when the certificate is given, otherwise on the certificate in the CMS.
        SigningOptions caGiven = options("{\"mode\":\"cms\",\"level\":\"B\",\"signing_certificate\":\""
                + certificate(Entity.ROOT_CA) + "\"}");
        assertMessage(fails(DssError.Code.SIGNING_FAILED, () -> engine.prepareSignature(pdf, caGiven)),
                "is a CA certificate");
        SigningOptions cms = options("{\"mode\":\"cms\",\"level\":\"LT\"}");
        int hits = tsaHits();
        assertMessage(fails(DssError.Code.SIGNING_FAILED, () -> sign(engine, pdf, cms,
                cmsFrom(ca, EnumSet.noneOf(Cms.class)))), "is a CA certificate");
        assertMessage(fails(DssError.Code.SIGNING_FAILED, () -> sign(engine, text, cms,
                cmsFrom(tsa, EnumSet.of(Cms.SIGNING_TIME)))), "extended key usage (timeStamping)");
        assertEquals(hits, tsaHits(), "refused before any timestamp was requested");
    }

    // ------------------------------------------------------------------ what prepare refuses up front

    /**
     * From T up (in mode "cms"; LT up in both modes) DSS re-checks the PDF's existing signatures when it extends
     * the document, after the new signature is in. prepare runs those checks first, so the external signature is
     * not spent on a PDF complete would refuse.
     */
    @Test
    void aPdfWhoseExistingSignaturesCompleteWouldRefuseIsRefusedAtPrepare() {
        byte[] tampered = Fixtures.read("tampered/pades/b-b.pdf");
        for (String level : List.of("T", "LT", "LTA")) {
            SigningOptions cms = options("{\"mode\":\"cms\",\"level\":\"" + level + "\"}");
            assertMessage(fails(DssError.Code.SIGNING_FAILED, () -> engine.prepareSignature(tampered, cms)),
                    "existing signatures cannot be extended to " + level);
        }
        for (String level : List.of("LT", "LTA")) {
            SigningOptions value = options("{\"mode\":\"signature_value\",\"level\":\"" + level + "\","
                    + certificates(Entity.SIGNER_RSA) + "}");
            assertMessage(fails(DssError.Code.SIGNING_FAILED, () -> engine.prepareSignature(tampered, value)),
                    "existing signatures cannot be extended to " + level);
        }
        // At B nothing is extended; at T in mode "signature_value" the timestamp goes into the new CMS only.
        SigningResult b = sign(engine, tampered, options("{\"mode\":\"cms\",\"level\":\"B\"}"),
                cmsFrom(rsa, EnumSet.noneOf(Cms.class)));
        assertEquals("PAdES-BASELINE-B", b.level().toString());
        SigningResult t = sign(engine, tampered, options("{\"mode\":\"signature_value\",\"level\":\"T\","
                + certificates(Entity.SIGNER_RSA) + "}"), valueFrom(rsa));
        assertEquals("PAdES-BASELINE-T", t.level().toString());

        // A PDF whose signature is sound is co-signed, and every signature ends up at LT.
        byte[] signedOnce = Fixtures.read("pades/b-b.pdf");
        SigningResult lt = sign(engine, signedOnce, options("{\"mode\":\"cms\",\"level\":\"LT\"}"),
                cmsFrom(rsa, EnumSet.noneOf(Cms.class)));
        ValidationResult v = validate(engine, lt.document(), null);
        assertEquals(List.of(PASSED, PASSED), FixtureValidationTest.verdicts(v), () -> v.reports.get(ReportKind.SIMPLE));
        v.signatures.forEach(s -> assertEquals("PAdES-BASELINE-LT", s.format().toString()));

        // Existing signatures already at T, mode "signature_value" (the new CMS brings its own timestamp): DSS adds
        // no document timestamp first and only re-checks that the signatures verify, as prepare does.
        byte[] tamperedT = Fixtures.read("tampered/pades/b-t.pdf");
        SigningOptions valueLt = options("{\"mode\":\"signature_value\",\"level\":\"LT\","
                + certificates(Entity.SIGNER_RSA) + "}");
        assertMessage(fails(DssError.Code.SIGNING_FAILED, () -> engine.prepareSignature(tamperedT, valueLt)),
                "existing signatures cannot be extended to LT");
        SigningResult coSigned = sign(engine, Fixtures.read("pades/b-t.pdf"), valueLt, valueFrom(rsa));
        ValidationResult vt = validate(engine, coSigned.document(), null);
        assertEquals(List.of(PASSED, PASSED), FixtureValidationTest.verdicts(vt),
                () -> vt.reports.get(ReportKind.SIMPLE));
        vt.signatures.forEach(s -> assertEquals("PAdES-BASELINE-LT", s.format().toString()));
    }

    @Test
    void aContentSizeTheCmsCannotFitIsRefusedAtPrepare() {
        SigningOptions small = options("{\"mode\":\"signature_value\",\"level\":\"B\",\"pades\":{\"content_size\":500},"
                + certificates(Entity.SIGNER_RSA) + "}");
        assertMessage(fails(DssError.Code.INVALID_ARGUMENT, () -> engine.prepareSignature(pdf, small)),
                "'pades.content_size' is 500 bytes, but the CMS");
        // The estimate is a lower bound: what passes it is signed.
        SigningOptions enough = options("{\"mode\":\"signature_value\",\"level\":\"B\",\"pades\":{\"content_size\":4000},"
                + certificates(Entity.SIGNER_RSA) + "}");
        assertValidatesAs(engine, sign(engine, pdf, enough, valueFrom(rsa)).document(), null, "PAdES-BASELINE-B");
    }

    /**
     * The estimate counts the certificates DSS embeds, selected as DSS selects them: the chain from the signing
     * certificate up to the trust anchor (which is left out), and nothing off that path. So a content_size the
     * real CMS fits is never refused, whatever else the chain carries.
     */
    @Test
    void theContentSizeEstimateCountsOnlyTheCertificatesDssEmbeds() {
        // The chain carries the root (the trust anchor) and a certificate that is not on the signer's path at all.
        String chain = "\"signing_certificate\":\"" + certificate(Entity.SIGNER_RSA) + "\",\"certificate_chain\":[\""
                + certificate(Entity.ROOT_CA) + "\",\"" + certificate(Entity.TL_SIGNER) + "\"]";
        Function<Integer, SigningOptions> with = size -> options("{\"mode\":\"signature_value\",\"level\":\"B\","
                + "\"pades\":{\"content_size\":" + size + "}," + chain + "}");
        int real = cmsLength(sign(engine, pdf, with.apply(20000), valueFrom(rsa)).document());
        // Exactly the real size fits, although the chain holds two certificates DSS leaves out of the CMS.
        SigningResult tight = sign(engine, pdf, with.apply(real), valueFrom(rsa));
        assertValidatesAs(engine, tight.document(), null, "PAdES-BASELINE-B");
        // The estimate is tighter than the length of the off-path certificate: that much less is refused.
        int offPath = t.pki.token(Entity.TL_SIGNER).getEncoded().length;
        assertMessage(fails(DssError.Code.INVALID_ARGUMENT, () -> engine.prepareSignature(pdf, with.apply(real - offPath))),
                "but the CMS DSS builds around the signature value will be at least");
    }

    /** The DER length of the CMS in the last signature of {@code signedPdf} (its /Contents, zero-padded by DSS). */
    private static int cmsLength(byte[] signedPdf) {
        Matcher m = Pattern.compile("/Contents\\s*<([0-9A-Fa-f]+)>")
                .matcher(new String(signedPdf, StandardCharsets.ISO_8859_1));
        String hex = null;
        while (m.find()) {
            hex = m.group(1);
        }
        assertNotNull(hex, "a /Contents entry");
        try (ASN1InputStream in = new ASN1InputStream(Hex.decode(hex))) {
            return in.readObject().getEncoded(ASN1Encoding.DER).length;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** PAdES level T: mode "cms" adds a document timestamp, mode "signature_value" a signature timestamp. */
    @Test
    void padesLevelTTimestampKindDependsOnTheMode() {
        SigningResult cms = sign(engine, pdf, options("{\"mode\":\"cms\",\"level\":\"T\"}"),
                cmsFrom(rsa, EnumSet.noneOf(Cms.class)));
        assertTrue(appended(cms).contains("/DocTimeStamp"), "cms: a document timestamp revision");
        SigningResult value = sign(engine, pdf, options("{\"mode\":\"signature_value\",\"level\":\"T\","
                + certificates(Entity.SIGNER_RSA) + "}"), valueFrom(rsa));
        assertFalse(appended(value).contains("/DocTimeStamp"), "signature_value: the timestamp is inside the CMS");
        assertValidatesAs(engine, value.document(), null, "PAdES-BASELINE-T");
    }

    private String appended(SigningResult r) {
        return new String(r.document(), pdf.length, r.document().length - pdf.length, StandardCharsets.ISO_8859_1);
    }
}
