/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.signature.PAdESSignatureRequirementsChecker;
import eu.europa.esig.dss.pades.signature.PAdESWithExternalCMSService;
import eu.europa.esig.dss.pades.validation.PDFDocumentAnalyzer;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.BaselineBCertificateSelector;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

import it.codingduck.dssnative.engine.SigningOptions.Format;
import it.codingduck.dssnative.engine.SigningOptions.Level;
import it.codingduck.dssnative.engine.SigningOptions.Mode;
import it.codingduck.dssnative.engine.SigningOptions.Packaging;
import it.codingduck.dssnative.visible.VisibleImageParameters;

/**
 * Signing with a key held elsewhere, with DSS building the signed document. Two stateless steps: {@link #prepare}
 * computes the digest the external signer signs; {@link #complete} redoes that work from the same document and
 * options and builds the signed document from what the signer returned, after checking that it signs exactly
 * this digest. Nothing is kept between the calls, so the signer may take as long as it needs.
 *
 * <p>For PAdES this relies on DSS preparing the same PDF twice: the signature dictionary, the {@code /Contents}
 * placeholder and the document ID follow from the options, the signing time and the document name alone, never
 * from the host (the signing date is written in UTC, whatever the host's time zone).
 *
 * <p>Everything {@code complete} would refuse that can be known before the external signature is spent is
 * refused at {@code prepare}: an unsuitable signing certificate (when given), a {@code pades.content_size} the
 * CMS DSS builds cannot fit, and existing PDF signatures that DSS would reject when it extends the document
 * (checked whenever the requested level may extend it; see {@link #assertExistingSignaturesExtendable}).
 */
final class ExternalSigning {

    private static final TimeZone UTC = TimeZone.getTimeZone("UTC");
    /**
     * Lower bound for the CMS framing DSS adds around the signed attributes, the signature value and the
     * certificates (ContentInfo, SignedData, SignerInfo, algorithm identifiers, tags and lengths).
     */
    private static final int CMS_FRAMING_MIN = 64;

    private final CertificateVerifier verifier;
    private final TSPSource tspSource;
    private final IPdfObjFactory pdfObjFactory;

    /** @param tspSource never null: a stand-in that fails clearly when no TSA is configured */
    ExternalSigning(CertificateVerifier verifier, TSPSource tspSource, IPdfObjFactory pdfObjFactory) {
        this.verifier = verifier;
        this.tspSource = tspSource;
        this.pdfObjFactory = pdfObjFactory;
    }

    static Format format(byte[] document, SigningOptions options) {
        boolean pdf = InputNormalizer.sniff(document) == InputNormalizer.Type.PDF;
        Format format = options.format != null ? options.format : (pdf ? Format.PADES : Format.CADES);
        if (format == Format.PADES && !pdf) {
            throw new DssError(DssError.Code.UNSUPPORTED_DOCUMENT, "PAdES needs a PDF document");
        }
        if (format == Format.PADES && options.packaging != null) {
            throw new DssError(DssError.Code.INVALID_ARGUMENT,
                    "options: 'packaging' applies to CAdES only (a PAdES signature is always inside the PDF)");
        }
        if (format == Format.CADES && (options.reason != null || options.location != null
                || options.contactInfo != null || options.signerName != null || options.contentSize != null
                || options.visible != null)) {
            throw new DssError(DssError.Code.INVALID_ARGUMENT, "options: 'pades' applies to PAdES only");
        }
        return format;
    }

    PreparedSignature prepare(byte[] document, SigningOptions options) {
        Format format = format(document, options);
        Instant time = options.signingTime != null ? options.signingTime
                : Instant.now().truncatedTo(ChronoUnit.SECONDS);
        SigningOptions o = options.withSigningTime(time);
        if (o.signingCertificate != null) {
            SigningCertificateCheck.assertSuitable(o.signingCertificate, time);
        }
        DSSDocument doc = document(document, o, format);

        if (format == Format.PADES) {
            PAdESSignatureParameters parameters = padesParameters(o, visible(document, o));
            assertExistingSignaturesExtendable(doc, o, parameters);
            if (o.mode == Mode.CMS) {
                byte[] digest = externalCmsService().getMessageDigest(doc, parameters).getValue();
                return new PreparedSignature(format, o.digestAlgorithm, digest, null, time);
            }
            ToBeSigned tbs = padesService().getDataToSign(doc, parameters);
            assertContentSizeFits(o, parameters, tbs);
            return prepared(format, o, tbs, time);
        }
        if (o.mode == Mode.CMS) {
            return new PreparedSignature(format, o.digestAlgorithm, DSSUtils.digest(o.digestAlgorithm, document), null,
                    time);
        }
        return prepared(format, o, cadesService().getDataToSign(doc, cadesParameters(o)), time);
    }

    private static PreparedSignature prepared(Format format, SigningOptions o, ToBeSigned tbs, Instant time) {
        return new PreparedSignature(format, o.digestAlgorithm, DSSUtils.digest(o.digestAlgorithm, tbs.getBytes()),
                tbs.getBytes(), time);
    }

    SigningResult complete(byte[] document, SigningOptions o, byte[] external) {
        Format format = format(document, o);
        if (o.signingTime == null && (format == Format.PADES || o.mode == Mode.SIGNATURE_VALUE)) {
            throw new DssError(DssError.Code.INVALID_ARGUMENT,
                    "options: 'signing_time' is required to complete: pass the one prepare returned");
        }
        if (o.signingCertificate != null) {
            SigningCertificateCheck.assertSuitable(o.signingCertificate, o.signingTime);
        }
        DSSDocument doc = document(document, o, format);
        VisibleImageParameters visible = format == Format.PADES ? visible(document, o) : null;
        if (o.mode == Mode.CMS) {
            return format == Format.PADES ? padesFromCms(doc, o, visible, external)
                    : cadesFromCms(doc, document, o, external);
        }
        SignatureValue value = signatureValue(external, o);
        if (format == Format.PADES) {
            PAdESService service = padesService();
            PAdESSignatureParameters parameters = padesParameters(o, visible);
            ToBeSigned tbs = service.getDataToSign(doc, parameters);
            assertContentSizeFits(o, parameters, tbs);
            assertSignatureValueValid(service.isValidSignatureValue(tbs, value, o.signingCertificate));
            DSSDocument signed = service.signDocument(doc, parameters, value);
            return new SigningResult(DSSUtils.toByteArray(signed), format, o.level.pades, "ENVELOPED");
        }
        CAdESService service = cadesService();
        CAdESSignatureParameters parameters = cadesParameters(o);
        assertSignatureValueValid(service.isValidSignatureValue(service.getDataToSign(doc, parameters), value,
                o.signingCertificate));
        DSSDocument signed = service.signDocument(doc, parameters, value);
        return new SigningResult(DSSUtils.toByteArray(signed), format, o.level.cades,
                parameters.getSignaturePackaging().name());
    }

    // ------------------------------------------------------------------ mode "cms"

    private SigningResult padesFromCms(DSSDocument doc, SigningOptions o, VisibleImageParameters visible,
                                       byte[] external) {
        PAdESWithExternalCMSService service = externalCmsService();
        // One parameters object for both calls: DSS keeps the prepared PDF in it, so signing splices the CMS into
        // the placeholder instead of preparing the PDF a second time.
        PAdESSignatureParameters parameters = padesParameters(o, visible);
        byte[] digest = service.getMessageDigest(doc, parameters).getValue();
        ExternalCms.Checked checked = ExternalCms.check(external, Format.PADES, o, digest);
        SigningCertificateCheck.assertSuitable(checked.signerCertificate(), o.signingTime);
        byte[] der = checked.cms().getDEREncoded();
        int reserved = o.contentSizeOrDefault();
        if (der.length > reserved) {
            throw new DssError(DssError.Code.SIGNING_FAILED, "the CMS is " + der.length + " bytes, more than the "
                    + reserved + " reserved for it in the PDF: prepare and sign again with a larger "
                    + "'pades.content_size'");
        }
        // DSS embeds the CMS, then extends unless the level is B, or T and the CMS already has its timestamp.
        DSSDocument signed = service.signDocument(doc, parameters, new InMemoryDocument(der));
        return new SigningResult(DSSUtils.toByteArray(signed), Format.PADES,
                reached(o.level, checked.timestamped()).pades, "ENVELOPED");
    }

    private SigningResult cadesFromCms(DSSDocument doc, byte[] content, SigningOptions o, byte[] external) {
        ExternalCms.Checked checked = ExternalCms.check(external, Format.CADES, o,
                DSSUtils.digest(o.digestAlgorithm, content));
        // For CAdES the CMS carries the time it claims (the signing-time attribute); the options' signing_time is
        // not part of the digest, so the certificate is checked at the time the signature itself states.
        SigningCertificateCheck.assertSuitable(checked.signerCertificate(), checked.claimedSigningTime());
        Packaging packaging = o.packaging != null ? o.packaging : Packaging.DETACHED;
        byte[] der = checked.cms().getDEREncoded();
        if (packaging == Packaging.ENVELOPING) {
            der = encapsulate(der, content);
        }
        DSSDocument signed = new InMemoryDocument(der, doc.getName() + (packaging == Packaging.ENVELOPING ? ".p7m"
                : ".p7s"));
        boolean timestamped = checked.timestamped();
        if (o.level == Level.LT || o.level == Level.LTA || (o.level == Level.T && !timestamped)) {
            CAdESSignatureParameters parameters = new CAdESSignatureParameters();
            parameters.setSignatureLevel(o.level.cades);
            parameters.setSignaturePackaging(packaging == Packaging.ENVELOPING ? SignaturePackaging.ENVELOPING
                    : SignaturePackaging.DETACHED);
            parameters.setDigestAlgorithm(o.digestAlgorithm);
            if (packaging == Packaging.DETACHED) {
                parameters.setDetachedContents(List.of(doc));
            }
            signed = cadesService().extendDocument(signed, parameters);
        }
        return new SigningResult(DSSUtils.toByteArray(signed), Format.CADES, reached(o.level, timestamped).cades,
                packaging.name());
    }

    /** At B, an external CMS that already carries a signature timestamp is a T signature. */
    private static Level reached(Level requested, boolean timestamped) {
        return requested == Level.B && timestamped ? Level.T : requested;
    }

    /** A detached DER CMS with {@code content} put into encapContentInfo: the signature covers it unchanged. */
    static byte[] encapsulate(byte[] detachedDer, byte[] content) {
        try {
            ContentInfo ci = ContentInfo.getInstance(detachedDer);
            SignedData sd = SignedData.getInstance(ci.getContent());
            ContentInfo eci = new ContentInfo(CMSObjectIdentifiers.data, new DEROctetString(content));
            SignedData attached = new SignedData(sd.getDigestAlgorithms(), eci, sd.getCertificates(), sd.getCRLs(),
                    sd.getSignerInfos());
            return new DERSequence(new ASN1Encodable[] {
                    CMSObjectIdentifiers.signedData, new DERTaggedObject(true, 0, attached)})
                    .getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            throw failed("cannot put the content into the CMS: " + e.getMessage());
        }
    }

    // ------------------------------------------------------------------ mode "signature_value"

    /**
     * The external signature value for the signing certificate's key. Base64 text is decoded. For ECDSA keys both
     * the DER {@code SEQUENCE {r, s}} and the plain {@code r||s} concatenation are accepted.
     */
    private static SignatureValue signatureValue(byte[] external, SigningOptions o) {
        byte[] value = external;
        byte[] decoded = InputNormalizer.decodeText(external);
        if (decoded != null) {
            value = decoded;
        }
        EncryptionAlgorithm encryption;
        try {
            encryption = EncryptionAlgorithm.forKey(o.signingCertificate.getPublicKey());
        } catch (RuntimeException e) {
            throw new DssError(DssError.Code.INVALID_ARGUMENT, "options: unsupported key in 'signing_certificate': "
                    + e.getMessage());
        }
        SignatureAlgorithm algorithm = SignatureAlgorithm.getAlgorithm(encryption, o.digestAlgorithm);
        if (algorithm == null) {
            throw new DssError(DssError.Code.INVALID_ARGUMENT, "options: no signature algorithm for a "
                    + encryption.getName() + " key with " + o.digestAlgorithm.getName());
        }
        if (EncryptionAlgorithm.ECDSA.equals(encryption) && !isDerEcdsa(value)) {
            SignatureAlgorithm plain = SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.PLAIN_ECDSA,
                    o.digestAlgorithm);
            return DSSUtils.convertECSignatureValue(algorithm, new SignatureValue(plain, value));
        }
        return new SignatureValue(algorithm, value);
    }

    private static boolean isDerEcdsa(byte[] value) {
        try {
            ASN1Sequence seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(value));
            return seq.size() == 2 && seq.getObjectAt(0) instanceof ASN1Integer
                    && seq.getObjectAt(1) instanceof ASN1Integer;
        } catch (IOException | RuntimeException e) {
            return false;
        }
    }

    private static void assertSignatureValueValid(boolean valid) {
        if (!valid) {
            throw failed("the signature value does not verify with the signing certificate over this document's "
                    + "data to be signed: prepare and complete need the same document and options, including "
                    + "signing_time, and the signer must use the signing certificate's key");
        }
    }

    /**
     * In mode {@code "signature_value"} DSS builds the CMS and checks only when it writes it that it fits
     * {@code pades.content_size}; by then the external signature is spent. This estimates a lower bound of the
     * CMS size (the signed attributes, the signature value, the certificates DSS will include and the CMS framing)
     * and refuses a size that cannot fit. The signature timestamp of level T is not part of the estimate: its
     * size depends on the TSA.
     */
    private void assertContentSizeFits(SigningOptions o, PAdESSignatureParameters parameters, ToBeSigned tbs) {
        int reserved = o.contentSizeOrDefault();
        int atLeast = estimatedCmsSize(o, parameters, tbs);
        if (atLeast > reserved) {
            throw new DssError(DssError.Code.INVALID_ARGUMENT, "options: 'pades.content_size' is " + reserved
                    + " bytes, but the CMS DSS builds around the signature value will be at least " + atLeast
                    + " (signed attributes, signature value and certificates"
                    + (o.level != Level.B ? ", before the timestamp" : "") + "): raise it, or leave the default "
                    + SigningOptions.DEFAULT_CONTENT_SIZE);
        }
    }

    private int estimatedCmsSize(SigningOptions o, PAdESSignatureParameters parameters, ToBeSigned tbs) {
        // The certificates DSS embeds, selected as its CMS builder selects them: the chain from the signing
        // certificate up to the first trust anchor (left out under the B-level trust anchor policy, with whatever is
        // above it); a certificate of the chain that is not on that path is left out too.
        List<CertificateToken> included = new BaselineBCertificateSelector(parameters.getSigningCertificate(),
                parameters.getCertificateChain())
                .setTrustedCertificateSource(verifier.getTrustedCertSources())
                .setTrustAnchorBPPolicy(parameters.bLevel().isTrustAnchorBPPolicy())
                .getCertificates();
        int size = tbs.getBytes().length + minimalSignatureValueSize(o.signingCertificate.getPublicKey())
                + CMS_FRAMING_MIN;
        for (CertificateToken c : included) {
            size += c.getEncoded().length;
        }
        return size;
    }

    /** A lower bound of the signature value's length: exact for RSA, small for ECDSA (whose DER length varies). */
    private static int minimalSignatureValueSize(PublicKey key) {
        if (key instanceof RSAPublicKey rsa) {
            return (rsa.getModulus().bitLength() + 7) / 8;
        }
        if (key instanceof ECPublicKey ec) {
            return 2 * ((ec.getParams().getCurve().getField().getFieldSize() + 7) / 8 - 1);
        }
        return 0;
    }

    // ------------------------------------------------------------------ the PDF's other signatures

    /**
     * When DSS extends the PDF after embedding the new signature (mode {@code "cms"} from T up, where it adds the
     * document timestamp the new signature needs; mode {@code "signature_value"} from LT up) it re-checks every
     * signature already in the PDF and refuses a broken one, one whose certificate had expired without proof of
     * time, or one already at a higher level. {@code prepare} runs the same checks (with the same verifier and
     * alerts, without fetching revocation data) whenever the requested level may extend the document, so that no
     * external signature is spent on a document {@code complete} would refuse.
     *
     * <p>Which checks DSS runs depends on whether the PDF needs a document timestamp first. It does when any
     * signature in it lacks a T profile: {@code PAdESLevelBaselineT} then asserts that T is the highest level, that
     * the signatures verify and that their signing certificates are valid. Otherwise {@code PAdESLevelBaselineLT}
     * asserts that LT is the highest level (at LT) and that the signatures verify; their chains it checks with
     * revocation data, which {@code prepare} does not fetch, so that stays with {@code complete}. In mode
     * {@code "cms"} the new signature is itself at B when DSS extends, so the PDF always needs the document
     * timestamp and the first set applies; at T this is checked even when the signer's CMS turns out to carry its
     * own timestamp (then {@code complete} does not extend at all), the one case where {@code prepare} is stricter.
     * In mode {@code "signature_value"} the new CMS brings its own signature timestamp, so the existing signatures
     * decide, as they do at {@code complete}.
     */
    private void assertExistingSignaturesExtendable(DSSDocument doc, SigningOptions o,
                                                    PAdESSignatureParameters parameters) {
        boolean extended = o.level == Level.LT || o.level == Level.LTA || (o.level == Level.T && o.mode == Mode.CMS);
        if (!extended) {
            return;
        }
        PDFDocumentAnalyzer analyzer = new PDFDocumentAnalyzer(doc);
        analyzer.setPdfObjFactory(pdfObjFactory);
        analyzer.setCertificateVerifier(verifier);
        List<AdvancedSignature> signatures = analyzer.getSignatures();
        if (signatures.isEmpty()) {
            return;
        }
        boolean documentTimestampFirst = o.mode == Mode.CMS || signatures.stream().anyMatch(s -> !s.hasTProfile());
        PAdESSignatureRequirementsChecker checker = new PAdESSignatureRequirementsChecker(verifier, parameters);
        try {
            if (documentTimestampFirst) {
                // What PAdESLevelBaselineT asserts before it adds the document timestamp.
                checker.assertExtendToTLevelPossible(signatures);
                checker.assertSignaturesValid(signatures);
                checker.assertSigningCertificateIsValid(signatures);
            } else {
                // What PAdESLevelBaselineLT asserts without one, short of the chain validity (revocation data).
                if (o.level == Level.LT) {
                    checker.assertExtendToLTLevelPossible(signatures);
                }
                checker.assertSignaturesValid(signatures);
            }
        } catch (AlertException | IllegalInputException e) {
            throw failed("the PDF's existing signatures cannot be extended to " + o.level + " together with the new "
                    + "one, so complete would refuse it: " + e.getMessage());
        }
    }

    // ------------------------------------------------------------------ DSS plumbing

    private static DSSDocument document(byte[] document, SigningOptions o, Format format) {
        String name = o.filename != null ? o.filename : (format == Format.PADES ? "document.pdf" : "document");
        return new InMemoryDocument(document, name);
    }

    /**
     * The appearance of a visible signature, placed in this PDF. Resolved once per call: it opens the PDF to find
     * the page or field, and checks the caller's page, box and field before DSS sees them.
     */
    private static VisibleImageParameters visible(byte[] pdf, SigningOptions o) {
        if (o.visible == null) {
            return null;
        }
        return VisibleImageParameters.of(pdf, o.visible.appearance(o.signerName, o.reason, o.location,
                o.signingCertificate, o.signingTime));
    }

    private PAdESSignatureParameters padesParameters(SigningOptions o, VisibleImageParameters visible) {
        PAdESSignatureParameters p = new PAdESSignatureParameters();
        p.setSignatureLevel(o.level.pades);
        p.setDigestAlgorithm(o.digestAlgorithm);
        p.bLevel().setSigningDate(Date.from(o.signingTime));
        // The /M date is written in this zone (DSS defaults to the host's): fix it, or prepare and complete on
        // hosts in different zones build different PDFs and the signature does not match.
        p.setSigningTimeZone(UTC);
        p.setContentSize(o.contentSizeOrDefault());
        p.setReason(o.reason);
        p.setLocation(o.location);
        p.setContactInfo(o.contactInfo);
        p.setSignerName(o.signerName);
        if (visible != null) {
            p.setImageParameters(visible);
        }
        if (o.mode == Mode.SIGNATURE_VALUE) {
            p.setSigningCertificate(o.signingCertificate);
            p.setCertificateChain(o.certificateChain);
        }
        return p;
    }

    private static CAdESSignatureParameters cadesParameters(SigningOptions o) {
        CAdESSignatureParameters p = new CAdESSignatureParameters();
        p.setSignatureLevel(o.level.cades);
        p.setSignaturePackaging(o.packaging == Packaging.ENVELOPING ? SignaturePackaging.ENVELOPING
                : SignaturePackaging.DETACHED);
        p.setDigestAlgorithm(o.digestAlgorithm);
        // Sign the bytes given, also when they are a CMS (.p7m.p7m); never add a co-signer to them.
        p.setParallelSignature(false);
        p.bLevel().setSigningDate(Date.from(o.signingTime));
        p.setSigningCertificate(o.signingCertificate);
        p.setCertificateChain(o.certificateChain);
        return p;
    }

    private PAdESWithExternalCMSService externalCmsService() {
        PAdESWithExternalCMSService service = new PAdESWithExternalCMSService();
        service.setCertificateVerifier(verifier);
        service.setTspSource(tspSource);
        service.setPdfObjFactory(pdfObjFactory);
        return service;
    }

    private PAdESService padesService() {
        PAdESService service = new PAdESService(verifier);
        service.setTspSource(tspSource);
        service.setPdfObjFactory(pdfObjFactory);
        return service;
    }

    private CAdESService cadesService() {
        CAdESService service = new CAdESService(verifier);
        service.setTspSource(tspSource);
        return service;
    }

    private static DssError failed(String message) {
        return new DssError(DssError.Code.SIGNING_FAILED, message);
    }
}
