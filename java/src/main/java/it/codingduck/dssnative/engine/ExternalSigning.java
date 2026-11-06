/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import java.io.IOException;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.SignerInformation;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.cms.CMSUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.signature.SignatureCryptographicVerification;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.signature.PAdESWithExternalCMSService;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
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
 */
final class ExternalSigning {

    private static final TimeZone UTC = TimeZone.getTimeZone("UTC");

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
        DigestAlgorithm digestAlgorithm = o.digestAlgorithm;
        DSSDocument doc = document(document, o, format);
        VisibleImageParameters visible = format == Format.PADES ? visible(document, o) : null;

        if (o.mode == Mode.CMS) {
            byte[] digest = format == Format.PADES
                    ? externalCmsService().getMessageDigest(doc, padesParameters(o, visible)).getValue()
                    : DSSUtils.digest(digestAlgorithm, document);
            return new PreparedSignature(format, digestAlgorithm, digest, null, time);
        }
        ToBeSigned tbs = format == Format.PADES
                ? padesService().getDataToSign(doc, padesParameters(o, visible))
                : cadesService().getDataToSign(doc, cadesParameters(o));
        return new PreparedSignature(format, digestAlgorithm, DSSUtils.digest(digestAlgorithm, tbs.getBytes()),
                tbs.getBytes(), time);
    }

    SigningResult complete(byte[] document, SigningOptions o, byte[] external) {
        Format format = format(document, o);
        if (o.signingTime == null && (format == Format.PADES || o.mode == Mode.SIGNATURE_VALUE)) {
            throw new DssError(DssError.Code.INVALID_ARGUMENT,
                    "options: 'signing_time' is required to complete: pass the one prepare returned");
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
            assertSignatureValueValid(service.isValidSignatureValue(service.getDataToSign(doc, parameters), value,
                    o.signingCertificate));
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
        byte[] digest = service.getMessageDigest(doc, padesParameters(o, visible)).getValue();
        CMS cms = checkedCms(external, Format.PADES, o, digest);
        byte[] der = cms.getDEREncoded();
        int reserved = o.contentSizeOrDefault();
        if (der.length > reserved) {
            throw new DssError(DssError.Code.SIGNING_FAILED, "the CMS is " + der.length + " bytes, more than the "
                    + reserved + " reserved for it in the PDF: prepare and sign again with a larger "
                    + "'pades.content_size'");
        }
        boolean timestamped = hasSignatureTimestamp(cms);
        // DSS embeds the CMS, then extends unless the level is B, or T and the CMS already has its timestamp.
        DSSDocument signed = service.signDocument(doc, padesParameters(o, visible), new InMemoryDocument(der));
        return new SigningResult(DSSUtils.toByteArray(signed), Format.PADES, reached(o.level, timestamped).pades,
                "ENVELOPED");
    }

    private SigningResult cadesFromCms(DSSDocument doc, byte[] content, SigningOptions o, byte[] external) {
        CMS cms = checkedCms(external, Format.CADES, o, DSSUtils.digest(o.digestAlgorithm, content));
        Packaging packaging = o.packaging != null ? o.packaging : Packaging.DETACHED;
        byte[] der = cms.getDEREncoded();
        if (packaging == Packaging.ENVELOPING) {
            der = encapsulate(der, content);
        }
        DSSDocument signed = new InMemoryDocument(der, doc.getName() + (packaging == Packaging.ENVELOPING ? ".p7m"
                : ".p7s"));
        boolean timestamped = hasSignatureTimestamp(cms);
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

    /**
     * Parses what the external signer returned and checks it is a baseline-B CMS for this {@code digest}, with
     * reasons a caller can act on. DSS's own checker only logs them.
     */
    private static CMS checkedCms(byte[] external, Format format, SigningOptions o, byte[] digest) {
        InputNormalizer.Normalized input = InputNormalizer.normalize(external);
        if (input.type() != InputNormalizer.Type.CMS) {
            throw failed("mode \"cms\" expects a CMS SignedData from the external signer (DER, BER, base64 or "
                    + "PEM), and this is not one; for a bare signature value use mode \"signature_value\"");
        }
        CMS cms;
        try {
            cms = CMSUtils.parseToCMS(input.bytes());
        } catch (RuntimeException e) {
            throw failed("the external CMS cannot be parsed: " + e.getMessage());
        }
        Collection<SignerInformation> signers = cms.getSignerInfos().getSigners();
        if (signers.size() != 1) {
            throw failed("the CMS has " + signers.size() + " signers; exactly one is expected");
        }
        if (!cms.isDetachedSignature()) {
            throw failed("the CMS encapsulates content; the external signer must return a detached CMS (it "
                    + "signs a digest, the content stays here)");
        }
        SignerInformation signer = signers.iterator().next();
        if (!o.digestAlgorithm.getOid().equals(signer.getDigestAlgOID())) {
            DigestAlgorithm used = digestAlgorithmOrNull(signer.getDigestAlgOID());
            throw failed("the CMS uses digest algorithm " + (used != null ? used.getName() : signer.getDigestAlgOID())
                    + ", the options say " + o.digestAlgorithm.getName());
        }

        AttributeTable signed = signer.getSignedAttributes();
        if (signed == null) {
            throw failed("the CMS has no signed attributes");
        }
        Attribute contentType = signed.get(PKCSObjectIdentifiers.pkcs_9_at_contentType);
        if (contentType == null || !CMSObjectIdentifiers.data.equals(contentType.getAttrValues().getObjectAt(0))) {
            throw failed("the CMS has no content-type attribute with value id-data, which baseline signatures "
                    + "require");
        }
        Attribute messageDigest = signed.get(PKCSObjectIdentifiers.pkcs_9_at_messageDigest);
        if (messageDigest == null) {
            throw failed("the CMS has no message-digest attribute");
        }
        byte[] signedDigest = ASN1OctetString.getInstance(messageDigest.getAttrValues().getObjectAt(0)).getOctets();
        if (!MessageDigest.isEqual(signedDigest, digest)) {
            throw failed("the CMS signs the digest " + Base64.getEncoder().encodeToString(signedDigest)
                    + ", not this document's " + Base64.getEncoder().encodeToString(digest) + ": prepare and complete "
                    + "need the same document and options, including signing_time");
        }
        if (signed.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2) == null
                && signed.get(PKCSObjectIdentifiers.id_aa_signingCertificate) == null) {
            throw failed("the CMS has no signing-certificate-v2 attribute, which baseline signatures require");
        }
        boolean signingTime = signed.get(PKCSObjectIdentifiers.pkcs_9_at_signingTime) != null;
        if (format == Format.PADES && signingTime) {
            throw failed("the CMS has a signing-time attribute, which PAdES does not allow (the signing time is the "
                    + "PDF's /M entry): the external signer must leave it out");
        }
        if (format == Format.CADES && !signingTime) {
            throw failed("the CMS has no signing-time attribute, which CAdES-BASELINE-B requires");
        }

        CertificateToken signerCertificate = signerCertificate(cms, signer);
        if (o.signingCertificate != null && !o.signingCertificate.equals(signerCertificate)) {
            throw failed("the CMS is signed by " + signerCertificate.getSubject().getRFC2253() + ", not by the "
                    + "signing_certificate given (" + o.signingCertificate.getSubject().getRFC2253() + ")");
        }
        CAdESSignature signature = new CAdESSignature(cms, signer);
        signature.setDetachedContents(List.of(new DigestDocument(o.digestAlgorithm, digest)));
        SignatureCryptographicVerification verification = signature.getSignatureCryptographicVerification();
        if (!verification.isSignatureValid()) {
            throw failed("the CMS signature does not verify with its signer's certificate: "
                    + verification.getErrorMessage());
        }
        return cms;
    }

    private static CertificateToken signerCertificate(CMS cms, SignerInformation signer) {
        @SuppressWarnings("unchecked")
        Collection<X509CertificateHolder> matches = cms.getCertificates().getMatches(signer.getSID());
        if (matches.isEmpty()) {
            throw failed("the CMS does not contain its signer's certificate");
        }
        try {
            return DSSUtils.loadCertificate(matches.iterator().next().getEncoded());
        } catch (IOException e) {
            throw failed("the signer's certificate in the CMS cannot be read: " + e.getMessage());
        }
    }

    private static boolean hasSignatureTimestamp(CMS cms) {
        AttributeTable unsigned = cms.getSignerInfos().getSigners().iterator().next().getUnsignedAttributes();
        return unsigned != null && unsigned.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken) != null;
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

    private static DigestAlgorithm digestAlgorithmOrNull(String oid) {
        try {
            return DigestAlgorithm.forOID(oid);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static DssError failed(String message) {
        return new DssError(DssError.Code.SIGNING_FAILED, message);
    }
}
