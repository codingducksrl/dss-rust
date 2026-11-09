/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import java.io.IOException;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.tsp.TSPException;

import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.cms.CMSUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.signature.SignatureCryptographicVerification;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;

import it.codingduck.dssnative.engine.SigningOptions.Format;

/**
 * What {@code complete} requires of the CMS an external signer returns in mode {@code "cms"}: a detached
 * baseline-B CMS over the digest {@code prepare} gave, signed with the digest algorithm of the options by the
 * certificate it carries and references, with no unsigned attribute other than one valid signature timestamp. The
 * engine adds everything above B itself. Each failure is {@link DssError.Code#SIGNING_FAILED} with a reason the
 * caller can act on; DSS's own checkers only log theirs, and malformed attributes would otherwise surface as
 * internal errors.
 */
final class ExternalCms {

    /** archive-time-stamp-v3 (ETSI EN 319 122-1), not in BouncyCastle's identifiers. */
    private static final ASN1ObjectIdentifier ARCHIVE_TIMESTAMP_V3 = new ASN1ObjectIdentifier("0.4.0.1733.2.4");
    private static final Map<ASN1ObjectIdentifier, String> UNSIGNED_ATTRIBUTE_NAMES = Map.of(
            PKCSObjectIdentifiers.id_aa_ets_certValues, "certificate-values",
            PKCSObjectIdentifiers.id_aa_ets_revocationValues, "revocation-values",
            PKCSObjectIdentifiers.id_aa_ets_certificateRefs, "complete-certificate-references",
            PKCSObjectIdentifiers.id_aa_ets_revocationRefs, "complete-revocation-references",
            PKCSObjectIdentifiers.id_aa_ets_escTimeStamp, "CAdES-C-time-stamp",
            PKCSObjectIdentifiers.id_aa_ets_certCRLTimestamp, "time-stamped-certs-crls-references",
            PKCSObjectIdentifiers.id_aa_ets_archiveTimestamp, "archive-time-stamp-v2",
            ARCHIVE_TIMESTAMP_V3, "archive-time-stamp-v3",
            PKCSObjectIdentifiers.pkcs_9_at_counterSignature, "counter-signature");

    /**
     * A CMS that passed every check.
     *
     * @param signerCertificate   the certificate the CMS is signed with
     * @param timestamped         whether it carries a (valid) signature timestamp
     * @param claimedSigningTime  the signing-time attribute (CAdES); null for PAdES, where the time is the PDF's
     */
    record Checked(CMS cms, CertificateToken signerCertificate, boolean timestamped, Instant claimedSigningTime) {
    }

    private ExternalCms() {
    }

    static Checked check(byte[] external, Format format, SigningOptions o, byte[] digest) {
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
        try {
            return checked(cms, format, o, digest);
        } catch (DssError e) {
            throw e;
        } catch (RuntimeException e) {
            // BouncyCastle's getInstance and casts on an attribute of the wrong shape.
            throw failed("the external CMS is malformed: " + e);
        }
    }

    private static Checked checked(CMS cms, Format format, SigningOptions o, byte[] digest) {
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
        Attribute contentType = attribute(signed, PKCSObjectIdentifiers.pkcs_9_at_contentType, "content-type");
        if (contentType == null || !CMSObjectIdentifiers.data.equals(value(contentType, "content-type"))) {
            throw failed("the CMS has no content-type attribute with value id-data, which baseline signatures "
                    + "require");
        }
        Attribute messageDigest = attribute(signed, PKCSObjectIdentifiers.pkcs_9_at_messageDigest, "message-digest");
        if (messageDigest == null) {
            throw failed("the CMS has no message-digest attribute");
        }
        byte[] signedDigest = ASN1OctetString.getInstance(value(messageDigest, "message-digest")).getOctets();
        if (!MessageDigest.isEqual(signedDigest, digest)) {
            throw failed("the CMS signs the digest " + Base64.getEncoder().encodeToString(signedDigest)
                    + ", not this document's " + Base64.getEncoder().encodeToString(digest) + ": prepare and complete "
                    + "need the same document and options, including signing_time");
        }
        Attribute signingTime = attribute(signed, PKCSObjectIdentifiers.pkcs_9_at_signingTime, "signing-time");
        if (format == Format.PADES && signingTime != null) {
            throw failed("the CMS has a signing-time attribute, which PAdES does not allow (the signing time is the "
                    + "PDF's /M entry): the external signer must leave it out");
        }
        if (format == Format.CADES && signingTime == null) {
            throw failed("the CMS has no signing-time attribute, which CAdES-BASELINE-B requires");
        }
        Instant claimed = signingTime != null
                ? Time.getInstance(value(signingTime, "signing-time")).getDate().toInstant() : null;

        CertificateToken signerCertificate = signerCertificate(cms, signer);
        if (o.signingCertificate != null && !o.signingCertificate.equals(signerCertificate)) {
            throw failed("the CMS is signed by " + signerCertificate.getSubject().getRFC2253() + ", not by the "
                    + "signing_certificate given (" + o.signingCertificate.getSubject().getRFC2253() + ")");
        }
        checkSigningCertificateReference(signed, signerCertificate);

        CAdESSignature signature = new CAdESSignature(cms, signer);
        signature.setDetachedContents(List.of(new DigestDocument(o.digestAlgorithm, digest)));
        checkSignatureAlgorithm(signature, signer, signerCertificate, o.digestAlgorithm);
        SignatureCryptographicVerification verification = signature.getSignatureCryptographicVerification();
        if (!verification.isSignatureValid()) {
            throw failed("the CMS signature does not verify with its signer's certificate: "
                    + verification.getErrorMessage());
        }
        boolean timestamped = checkUnsignedAttributes(cms, signer);
        return new Checked(cms, signerCertificate, timestamped, claimed);
    }

    private static CertificateToken signerCertificate(CMS cms, SignerInformation signer) {
        @SuppressWarnings("unchecked")
        Collection<X509CertificateHolder> matches = cms.getCertificates().getMatches(signer.getSID());
        if (matches.isEmpty()) {
            throw failed("the CMS does not contain its signer's certificate");
        }
        try {
            return DSSUtils.loadCertificate(matches.iterator().next().getEncoded());
        } catch (IOException | RuntimeException e) {
            throw failed("the signer's certificate in the CMS cannot be read: " + e.getMessage());
        }
    }

    /**
     * The signing-certificate(-v2) attribute must reference the certificate the CMS is signed with: its hash, and
     * its issuer and serial when given. Validators grade a mismatch NO_SIGNING_CERTIFICATE_FOUND.
     */
    private static void checkSigningCertificateReference(AttributeTable signed, CertificateToken certificate) {
        Attribute v2 = attribute(signed, PKCSObjectIdentifiers.id_aa_signingCertificateV2, "signing-certificate-v2");
        Attribute v1 = attribute(signed, PKCSObjectIdentifiers.id_aa_signingCertificate, "signing-certificate");
        if (v2 == null && v1 == null) {
            throw failed("the CMS has no signing-certificate-v2 (or signing-certificate) attribute, which baseline "
                    + "signatures require");
        }
        if (v2 != null) {
            ESSCertIDv2[] ids = SigningCertificateV2.getInstance(value(v2, "signing-certificate-v2")).getCerts();
            if (ids.length == 0) {
                throw failed("the CMS's signing-certificate-v2 attribute references no certificate");
            }
            // The first ESSCertIDv2 is the signing certificate (RFC 5035); the others, the chain.
            assertReferences("signing-certificate-v2", ids[0].getHashAlgorithm().getAlgorithm().getId(),
                    ids[0].getCertHash(), ids[0].getIssuerSerial(), certificate);
        }
        if (v1 != null) {
            ESSCertID[] ids = SigningCertificate.getInstance(value(v1, "signing-certificate")).getCerts();
            if (ids.length == 0) {
                throw failed("the CMS's signing-certificate attribute references no certificate");
            }
            assertReferences("signing-certificate", DigestAlgorithm.SHA1.getOid(), ids[0].getCertHash(),
                    ids[0].getIssuerSerial(), certificate);
        }
    }

    private static void assertReferences(String attribute, String hashOid, byte[] hash, IssuerSerial issuerSerial,
                                         CertificateToken certificate) {
        DigestAlgorithm algorithm = digestAlgorithmOrNull(hashOid);
        if (algorithm == null) {
            throw failed("the CMS's " + attribute + " attribute hashes the certificate with an unsupported algorithm ("
                    + hashOid + ")");
        }
        if (!MessageDigest.isEqual(hash, certificate.getDigest(algorithm))) {
            throw failed("the CMS's " + attribute + " attribute does not reference the certificate the CMS is signed "
                    + "with (" + certificate.getSubject().getRFC2253() + "): the certificate hash differs. The signer "
                    + "must reference the certificate whose key it signs with");
        }
        if (issuerSerial == null) {
            return;
        }
        if (!issuerSerial.getSerial().getValue().equals(certificate.getSerialNumber())) {
            throw failed("the CMS's " + attribute + " attribute names serial number " + issuerSerial.getSerial().getValue()
                    + ", the signer's certificate has " + certificate.getSerialNumber());
        }
        X500Name issuer = X500Name.getInstance(certificate.getCertificate().getIssuerX500Principal().getEncoded());
        boolean named = false;
        for (GeneralName name : issuerSerial.getIssuer().getNames()) {
            if (name.getTagNo() == GeneralName.directoryName) {
                if (X500Name.getInstance(name.getName()).equals(issuer)) {
                    return;
                }
                named = true;
            }
        }
        if (named) {
            throw failed("the CMS's " + attribute + " attribute names another issuer than the signer's certificate's ("
                    + certificate.getIssuer().getRFC2253() + ")");
        }
    }

    /**
     * The signature algorithm (SignerInfo.signatureAlgorithm) must hash with the digest algorithm of the options
     * and fit the signer's key. BouncyCastle verifies a SHA-1 (or MD5) signature whatever the digestAlgorithm
     * field says, and validators then grade the document INDETERMINATE.
     */
    private static void checkSignatureAlgorithm(CAdESSignature signature, SignerInformation signer,
                                                CertificateToken certificate, DigestAlgorithm expected) {
        EncryptionAlgorithm encryption = signature.getEncryptionAlgorithm();
        DigestAlgorithm digest = signature.getDigestAlgorithm();
        if (digest == null) {
            // A bare key algorithm (rsaEncryption) as signatureAlgorithm, as RFC 5652 allows: the hash is the
            // SignerInfo's digestAlgorithm, already checked against the options.
            digest = digestAlgorithmOrNull(signer.getDigestAlgOID());
        }
        if (encryption == null || digest == null) {
            throw failed("the CMS uses an unsupported signature algorithm (" + signer.getEncryptionAlgOID() + ")");
        }
        if (digest != expected) {
            throw failed("the CMS signature algorithm is " + encryption.getName() + " with " + digest.getName()
                    + ", the options say " + expected.getName() + ": the signature must hash with the digest "
                    + "algorithm of the message digest");
        }
        EncryptionAlgorithm key;
        try {
            key = EncryptionAlgorithm.forKey(certificate.getPublicKey());
        } catch (RuntimeException e) {
            throw failed("the signer's certificate in the CMS holds an unsupported key: " + e.getMessage());
        }
        if (!key.isEquivalent(encryption)) {
            throw failed("the CMS signature algorithm is " + encryption.getName() + " but the signer's certificate "
                    + "holds a " + key.getName() + " key");
        }
    }

    /**
     * The only unsigned attribute a baseline-B CMS may bring is one signature timestamp, and it must be a token
     * over this signature value that verifies with its TSA certificate: {@code complete} reports and relies on
     * it (T is not added again). Validation material (certificate-values, revocation-values, archive timestamps,
     * counter-signatures) is the engine's to add, and PAdES allows none of it inside the CMS.
     *
     * @return whether a signature timestamp is present
     */
    private static boolean checkUnsignedAttributes(CMS cms, SignerInformation signer) {
        AttributeTable unsigned = signer.getUnsignedAttributes();
        if (unsigned == null) {
            return false;
        }
        Attribute timestamp = null;
        ASN1EncodableVector all = unsigned.toASN1EncodableVector();
        for (int i = 0; i < all.size(); i++) {
            Attribute attribute = Attribute.getInstance(all.get(i));
            ASN1ObjectIdentifier oid = attribute.getAttrType();
            if (!PKCSObjectIdentifiers.id_aa_signatureTimeStampToken.equals(oid)) {
                String name = UNSIGNED_ATTRIBUTE_NAMES.get(oid);
                throw failed("the CMS has an unsigned attribute " + (name != null ? name + " (" + oid + ")" : oid)
                        + ": the external signer must return a baseline-B CMS with at most a signature timestamp; "
                        + "the engine adds what the requested level needs");
            }
            if (timestamp != null) {
                throw failed("the CMS has two signature-time-stamp attributes; at most one is expected");
            }
            timestamp = attribute;
        }
        if (timestamp == null) {
            return false;
        }
        checkSignatureTimestamp(cms, signer, value(timestamp, "signature-time-stamp"));
        return true;
    }

    private static void checkSignatureTimestamp(CMS cms, SignerInformation signer, ASN1Encodable value) {
        TimestampToken token;
        try {
            token = new TimestampToken(value.toASN1Primitive().getEncoded(ASN1Encoding.DER),
                    TimestampType.SIGNATURE_TIMESTAMP);
        } catch (TSPException | CMSException | IOException | RuntimeException e) {
            throw failed("the CMS's signature-time-stamp attribute does not hold a timestamp token: " + e.getMessage());
        }
        if (!token.matchData(new InMemoryDocument(signer.getSignature()), true)) {
            throw failed("the signature timestamp in the CMS is not over this signature value (its message imprint "
                    + "does not match)");
        }
        List<CertificateToken> candidates = new ArrayList<>(token.getCertificates());
        @SuppressWarnings("unchecked")
        Collection<X509CertificateHolder> inCms = cms.getCertificates().getMatches(null);
        for (X509CertificateHolder holder : inCms) {
            try {
                candidates.add(DSSUtils.loadCertificate(holder.getEncoded()));
            } catch (IOException | RuntimeException e) {
                // not a usable candidate
            }
        }
        if (candidates.stream().noneMatch(token::isSignedBy)) {
            throw failed("the signature timestamp in the CMS does not verify with any certificate in the token or "
                    + "the CMS" + (candidates.isEmpty() ? " (there is none)" : "") + ": the TSA's signature is broken "
                    + "or its certificate is missing");
        }
    }

    /** The attribute with {@code oid}, if present once. */
    private static Attribute attribute(AttributeTable table, ASN1ObjectIdentifier oid, String name) {
        ASN1EncodableVector all = table.getAll(oid);
        if (all.size() > 1) {
            throw failed("the CMS has " + all.size() + " " + name + " attributes; at most one is allowed");
        }
        return all.size() == 0 ? null : Attribute.getInstance(all.get(0));
    }

    /** The attribute's single value: an empty or multi-valued attribute is malformed, not an internal error. */
    private static ASN1Encodable value(Attribute attribute, String name) {
        ASN1Set values = attribute.getAttrValues();
        if (values.size() != 1) {
            throw failed("the CMS's " + name + " attribute has " + values.size() + " values; exactly one is expected");
        }
        return values.getObjectAt(0);
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
