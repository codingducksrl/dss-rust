/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.testsupport;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.spi.DSSASN1Utils;

import it.codingduck.dssnative.testsupport.TestPki.Entity;

/**
 * Stands in for a signing service that holds the key and never sees the document: it receives a digest and
 * returns either a bare signature value or a detached CMS built around that digest, the way such services do
 * (content-type, message-digest = the digest received, signing-certificate-v2, optionally signing-time; the
 * signer's certificate; optionally a signature timestamp from the test TSA; optionally BER with indefinite
 * lengths, as streaming encoders write it).
 */
public final class ExternalSigner {

    /** Shape of the CMS {@link #cms} returns. */
    public enum Cms {
        /** A signing-time signed attribute (CAdES wants one, PAdES forbids it). */
        SIGNING_TIME,
        /** A signature-time-stamp unsigned attribute over the signature value, from the test TSA. */
        TIMESTAMP,
        /** The issuer's certificate too, not only the signer's. */
        CHAIN,
        /** BER with indefinite lengths instead of DER. */
        BER
    }

    private final TestPki pki;
    private final Entity signer;

    public ExternalSigner(TestPki pki, Entity signer) {
        this.pki = pki;
        this.signer = signer;
    }

    /**
     * The bare signature over a digest: RSA PKCS#1 v1.5 over {@code DigestInfo(algorithm, digest)}, or ECDSA
     * (DER, or the plain {@code r||s} concatenation when {@code plainEcdsa}).
     */
    public byte[] signatureValue(DigestAlgorithm algorithm, byte[] digest, boolean plainEcdsa) {
        PrivateKey key = pki.key(signer);
        try {
            if (EncryptionAlgorithm.forKey(key) == EncryptionAlgorithm.RSA) {
                Signature rsa = Signature.getInstance("NONEwithRSA");
                rsa.initSign(key);
                rsa.update(new DigestInfo(new AlgorithmIdentifier(new ASN1ObjectIdentifier(algorithm.getOid()),
                        DERNull.INSTANCE), digest).getEncoded(ASN1Encoding.DER));
                return rsa.sign();
            }
            Signature ecdsa = Signature.getInstance("NONEwithECDSA");
            ecdsa.initSign(key);
            ecdsa.update(digest);
            byte[] der = ecdsa.sign();
            return plainEcdsa ? DSSASN1Utils.toPlainDSASignatureValue(der) : der;
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A detached CMS SignedData whose message-digest is {@code digest}, shaped by {@code shape}. */
    public byte[] cms(DigestAlgorithm algorithm, byte[] digest, Set<Cms> shape) {
        try {
            X509Certificate cert = pki.x509(signer);
            AlgorithmIdentifier digestId = new AlgorithmIdentifier(new ASN1ObjectIdentifier(algorithm.getOid()));

            ASN1EncodableVector attributes = new ASN1EncodableVector();
            attributes.add(new Attribute(PKCSObjectIdentifiers.pkcs_9_at_contentType,
                    new DERSet(CMSObjectIdentifiers.data)));
            if (shape.contains(Cms.SIGNING_TIME)) {
                attributes.add(new Attribute(PKCSObjectIdentifiers.pkcs_9_at_signingTime,
                        new DERSet(new Time(new Date()))));
            }
            attributes.add(new Attribute(PKCSObjectIdentifiers.pkcs_9_at_messageDigest,
                    new DERSet(new DEROctetString(digest))));
            ESSCertIDv2 certId = new ESSCertIDv2(new AlgorithmIdentifier(new ASN1ObjectIdentifier(
                    DigestAlgorithm.SHA256.getOid())), MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()),
                    new IssuerSerial(new GeneralNames(new GeneralName(issuer(cert))), cert.getSerialNumber()));
            attributes.add(new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2,
                    new DERSet(new SigningCertificateV2(new ESSCertIDv2[] {certId}))));
            DERSet signedAttributes = new DERSet(attributes);

            SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.getAlgorithm(
                    EncryptionAlgorithm.forKey(pki.key(signer)), algorithm);
            Signature jca = Signature.getInstance(signatureAlgorithm.getJCEId());
            jca.initSign(pki.key(signer));
            jca.update(signedAttributes.getEncoded(ASN1Encoding.DER));
            byte[] signature = jca.sign();

            ASN1Set unsigned = null;
            if (shape.contains(Cms.TIMESTAMP)) {
                unsigned = new DERSet(new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken,
                        new DERSet(timestampToken(signature))));
            }
            SignerInfo signerInfo = new SignerInfo(
                    new SignerIdentifier(new IssuerAndSerialNumber(issuer(cert), cert.getSerialNumber())), digestId,
                    signedAttributes,
                    new DefaultSignatureAlgorithmIdentifierFinder().find(signatureAlgorithm.getJCEId()),
                    new DEROctetString(signature), unsigned);

            List<ASN1Encodable> certificates = new ArrayList<>();
            certificates.add(Certificate.getInstance(cert.getEncoded()));
            if (shape.contains(Cms.CHAIN)) {
                certificates.add(Certificate.getInstance(pki.x509(Entity.ROOT_CA).getEncoded()));
            }
            if (shape.contains(Cms.BER)) {
                ASN1EncodableVector sd = new ASN1EncodableVector();
                sd.add(new ASN1Integer(1));
                sd.add(new DERSet(digestId));
                sd.add(new BERSequence(CMSObjectIdentifiers.data));
                sd.add(new BERTaggedObject(false, 0, new BERSet(certificates.toArray(new ASN1Encodable[0]))));
                sd.add(new DERSet(signerInfo));
                return new BERSequence(new ASN1Encodable[] {CMSObjectIdentifiers.signedData,
                        new BERTaggedObject(true, 0, new BERSequence(sd))}).getEncoded(ASN1Encoding.BER);
            }
            SignedData sd = new SignedData(new DERSet(digestId), new ContentInfo(CMSObjectIdentifiers.data, null),
                    new DERSet(certificates.toArray(new ASN1Encodable[0])), null, new DERSet(signerInfo));
            return new ContentInfo(CMSObjectIdentifiers.signedData, sd).getEncoded(ASN1Encoding.DER);
        } catch (GeneralSecurityException | IOException | TSPException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A token from the test TSA whose imprint is the SHA-256 of {@code signature}. */
    private ContentInfo timestampToken(byte[] signature) throws GeneralSecurityException, IOException, TSPException {
        TimeStampRequestGenerator requests = new TimeStampRequestGenerator();
        requests.setCertReq(true);
        byte[] request = requests.generate(TSPAlgorithms.SHA256, MessageDigest.getInstance("SHA-256").digest(signature),
                new BigInteger(64, new SecureRandom())).getEncoded();
        return new TimeStampResponse(pki.timestampResponse(request)).getTimeStampToken().toCMSSignedData()
                .toASN1Structure();
    }

    private static X500Name issuer(X509Certificate cert) {
        return X500Name.getInstance(cert.getIssuerX500Principal().getEncoded());
    }
}
