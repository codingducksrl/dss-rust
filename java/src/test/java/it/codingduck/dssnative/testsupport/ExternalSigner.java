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
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

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
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
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
 * lengths, as streaming encoders write it). A {@link Tamper} makes it get one thing wrong, for refusal tests.
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

    /** One way a signer can get the CMS wrong. */
    public enum Tamper {
        /** A SignedData whose content is not a SignedData. */
        UNPARSEABLE,
        /** The SignerInfo twice. */
        TWO_SIGNERS,
        /** No signed attributes at all. */
        NO_SIGNED_ATTRIBUTES,
        NO_CONTENT_TYPE,
        /** A content-type attribute whose value SET is empty. */
        EMPTY_CONTENT_TYPE,
        NO_MESSAGE_DIGEST,
        /** A message-digest attribute whose value SET is empty. */
        EMPTY_MESSAGE_DIGEST,
        NO_SIGNING_CERTIFICATE,
        /** A signing-certificate-v2 whose certificate hash is all zeros. */
        WRONG_SIGNING_CERTIFICATE_HASH,
        /** A (correct) signing-certificate attribute, SHA-1, instead of the v2 one. */
        SIGNING_CERTIFICATE_V1,
        /** With {@link Cms#SIGNING_TIME}: a signing time in 2020, before the test PKI's certificates. */
        OLD_SIGNING_TIME,
        /** The signer's certificate left out of the CMS. */
        NO_CERTIFICATE,
        /** One bit of the signature value flipped. */
        BROKEN_SIGNATURE,
        /** The signature made with SHA-1 (signatureAlgorithm says so) while digestAlgorithm stays as asked. */
        SHA1_SIGNATURE,
        /** A signature-time-stamp attribute holding a 3-byte OCTET STRING instead of a token. */
        BOGUS_TIMESTAMP,
        /** A genuine token from the test TSA, over other bytes than the signature value. */
        FOREIGN_TIMESTAMP,
        /** A certificate-values unsigned attribute with a garbage value. */
        EXTRA_UNSIGNED_ATTRIBUTE,
        /** A signing-certificate-v2 whose IssuerSerial names the serial number after the certificate's. */
        WRONG_SERIAL,
        /** A signing-certificate-v2 whose IssuerSerial names the signer itself as the issuer. */
        WRONG_ISSUER,
        /** A signing-certificate-v2 that references no certificate at all (an empty list). */
        NO_CERTIFICATE_REFERENCED,
        /** A signing-certificate-v2 hashing the certificate with an algorithm nobody knows (1.2.3.4). */
        UNKNOWN_CERTIFICATE_HASH_ALGORITHM,
        /** A signing-certificate-v2 attribute whose value is an OCTET STRING, not a SigningCertificateV2. */
        MALFORMED_SIGNING_CERTIFICATE,
        /** The content-type attribute twice. */
        DUPLICATE_ATTRIBUTE,
        /**
         * Signed with the other test signer's key (the EC one for the RSA signer and vice versa), the certificate
         * carried and referenced unchanged: the signature algorithm says so, the key does not fit the certificate.
         */
        WRONG_KEY,
        /** A sound signature labelled with a signatureAlgorithm OID nobody knows (1.2.3.4.5). */
        UNKNOWN_SIGNATURE_ALGORITHM,
        /** A genuine timestamp over the signature value whose TSA signature has one bit flipped. */
        BROKEN_TIMESTAMP_SIGNATURE,
        /** A genuine timestamp with the TSA's certificate stripped from the token (the CMS does not carry it). */
        TIMESTAMP_WITHOUT_TSA_CERTIFICATE,
        /** Two signature-time-stamp attributes, each holding a genuine token over the signature value. */
        TWO_TIMESTAMPS
    }

    private final TestPki pki;
    private final Entity signer;
    /** Null: the current time and random nonces and serial numbers. */
    private final Supplier<Instant> clock;

    public ExternalSigner(TestPki pki, Entity signer) {
        this(pki, signer, null);
    }

    /**
     * A signer whose signing times and timestamps take their time from {@code clock} (called once per signing time
     * and once per timestamp), with timestamp nonces and serial numbers derived from the data, so that an RSA signer
     * returns the same bytes for the same digest: for the reproducible fixtures. Null {@code clock}: the current time
     * and random nonces.
     */
    public ExternalSigner(TestPki pki, Entity signer, Supplier<Instant> clock) {
        this.pki = pki;
        this.signer = signer;
        this.clock = clock;
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
        return cms(algorithm, digest, shape, null);
    }

    /** As {@link #cms(DigestAlgorithm, byte[], Set)}, with one thing wrong ({@code tamper} may be null). */
    public byte[] cms(DigestAlgorithm algorithm, byte[] digest, Set<Cms> shape, Tamper tamper) {
        try {
            if (tamper == Tamper.UNPARSEABLE) {
                return new ContentInfo(CMSObjectIdentifiers.signedData, new DEROctetString(new byte[] {1, 2, 3}))
                        .getEncoded(ASN1Encoding.DER);
            }
            X509Certificate cert = pki.x509(signer);
            AlgorithmIdentifier digestId = new AlgorithmIdentifier(new ASN1ObjectIdentifier(algorithm.getOid()));

            ASN1EncodableVector attributes = new ASN1EncodableVector();
            if (tamper == Tamper.EMPTY_CONTENT_TYPE) {
                attributes.add(new Attribute(PKCSObjectIdentifiers.pkcs_9_at_contentType, new DERSet()));
            } else if (tamper != Tamper.NO_CONTENT_TYPE) {
                Attribute contentType = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_contentType,
                        new DERSet(CMSObjectIdentifiers.data));
                attributes.add(contentType);
                if (tamper == Tamper.DUPLICATE_ATTRIBUTE) {
                    attributes.add(contentType);
                }
            }
            if (shape.contains(Cms.SIGNING_TIME)) {
                Date when = tamper == Tamper.OLD_SIGNING_TIME ? Date.from(Instant.parse("2020-01-01T00:00:00Z"))
                        : clock != null ? Date.from(clock.get()) : new Date();
                attributes.add(new Attribute(PKCSObjectIdentifiers.pkcs_9_at_signingTime, new DERSet(new Time(when))));
            }
            if (tamper == Tamper.EMPTY_MESSAGE_DIGEST) {
                attributes.add(new Attribute(PKCSObjectIdentifiers.pkcs_9_at_messageDigest, new DERSet()));
            } else if (tamper != Tamper.NO_MESSAGE_DIGEST) {
                attributes.add(new Attribute(PKCSObjectIdentifiers.pkcs_9_at_messageDigest,
                        new DERSet(new DEROctetString(digest))));
            }
            X500Name issuerName = tamper == Tamper.WRONG_ISSUER
                    ? X500Name.getInstance(cert.getSubjectX500Principal().getEncoded()) : issuer(cert);
            BigInteger serial = tamper == Tamper.WRONG_SERIAL ? cert.getSerialNumber().add(BigInteger.ONE)
                    : cert.getSerialNumber();
            IssuerSerial issuerSerial = new IssuerSerial(new GeneralNames(new GeneralName(issuerName)), serial);
            if (tamper == Tamper.SIGNING_CERTIFICATE_V1) {
                ESSCertID certId = new ESSCertID(MessageDigest.getInstance("SHA-1").digest(cert.getEncoded()),
                        issuerSerial);
                attributes.add(new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificate,
                        new DERSet(new SigningCertificate(certId))));
            } else if (tamper == Tamper.MALFORMED_SIGNING_CERTIFICATE) {
                attributes.add(new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2,
                        new DERSet(new DEROctetString(new byte[] {7, 8, 9}))));
            } else if (tamper == Tamper.NO_CERTIFICATE_REFERENCED) {
                attributes.add(new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2,
                        new DERSet(new SigningCertificateV2(new ESSCertIDv2[0]))));
            } else if (tamper != Tamper.NO_SIGNING_CERTIFICATE) {
                byte[] hash = tamper == Tamper.WRONG_SIGNING_CERTIFICATE_HASH ? new byte[32]
                        : MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
                String hashOid = tamper == Tamper.UNKNOWN_CERTIFICATE_HASH_ALGORITHM ? "1.2.3.4"
                        : DigestAlgorithm.SHA256.getOid();
                ESSCertIDv2 certId = new ESSCertIDv2(new AlgorithmIdentifier(new ASN1ObjectIdentifier(hashOid)), hash,
                        issuerSerial);
                attributes.add(new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2,
                        new DERSet(new SigningCertificateV2(new ESSCertIDv2[] {certId}))));
            }
            DERSet signedAttributes = tamper == Tamper.NO_SIGNED_ATTRIBUTES ? null : new DERSet(attributes);

            PrivateKey key = tamper == Tamper.WRONG_KEY
                    ? pki.key(signer == Entity.SIGNER_RSA ? Entity.SIGNER_EC : Entity.SIGNER_RSA) : pki.key(signer);
            EncryptionAlgorithm encryption = EncryptionAlgorithm.forKey(key);
            SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.getAlgorithm(encryption,
                    tamper == Tamper.SHA1_SIGNATURE ? DigestAlgorithm.SHA1 : algorithm);
            AlgorithmIdentifier signatureId = tamper == Tamper.UNKNOWN_SIGNATURE_ALGORITHM
                    ? new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3.4.5"))
                    : new DefaultSignatureAlgorithmIdentifierFinder().find(signatureAlgorithm.getJCEId());
            Signature jca = Signature.getInstance(signatureAlgorithm.getJCEId());
            jca.initSign(key);
            jca.update(signedAttributes != null ? signedAttributes.getEncoded(ASN1Encoding.DER) : digest);
            byte[] signature = jca.sign();
            if (tamper == Tamper.BROKEN_SIGNATURE) {
                signature[signature.length / 2] ^= 0x01;
            }

            ASN1EncodableVector unsignedAttributes = new ASN1EncodableVector();
            if (shape.contains(Cms.TIMESTAMP) || tamper == Tamper.FOREIGN_TIMESTAMP
                    || tamper == Tamper.BROKEN_TIMESTAMP_SIGNATURE || tamper == Tamper.TIMESTAMP_WITHOUT_TSA_CERTIFICATE
                    || tamper == Tamper.TWO_TIMESTAMPS) {
                ContentInfo token = timestampToken(tamper == Tamper.FOREIGN_TIMESTAMP ? digest : signature);
                if (tamper == Tamper.BROKEN_TIMESTAMP_SIGNATURE || tamper == Tamper.TIMESTAMP_WITHOUT_TSA_CERTIFICATE) {
                    token = rebuilt(token, tamper == Tamper.BROKEN_TIMESTAMP_SIGNATURE,
                            tamper == Tamper.TIMESTAMP_WITHOUT_TSA_CERTIFICATE);
                }
                unsignedAttributes.add(new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken,
                        new DERSet(token)));
                if (tamper == Tamper.TWO_TIMESTAMPS) {
                    unsignedAttributes.add(new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken,
                            new DERSet(timestampToken(signature))));
                }
            }
            if (tamper == Tamper.BOGUS_TIMESTAMP) {
                unsignedAttributes.add(new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken,
                        new DERSet(new DEROctetString(new byte[] {1, 2, 3}))));
            }
            if (tamper == Tamper.EXTRA_UNSIGNED_ATTRIBUTE) {
                unsignedAttributes.add(new Attribute(PKCSObjectIdentifiers.id_aa_ets_certValues,
                        new DERSet(new DEROctetString(new byte[] {4, 5, 6}))));
            }
            ASN1Set unsigned = unsignedAttributes.size() == 0 ? null : new DERSet(unsignedAttributes);
            SignerInfo signerInfo = new SignerInfo(
                    new SignerIdentifier(new IssuerAndSerialNumber(issuer(cert), cert.getSerialNumber())), digestId,
                    signedAttributes, signatureId, new DEROctetString(signature), unsigned);
            ASN1Encodable[] signerInfos = tamper == Tamper.TWO_SIGNERS
                    ? new ASN1Encodable[] {signerInfo, signerInfo} : new ASN1Encodable[] {signerInfo};

            List<ASN1Encodable> certificates = new ArrayList<>();
            if (tamper != Tamper.NO_CERTIFICATE) {
                certificates.add(Certificate.getInstance(cert.getEncoded()));
            }
            if (shape.contains(Cms.CHAIN)) {
                certificates.add(Certificate.getInstance(pki.x509(Entity.ROOT_CA).getEncoded()));
            }
            if (shape.contains(Cms.BER)) {
                ASN1EncodableVector sd = new ASN1EncodableVector();
                sd.add(new ASN1Integer(1));
                sd.add(new DERSet(digestId));
                sd.add(new BERSequence(CMSObjectIdentifiers.data));
                sd.add(new BERTaggedObject(false, 0, new BERSet(certificates.toArray(new ASN1Encodable[0]))));
                sd.add(new DERSet(signerInfos));
                return new BERSequence(new ASN1Encodable[] {CMSObjectIdentifiers.signedData,
                        new BERTaggedObject(true, 0, new BERSequence(sd))}).getEncoded(ASN1Encoding.BER);
            }
            SignedData sd = new SignedData(new DERSet(digestId), new ContentInfo(CMSObjectIdentifiers.data, null),
                    new DERSet(certificates.toArray(new ASN1Encodable[0])), null, new DERSet(signerInfos));
            return new ContentInfo(CMSObjectIdentifiers.signedData, sd).getEncoded(ASN1Encoding.DER);
        } catch (GeneralSecurityException | IOException | TSPException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A token from the test TSA whose imprint is the SHA-256 of {@code data}. */
    private ContentInfo timestampToken(byte[] data) throws GeneralSecurityException, IOException, TSPException {
        TimeStampRequestGenerator requests = new TimeStampRequestGenerator();
        requests.setCertReq(true);
        byte[] imprint = MessageDigest.getInstance("SHA-256").digest(data);
        // With a clock: nonce and token serial number from the imprint, so the same data gives the same token.
        BigInteger nonce = clock != null ? new BigInteger(1, Arrays.copyOf(imprint, 8))
                : new BigInteger(64, new SecureRandom());
        byte[] request = requests.generate(TSPAlgorithms.SHA256, imprint, nonce).getEncoded();
        byte[] response = clock != null ? pki.timestampResponse(request, clock.get(), nonce)
                : pki.timestampResponse(request);
        return new TimeStampResponse(response).getTimeStampToken().toCMSSignedData().toASN1Structure();
    }

    /**
     * {@code token} with its SignedData rebuilt: the TSA's signature value with one bit flipped when
     * {@code breakSignature}, and no certificates when {@code dropCertificates}; the TSTInfo and the signed
     * attributes stay as they are.
     */
    private static ContentInfo rebuilt(ContentInfo token, boolean breakSignature, boolean dropCertificates) {
        SignedData sd = SignedData.getInstance(token.getContent());
        SignerInfo si = SignerInfo.getInstance(sd.getSignerInfos().getObjectAt(0));
        byte[] value = si.getEncryptedDigest().getOctets().clone();
        if (breakSignature) {
            value[value.length / 2] ^= 0x01;
        }
        SignerInfo rebuiltSigner = new SignerInfo(si.getSID(), si.getDigestAlgorithm(), si.getAuthenticatedAttributes(),
                si.getDigestEncryptionAlgorithm(), new DEROctetString(value), si.getUnauthenticatedAttributes());
        SignedData rebuiltData = new SignedData(sd.getDigestAlgorithms(), sd.getEncapContentInfo(),
                dropCertificates ? null : sd.getCertificates(), sd.getCRLs(), new DERSet(rebuiltSigner));
        return new ContentInfo(CMSObjectIdentifiers.signedData, rebuiltData);
    }

    private static X500Name issuer(X509Certificate cert) {
        return X500Name.getInstance(cert.getIssuerX500Principal().getEncoded());
    }
}
