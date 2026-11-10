/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.testsupport;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;

/**
 * Synthetic PKI for tests and fixtures. Persisted in {@code testdata/fixtures/pki/test-pki.p12} so committed
 * fixtures stay verifiable; regenerate with {@code scripts/generate-fixtures.sh --new-pki}. {@link #generate} is
 * deterministic: every key, serial number and signature comes from a {@link #deterministicRandom} seeded per entity
 * and the validity period is fixed, so regenerating gives the same keys and certificates (on the same JDK; only the
 * PKCS#12 container's salts differ). Certificates issued at test time ({@link #issueNow} and the like) are random.
 *
 * <p>All names and URLs are fictitious ({@code .test} TLD, RFC 2606), so nothing here can reach the network.
 */
public final class TestPki {

    public static final char[] PASSWORD = "dss-native-test".toCharArray();
    public static final String CRL_URL = "http://crl.dss-native.test/root-ca.crl";
    /** Where the test TSA answers RFC 3161 requests; served in memory by {@link #timestampResponse}. */
    public static final String TSA_URL = "http://tsa.dss-native.test/tsr";
    /** Policy of the test TSA's tokens (an arbitrary OID). */
    public static final String TSA_POLICY = "1.3.6.1.4.1.99999.1.1";

    public enum Entity {
        ROOT_CA("root-ca"),
        SIGNER_RSA("signer-rsa"),
        SIGNER_EC("signer-ec"),
        TSA("tsa"),
        /** Signs the synthetic LOTL; plays the role of the OJ-announced LOTL signer. */
        LOTL_SIGNER("lotl-signer"),
        /** Signs the synthetic national TLs. */
        TL_SIGNER("tl-signer"),
        /** A CA listed only in the synthetic "DE" TL, to test the country filter. */
        OTHER_CA("other-ca");

        public final String alias;

        Entity(String alias) {
            this.alias = alias;
        }
    }

    /**
     * The committed PKI, loaded once per JVM. {@link #load()} is called by every {@link TestEngines}, and test
     * threads (a CRL served by {@link #freshCrl} on a trusted-list thread, a TSA answering on a validation thread)
     * call into it while the next test's main thread already does. A {@link KeyStore} is not thread-safe, and each
     * {@code getKey} decrypts the PKCS#12 entry anew (PBKDF2 + AES): sharing one instance that decrypts every key
     * exactly once keeps the keystore off the hot path entirely.
     */
    private static volatile TestPki committed;

    private final KeyStore store;
    private final Map<Entity, PrivateKey> keys = new ConcurrentHashMap<>();
    private final Map<Entity, X509Certificate> certificates = new ConcurrentHashMap<>();

    private TestPki(KeyStore store) {
        this.store = store;
    }

    public static Path defaultLocation() {
        return Fixtures.dir().resolve("pki/test-pki.p12");
    }

    /** The committed PKI at {@link #defaultLocation()}: one shared, immutable instance per JVM. */
    public static TestPki load() {
        TestPki pki = committed;
        if (pki == null) {
            synchronized (TestPki.class) {
                pki = committed;
                if (pki == null) {
                    pki = load(defaultLocation());
                    committed = pki;
                }
            }
        }
        return pki;
    }

    /** Loads a PKI written by {@link #generate}; a new instance on every call. */
    public static TestPki load(Path p12) {
        try (InputStream in = Files.newInputStream(p12)) {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(in, password());
            return new TestPki(ks);
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException("cannot load test PKI " + p12
                    + " (run scripts/generate-fixtures.sh)", e);
        }
    }

    /** A private copy of {@link #PASSWORD} for the JCA, which may clear the array it is given. */
    private static char[] password() {
        return PASSWORD.clone();
    }

    public X509Certificate x509(Entity e) {
        return certificates.computeIfAbsent(e, entity -> {
            try {
                synchronized (store) {
                    return (X509Certificate) store.getCertificate(entity.alias);
                }
            } catch (GeneralSecurityException ex) {
                throw new IllegalStateException(ex);
            }
        });
    }

    public CertificateToken token(Entity e) {
        return new CertificateToken(x509(e));
    }

    /** The entity's private key, decrypted from the PKCS#12 entry on first use and cached. */
    public PrivateKey key(Entity e) {
        return keys.computeIfAbsent(e, entity -> {
            try {
                synchronized (store) {
                    return (PrivateKey) store.getKey(entity.alias, password());
                }
            } catch (GeneralSecurityException ex) {
                throw new IllegalStateException(ex);
            }
        });
    }

    /** Chain from the entity up to (and including) the root, for entities issued by the root. */
    public List<CertificateToken> chain(Entity e) {
        return List.of(token(e), token(Entity.ROOT_CA));
    }

    public String pem(Entity e) {
        try {
            return "-----BEGIN CERTIFICATE-----\n"
                    + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(x509(e).getEncoded())
                    + "\n-----END CERTIFICATE-----\n";
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException(ex);
        }
    }

    /** A CRL from the root, issued now and listing nothing as revoked. */
    public byte[] freshCrl() {
        return crl(x509(Entity.ROOT_CA), key(Entity.ROOT_CA), Map.of());
    }

    /**
     * A CRL from {@code issuer}, issued now (to the second) and valid for 7 days, listing the serial numbers of
     * {@code revoked} as revoked (key compromise) at the given times.
     */
    public static byte[] crl(X509Certificate issuer, PrivateKey issuerKey, Map<BigInteger, Instant> revoked) {
        return crl(issuer, issuerKey, revoked, Instant.now());
    }

    /**
     * As {@link #crl(X509Certificate, PrivateKey, Map)}, issued at {@code thisUpdate} (to the second): for an RSA
     * issuer the same arguments give the same bytes.
     */
    public static byte[] crl(X509Certificate issuer, PrivateKey issuerKey, Map<BigInteger, Instant> revoked,
                             Instant thisUpdate) {
        return crl(issuer, issuerKey, revoked, thisUpdate,
                thisUpdate.truncatedTo(ChronoUnit.SECONDS).plus(7, ChronoUnit.DAYS));
    }

    /**
     * As {@link #crl(X509Certificate, PrivateKey, Map, Instant)}, valid until {@code nextUpdate} instead of for 7 days.
     * Both times are truncated to the second, as the encoding does: give a {@code nextUpdate} at least a second away
     * from now when the test needs it on a definite side of now.
     */
    public static byte[] crl(X509Certificate issuer, PrivateKey issuerKey, Map<BigInteger, Instant> revoked,
                             Instant thisUpdate, Instant nextUpdate) {
        try {
            Instant now = thisUpdate.truncatedTo(ChronoUnit.SECONDS);
            X509v2CRLBuilder b = new X509v2CRLBuilder(X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded()),
                    Date.from(now));
            b.setNextUpdate(Date.from(nextUpdate.truncatedTo(ChronoUnit.SECONDS)));
            for (Map.Entry<BigInteger, Instant> r : revoked.entrySet()) {
                b.addCRLEntry(r.getKey(), Date.from(r.getValue()), CRLReason.keyCompromise);
            }
            b.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(now.getEpochSecond())));
            b.addExtension(Extension.authorityKeyIdentifier, false,
                    new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(issuer));
            X509CRLHolder crl = b.build(signer(issuerKey));
            return crl.getEncoded();
        } catch (IOException | GeneralSecurityException | org.bouncycastle.operator.OperatorCreationException e) {
            throw new IllegalStateException(e);
        }
    }

    /** What an OCSP responder does with the request's nonce. */
    public enum Nonce {
        /** Copies it into the response (RFC 8954), as a responder should. */
        ECHO,
        /** Answers with a nonce of its own: a replayed or substituted response. */
        WRONG,
        /** Leaves it out, as many responders do. */
        OMIT
    }

    /**
     * An OCSP responder run by the issuing CA itself (RFC 6960 section 4.2.2.2): a successful response to the DER
     * {@code OCSPReq}, signed by {@code issuer}, produced now with thisUpdate now (to the second) and nextUpdate a
     * day later; each requested certificate is good unless its serial number is in {@code revoked}.
     */
    public static byte[] ocspResponse(byte[] request, X509Certificate issuer, PrivateKey issuerKey,
                                      Map<BigInteger, Instant> revoked, Nonce nonce) {
        try {
            OCSPReq req = new OCSPReq(request);
            Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
            X509CertificateHolder issuerHolder = new JcaX509CertificateHolder(issuer);
            BasicOCSPRespBuilder b = new BasicOCSPRespBuilder(new RespID(issuerHolder.getSubject()));
            for (Req r : req.getRequestList()) {
                Instant revokedAt = revoked.get(r.getCertID().getSerialNumber());
                CertificateStatus status = revokedAt == null ? CertificateStatus.GOOD
                        : new RevokedStatus(Date.from(revokedAt), CRLReason.keyCompromise);
                b.addResponse(r.getCertID(), status, Date.from(now), Date.from(now.plus(1, ChronoUnit.DAYS)), null);
            }
            Extension requested = req.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            if (requested != null && nonce != Nonce.OMIT) {
                Extension answered = requested;
                if (nonce == Nonce.WRONG) {
                    byte[] other = new byte[16];
                    new SecureRandom().nextBytes(other);
                    answered = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
                            new DEROctetString(new DEROctetString(other)));
                }
                b.setResponseExtensions(new Extensions(answered));
            }
            return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL,
                    b.build(signer(issuerKey), new X509CertificateHolder[] {issuerHolder}, Date.from(now))).getEncoded();
        } catch (IOException | GeneralSecurityException | OperatorCreationException | OCSPException e) {
            throw new IllegalStateException(e);
        }
    }

    /** An OCSP error response, e.g. {@link OCSPRespBuilder#INTERNAL_ERROR} or {@link OCSPRespBuilder#UNAUTHORIZED}. */
    public static byte[] ocspError(int status) {
        try {
            return new OCSPRespBuilder().build(status, null).getEncoded();
        } catch (IOException | OCSPException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The test TSA: a granted RFC 3161 response to a DER {@code TimeStampReq}, issued now. */
    public byte[] timestampResponse(byte[] request) {
        return timestampResponse(request, key(Entity.TSA), List.of(x509(Entity.TSA), x509(Entity.ROOT_CA)));
    }

    /**
     * The test TSA, answering at {@code genTime} with token serial number {@code serial}: the same request gives
     * the same bytes (the TSA key is RSA).
     */
    public byte[] timestampResponse(byte[] request, Instant genTime, BigInteger serial) {
        return timestampResponse(request, key(Entity.TSA), List.of(x509(Entity.TSA), x509(Entity.ROOT_CA)), genTime,
                serial);
    }

    /** A TSA with key {@code tsaKey} and certificate {@code chain[0]}, sending {@code chain} in its tokens. */
    public static byte[] timestampResponse(byte[] request, PrivateKey tsaKey, List<X509Certificate> chain) {
        return timestampResponse(request, tsaKey, chain, Instant.now(), new BigInteger(64, new SecureRandom()));
    }

    /**
     * As {@link #timestampResponse(byte[], PrivateKey, List)}, with genTime (also the token's signing-time
     * attribute) and serial number given.
     */
    public static byte[] timestampResponse(byte[] request, PrivateKey tsaKey, List<X509Certificate> chain,
                                           Instant genTime, BigInteger serial) {
        try {
            String algorithm = tsaKey.getAlgorithm().equals("EC") ? "SHA256withECDSA" : "SHA256withRSA";
            Date when = Date.from(genTime);
            // BouncyCastle would add a signing-time attribute of its own, taken from the clock.
            AttributeTable signingTime = new AttributeTable(
                    new Attribute(CMSAttributes.signingTime, new DERSet(new Time(when))));
            TimeStampTokenGenerator tokens = new TimeStampTokenGenerator(
                    new JcaSimpleSignerInfoGeneratorBuilder()
                            .setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(signingTime))
                            .build(algorithm, tsaKey, chain.get(0)),
                    new JcaDigestCalculatorProviderBuilder().build()
                            .get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)),
                    new ASN1ObjectIdentifier(TSA_POLICY));
            tokens.addCertificates(new JcaCertStore(chain));
            return new TimeStampResponseGenerator(tokens, TSPAlgorithms.ALLOWED)
                    .generate(new TimeStampRequest(request), serial, when)
                    .getEncoded();
        } catch (IOException | GeneralSecurityException | OperatorCreationException | TSPException e) {
            throw new IllegalStateException(e);
        }
    }

    // ------------------------------------------------------------------ generation

    /** Start of the persisted PKI's validity (it lasts 20 × 365 days): fixed, so {@link #generate} is reproducible. */
    public static final Instant PKI_NOT_BEFORE = Instant.parse("2026-01-01T00:00:00Z");

    /**
     * Creates a new PKI, valid for 20 years from {@link #PKI_NOT_BEFORE}. Deterministic: each entity's key, serial
     * number and certificate signature come from {@link #deterministicRandom} seeded with its alias, so the same
     * JDK gives the same keys and certificates on every run.
     */
    public static TestPki generate(Path p12) {
        try {
            Instant notBefore = PKI_NOT_BEFORE;
            Instant notAfter = notBefore.plus(20 * 365, ChronoUnit.DAYS);
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);

            SecureRandom r = entityRandom(Entity.ROOT_CA);
            KeyPair rootKp = rsa(3072, r);
            X509Certificate root = issue("CN=dss-native Test Root CA,O=dss-native test PKI,C=IT", rootKp.getPublic(),
                    null, rootKp.getPrivate(), notBefore, notAfter, Profile.CA, Pointers.PERSISTED, r);
            put(ks, Entity.ROOT_CA, rootKp.getPrivate(), root);

            r = entityRandom(Entity.SIGNER_RSA);
            KeyPair rsaKp = rsa(3072, r);
            put(ks, Entity.SIGNER_RSA, rsaKp.getPrivate(), issue(
                    "CN=Mario Rossi (TEST),GIVENNAME=Mario,SURNAME=Rossi,SERIALNUMBER=TINIT-TEST00000000001,O=dss-native test PKI,C=IT",
                    rsaKp.getPublic(), root, rootKp.getPrivate(), notBefore, notAfter, Profile.SIGNER,
                    Pointers.PERSISTED, r), root);

            r = entityRandom(Entity.SIGNER_EC);
            KeyPair ecKp = ec(r);
            put(ks, Entity.SIGNER_EC, ecKp.getPrivate(), issue(
                    "CN=Giulia Bianchi (TEST),GIVENNAME=Giulia,SURNAME=Bianchi,SERIALNUMBER=TINIT-TEST00000000002,O=dss-native test PKI,C=IT",
                    ecKp.getPublic(), root, rootKp.getPrivate(), notBefore, notAfter, Profile.SIGNER,
                    Pointers.PERSISTED, r), root);

            r = entityRandom(Entity.TSA);
            KeyPair tsaKp = rsa(3072, r);
            put(ks, Entity.TSA, tsaKp.getPrivate(), issue("CN=dss-native Test TSA,O=dss-native test PKI,C=IT",
                    tsaKp.getPublic(), root, rootKp.getPrivate(), notBefore, notAfter, Profile.TSA,
                    Pointers.PERSISTED, r), root);

            r = entityRandom(Entity.LOTL_SIGNER);
            KeyPair lotlKp = rsa(3072, r);
            put(ks, Entity.LOTL_SIGNER, lotlKp.getPrivate(), issue("CN=dss-native Test LOTL Signer,O=dss-native test PKI,C=EU",
                    lotlKp.getPublic(), null, lotlKp.getPrivate(), notBefore, notAfter, Profile.LIST_SIGNER,
                    Pointers.PERSISTED, r));

            r = entityRandom(Entity.TL_SIGNER);
            KeyPair tlKp = rsa(3072, r);
            put(ks, Entity.TL_SIGNER, tlKp.getPrivate(), issue("CN=dss-native Test TL Signer,O=dss-native test PKI,C=IT",
                    tlKp.getPublic(), null, tlKp.getPrivate(), notBefore, notAfter, Profile.LIST_SIGNER,
                    Pointers.PERSISTED, r));

            r = entityRandom(Entity.OTHER_CA);
            KeyPair otherKp = ec(r);
            put(ks, Entity.OTHER_CA, otherKp.getPrivate(), issue("CN=dss-native Other Test CA,O=dss-native test PKI,C=DE",
                    otherKp.getPublic(), null, otherKp.getPrivate(), notBefore, notAfter, Profile.CA,
                    Pointers.PERSISTED, r));

            Files.createDirectories(p12.getParent());
            try (OutputStream out = Files.newOutputStream(p12)) {
                ks.store(out, password());
            }
            return new TestPki(ks);
        } catch (IOException | GeneralSecurityException | org.bouncycastle.operator.OperatorCreationException e) {
            throw new IllegalStateException("cannot generate test PKI", e);
        }
    }

    /** What a certificate is for: its basic constraints, key usage and extended key usage. */
    public enum Profile { CA, SIGNER, TSA, LIST_SIGNER, TLS_SERVER }

    /** Where a certificate points relying parties for revocation data and its issuer; null members: none. */
    public record Pointers(String crlUrl, String ocspUrl, String caIssuersUrl) {
        /** What the persisted PKI's certificates carry: the root's CRL at {@link #CRL_URL}, nothing else. */
        static final Pointers PERSISTED = new Pointers(CRL_URL, null, null);
    }

    /** A key pair's private half and the certificate issued for it. */
    public record Issued(PrivateKey key, X509Certificate cert) {
    }

    /**
     * An EC P-256 key and a certificate for it issued now by {@code issuer} (valid from a day ago for 30 days),
     * with the given profile and revocation/issuer pointers, for tests that need certificates of their own.
     */
    public static Issued issueNow(String subject, Profile profile, X509Certificate issuer, PrivateKey issuerKey,
                                  Pointers pointers) {
        try {
            KeyPair kp = ec();
            Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
            return new Issued(kp.getPrivate(), issue(subject, kp.getPublic(), issuer, issuerKey,
                    now.minus(1, ChronoUnit.DAYS), now.plus(30, ChronoUnit.DAYS), profile, pointers));
        } catch (IOException | GeneralSecurityException | org.bouncycastle.operator.OperatorCreationException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * A PKCS#12 key store (password {@link #PASSWORD}) with a TLS server key and certificate for 127.0.0.1 and
     * localhost, issued now by the test root, for loopback HTTPS tests.
     */
    public KeyStore tlsServerKeyStore() {
        try {
            KeyPair kp = ec();
            Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
            X509Certificate cert = issue("CN=localhost,O=dss-native test PKI,C=IT", kp.getPublic(), x509(Entity.ROOT_CA),
                    key(Entity.ROOT_CA), now.minus(1, ChronoUnit.DAYS), now.plus(30, ChronoUnit.DAYS), Profile.TLS_SERVER);
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            ks.setKeyEntry("tls", kp.getPrivate(), password(), new Certificate[] {cert, x509(Entity.ROOT_CA)});
            return ks;
        } catch (IOException | GeneralSecurityException | org.bouncycastle.operator.OperatorCreationException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Writes a PKCS#12 trust store (password {@code changeit}) holding only the test root. */
    public Path writeRootTrustStore(Path file) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            ks.setCertificateEntry("test-root", x509(Entity.ROOT_CA));
            Files.createDirectories(file.getParent());
            try (OutputStream out = Files.newOutputStream(file)) {
                ks.store(out, "changeit".toCharArray());
            }
            return file;
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A throw-away self-signed list signer (RSA of {@code rsaBits}, or EC P-256 when 0), for one test. */
    public static SyntheticTrustedLists.ListSigner ephemeralListSigner(String cn, int rsaBits,
                                                                         EncryptionAlgorithm algorithm) {
        try {
            KeyPair kp = rsaBits > 0 ? rsa(rsaBits) : ec();
            Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
            X509Certificate cert = issue("CN=" + cn + ",O=dss-native test PKI,C=IT", kp.getPublic(), null,
                    kp.getPrivate(), now.minus(1, ChronoUnit.DAYS), now.plus(365, ChronoUnit.DAYS), Profile.LIST_SIGNER);
            return new SyntheticTrustedLists.ListSigner(kp.getPrivate(), cert, algorithm);
        } catch (IOException | GeneralSecurityException | org.bouncycastle.operator.OperatorCreationException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void put(KeyStore ks, Entity e, PrivateKey key, X509Certificate... chain) throws GeneralSecurityException {
        ks.setKeyEntry(e.alias, key, password(), (Certificate[]) chain);
    }

    /**
     * A {@code SHA1PRNG} seeded only with {@code label}: the same label gives the same stream of bytes on every run
     * (on the same JDK), which makes key generation, serial numbers and ECDSA signatures reproducible. For test
     * material only: anyone who knows the label knows every key derived from it.
     */
    public static SecureRandom deterministicRandom(String label) {
        try {
            SecureRandom r = SecureRandom.getInstance("SHA1PRNG", "SUN");
            r.setSeed(label.getBytes(StandardCharsets.UTF_8)); // before any output: replaces OS seeding
            return r;
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new IllegalStateException(e);
        }
    }

    private static SecureRandom entityRandom(Entity e) {
        return deterministicRandom("dss-native test PKI/" + e.alias);
    }

    private static KeyPair rsa(int bits) throws GeneralSecurityException {
        return rsa(bits, new SecureRandom());
    }

    private static KeyPair rsa(int bits, SecureRandom random) throws GeneralSecurityException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA", "SunRsaSign");
        g.initialize(bits, random);
        return g.generateKeyPair();
    }

    private static KeyPair ec() throws GeneralSecurityException {
        return ec(new SecureRandom());
    }

    private static KeyPair ec(SecureRandom random) throws GeneralSecurityException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "SunEC");
        g.initialize(new ECGenParameterSpec("secp256r1"), random);
        return g.generateKeyPair();
    }

    /** RSA PKCS#1 v1.5 is deterministic; ECDSA draws its per-signature nonce from {@code random}. */
    private static ContentSigner signer(PrivateKey key, SecureRandom random)
            throws org.bouncycastle.operator.OperatorCreationException {
        String alg = key.getAlgorithm().equals("EC") ? "SHA256withECDSA" : "SHA256withRSA";
        return new JcaContentSignerBuilder(alg).setSecureRandom(random).build(key);
    }

    private static ContentSigner signer(PrivateKey key) throws org.bouncycastle.operator.OperatorCreationException {
        return signer(key, new SecureRandom());
    }

    private static X509Certificate issue(String subject, PublicKey publicKey, X509Certificate issuer, PrivateKey issuerKey,
                                         Instant notBefore, Instant notAfter, Profile profile)
            throws GeneralSecurityException, IOException, org.bouncycastle.operator.OperatorCreationException {
        return issue(subject, publicKey, issuer, issuerKey, notBefore, notAfter, profile, Pointers.PERSISTED);
    }

    private static X509Certificate issue(String subject, PublicKey publicKey, X509Certificate issuer, PrivateKey issuerKey,
                                         Instant notBefore, Instant notAfter, Profile profile, Pointers pointers)
            throws GeneralSecurityException, IOException, org.bouncycastle.operator.OperatorCreationException {
        return issue(subject, publicKey, issuer, issuerKey, notBefore, notAfter, profile, pointers, new SecureRandom());
    }

    /** {@code random} gives the serial number and, for an EC issuer, the signature's nonce. */
    private static X509Certificate issue(String subject, PublicKey publicKey, X509Certificate issuer, PrivateKey issuerKey,
                                         Instant notBefore, Instant notAfter, Profile profile, Pointers pointers,
                                         SecureRandom random)
            throws GeneralSecurityException, IOException, org.bouncycastle.operator.OperatorCreationException {
        X500Name subjectName = new X500Name(subject);
        X500Name issuerName = issuer == null ? subjectName
                : X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded());
        BigInteger serial = new BigInteger(127, random);
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(issuerName, serial, Date.from(notBefore),
                Date.from(notAfter), subjectName, publicKey);
        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
        b.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(publicKey));
        if (issuer != null) {
            b.addExtension(Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(issuer));
            if (pointers.crlUrl() != null) {
                DistributionPoint dp = new DistributionPoint(new DistributionPointName(new GeneralNames(
                        new GeneralName(GeneralName.uniformResourceIdentifier, pointers.crlUrl()))), null, null);
                b.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(new DistributionPoint[] {dp}));
            }
            List<AccessDescription> access = new java.util.ArrayList<>();
            if (pointers.ocspUrl() != null) {
                access.add(new AccessDescription(AccessDescription.id_ad_ocsp,
                        new GeneralName(GeneralName.uniformResourceIdentifier, pointers.ocspUrl())));
            }
            if (pointers.caIssuersUrl() != null) {
                access.add(new AccessDescription(AccessDescription.id_ad_caIssuers,
                        new GeneralName(GeneralName.uniformResourceIdentifier, pointers.caIssuersUrl())));
            }
            if (!access.isEmpty()) {
                b.addExtension(Extension.authorityInfoAccess, false,
                        new AuthorityInformationAccess(access.toArray(new AccessDescription[0])));
            }
        }
        switch (profile) {
            case CA -> {
                b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
                b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
            }
            case SIGNER -> {
                b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
                b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.nonRepudiation));
            }
            case TSA -> {
                b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
                b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
                b.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));
            }
            case TLS_SERVER -> {
                b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
                b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
                b.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
                b.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName[] {
                        new GeneralName(GeneralName.iPAddress, "127.0.0.1"),
                        new GeneralName(GeneralName.dNSName, "localhost")}));
            }
            case LIST_SIGNER -> {
                b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
                b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
                // id-tsl-kp-tslSigning (ETSI TS 119 612 annex B)
                b.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(
                        KeyPurposeId.getInstance(new org.bouncycastle.asn1.ASN1ObjectIdentifier("0.4.0.2231.3.0"))));
            }
        }
        return new JcaX509CertificateConverter().getCertificate(b.build(signer(issuerKey, random)));
    }
}
