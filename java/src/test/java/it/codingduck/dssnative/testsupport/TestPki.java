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
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
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
 * fixtures stay verifiable; regenerate with {@code scripts/generate-fixtures.sh --new-pki}.
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

    private final KeyStore store;

    private TestPki(KeyStore store) {
        this.store = store;
    }

    public static Path defaultLocation() {
        return Fixtures.dir().resolve("pki/test-pki.p12");
    }

    public static TestPki load() {
        return load(defaultLocation());
    }

    public static TestPki load(Path p12) {
        try (InputStream in = Files.newInputStream(p12)) {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(in, PASSWORD);
            return new TestPki(ks);
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException("cannot load test PKI " + p12
                    + " (run scripts/generate-fixtures.sh)", e);
        }
    }

    public X509Certificate x509(Entity e) {
        try {
            return (X509Certificate) store.getCertificate(e.alias);
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException(ex);
        }
    }

    public CertificateToken token(Entity e) {
        return new CertificateToken(x509(e));
    }

    public PrivateKey key(Entity e) {
        try {
            return (PrivateKey) store.getKey(e.alias, PASSWORD);
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException(ex);
        }
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
        try {
            Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
            X509Certificate root = x509(Entity.ROOT_CA);
            X509v2CRLBuilder b = new X509v2CRLBuilder(X500Name.getInstance(root.getSubjectX500Principal().getEncoded()),
                    Date.from(now));
            b.setNextUpdate(Date.from(now.plus(7, ChronoUnit.DAYS)));
            b.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(now.getEpochSecond())));
            b.addExtension(Extension.authorityKeyIdentifier, false,
                    new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(root));
            X509CRLHolder crl = b.build(signer(key(Entity.ROOT_CA)));
            return crl.getEncoded();
        } catch (IOException | GeneralSecurityException | org.bouncycastle.operator.OperatorCreationException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The test TSA: a granted RFC 3161 response to a DER {@code TimeStampReq}, issued now. */
    public byte[] timestampResponse(byte[] request) {
        try {
            TimeStampTokenGenerator tokens = new TimeStampTokenGenerator(
                    new JcaSimpleSignerInfoGeneratorBuilder().build("SHA256withRSA", key(Entity.TSA), x509(Entity.TSA)),
                    new JcaDigestCalculatorProviderBuilder().build()
                            .get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)),
                    new ASN1ObjectIdentifier(TSA_POLICY));
            tokens.addCertificates(new JcaCertStore(List.of(x509(Entity.TSA), x509(Entity.ROOT_CA))));
            return new TimeStampResponseGenerator(tokens, TSPAlgorithms.ALLOWED)
                    .generate(new TimeStampRequest(request), new BigInteger(64, new SecureRandom()), new Date())
                    .getEncoded();
        } catch (IOException | GeneralSecurityException | OperatorCreationException | TSPException e) {
            throw new IllegalStateException(e);
        }
    }

    // ------------------------------------------------------------------ generation

    /** Creates a new PKI, valid for 20 years from the start of the current year. */
    public static TestPki generate(Path p12) {
        try {
            Instant notBefore = Instant.parse(java.time.Year.now() + "-01-01T00:00:00Z");
            Instant notAfter = notBefore.plus(20 * 365, ChronoUnit.DAYS);
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);

            KeyPair rootKp = rsa(3072);
            X509Certificate root = issue("CN=dss-native Test Root CA,O=dss-native test PKI,C=IT", rootKp.getPublic(),
                    null, rootKp.getPrivate(), notBefore, notAfter, Profile.CA);
            put(ks, Entity.ROOT_CA, rootKp.getPrivate(), root);

            KeyPair rsaKp = rsa(3072);
            put(ks, Entity.SIGNER_RSA, rsaKp.getPrivate(), issue(
                    "CN=Mario Rossi (TEST),GIVENNAME=Mario,SURNAME=Rossi,SERIALNUMBER=TINIT-TEST00000000001,O=dss-native test PKI,C=IT",
                    rsaKp.getPublic(), root, rootKp.getPrivate(), notBefore, notAfter, Profile.SIGNER), root);

            KeyPair ecKp = ec();
            put(ks, Entity.SIGNER_EC, ecKp.getPrivate(), issue(
                    "CN=Giulia Bianchi (TEST),GIVENNAME=Giulia,SURNAME=Bianchi,SERIALNUMBER=TINIT-TEST00000000002,O=dss-native test PKI,C=IT",
                    ecKp.getPublic(), root, rootKp.getPrivate(), notBefore, notAfter, Profile.SIGNER), root);

            KeyPair tsaKp = rsa(3072);
            put(ks, Entity.TSA, tsaKp.getPrivate(), issue("CN=dss-native Test TSA,O=dss-native test PKI,C=IT",
                    tsaKp.getPublic(), root, rootKp.getPrivate(), notBefore, notAfter, Profile.TSA), root);

            KeyPair lotlKp = rsa(3072);
            put(ks, Entity.LOTL_SIGNER, lotlKp.getPrivate(), issue("CN=dss-native Test LOTL Signer,O=dss-native test PKI,C=EU",
                    lotlKp.getPublic(), null, lotlKp.getPrivate(), notBefore, notAfter, Profile.LIST_SIGNER));

            KeyPair tlKp = rsa(3072);
            put(ks, Entity.TL_SIGNER, tlKp.getPrivate(), issue("CN=dss-native Test TL Signer,O=dss-native test PKI,C=IT",
                    tlKp.getPublic(), null, tlKp.getPrivate(), notBefore, notAfter, Profile.LIST_SIGNER));

            KeyPair otherKp = ec();
            put(ks, Entity.OTHER_CA, otherKp.getPrivate(), issue("CN=dss-native Other Test CA,O=dss-native test PKI,C=DE",
                    otherKp.getPublic(), null, otherKp.getPrivate(), notBefore, notAfter, Profile.CA));

            Files.createDirectories(p12.getParent());
            try (OutputStream out = Files.newOutputStream(p12)) {
                ks.store(out, PASSWORD);
            }
            return new TestPki(ks);
        } catch (IOException | GeneralSecurityException | org.bouncycastle.operator.OperatorCreationException e) {
            throw new IllegalStateException("cannot generate test PKI", e);
        }
    }

    private enum Profile { CA, SIGNER, TSA, LIST_SIGNER, TLS_SERVER }

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
            ks.setKeyEntry("tls", kp.getPrivate(), PASSWORD, new Certificate[] {cert, x509(Entity.ROOT_CA)});
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
        ks.setKeyEntry(e.alias, key, PASSWORD, (Certificate[]) chain);
    }

    private static KeyPair rsa(int bits) throws GeneralSecurityException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(bits, new SecureRandom());
        return g.generateKeyPair();
    }

    private static KeyPair ec() throws GeneralSecurityException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        return g.generateKeyPair();
    }

    private static ContentSigner signer(PrivateKey key) throws org.bouncycastle.operator.OperatorCreationException {
        String alg = key.getAlgorithm().equals("EC") ? "SHA256withECDSA" : "SHA256withRSA";
        return new JcaContentSignerBuilder(alg).build(key);
    }

    private static X509Certificate issue(String subject, PublicKey publicKey, X509Certificate issuer, PrivateKey issuerKey,
                                         Instant notBefore, Instant notAfter, Profile profile)
            throws GeneralSecurityException, IOException, org.bouncycastle.operator.OperatorCreationException {
        X500Name subjectName = new X500Name(subject);
        X500Name issuerName = issuer == null ? subjectName
                : X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded());
        BigInteger serial = new BigInteger(127, new SecureRandom());
        X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(issuerName, serial, Date.from(notBefore),
                Date.from(notAfter), subjectName, publicKey);
        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
        b.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(publicKey));
        if (issuer != null) {
            b.addExtension(Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(issuer));
            DistributionPoint dp = new DistributionPoint(new DistributionPointName(
                    new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, CRL_URL))), null, null);
            b.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(new DistributionPoint[] {dp}));
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
        return new JcaX509CertificateConverter().getCertificate(b.build(signer(issuerKey)));
    }
}
