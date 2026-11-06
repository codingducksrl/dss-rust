/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.testsupport;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import eu.europa.esig.dss.xades.tsl.TrustedListV6SignatureParametersBuilder;

import it.codingduck.dssnative.testsupport.TestPki.Entity;

/**
 * Builds a signed synthetic EU LOTL (TSL v6) pointing at two national TLs, "IT" (listing the test root CA and
 * TSA) and "DE" (listing an unrelated CA), and serves them through {@link FakeHttp}. Generated per test run so
 * the lists never expire in the repository.
 */
public final class SyntheticTrustedLists {

    public static final String LOTL_URL = "https://lotl.dss-native.test/eu-lotl.xml";
    public static final String OJ_URL = "https://oj.dss-native.test/C/2026/0001/oj";
    public static final String IT_TL_URL = "https://tl.dss-native.test/IT.xml";
    public static final String DE_TL_URL = "https://tl.dss-native.test/DE.xml";
    public static final char[] OJ_KEYSTORE_PASSWORD = "dss-password".toCharArray();

    private static final String TSL_NS = "http://uri.etsi.org/02231/v2#";
    private static final String ADD_NS = "http://uri.etsi.org/02231/v2/additionaltypes#";
    private static final String GENERIC = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric";
    private static final String LOTL_TYPE = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists";
    private static final String MIME = "application/vnd.etsi.tsl+xml";

    /** A key that signs a list, its certificate, and optionally the signature scheme (default: from the key). */
    public record ListSigner(PrivateKey key, X509Certificate cert, EncryptionAlgorithm algorithm) {
        public static ListSigner of(TestPki pki, Entity e) {
            return new ListSigner(pki.key(e), pki.x509(e), null);
        }
    }

    private final TestPki pki;
    private final int sequenceNumber;
    private Duration nextUpdateIn = Duration.ofDays(180);
    private ListSigner nationalSigner;
    private String lotlUrl = LOTL_URL;
    private String itUrl = IT_TL_URL;
    private String deUrl = DE_TL_URL;

    public SyntheticTrustedLists(TestPki pki, int sequenceNumber) {
        this.pki = pki;
        this.sequenceNumber = sequenceNumber;
        this.nationalSigner = ListSigner.of(pki, Entity.TL_SIGNER);
    }

    /** Publishes the lists under {@code baseUrl} ({@code /eu-lotl.xml}, {@code /IT.xml}, {@code /DE.xml}). */
    public SyntheticTrustedLists withBaseUrl(String baseUrl) {
        this.lotlUrl = baseUrl + "/eu-lotl.xml";
        this.itUrl = baseUrl + "/IT.xml";
        this.deUrl = baseUrl + "/DE.xml";
        return this;
    }

    /** Sets every list's NextUpdate this far from the time it is built (default 180 days). */
    public SyntheticTrustedLists withNextUpdateIn(Duration duration) {
        this.nextUpdateIn = duration;
        return this;
    }

    /** Uses {@code signer} for the national TLs and announces its certificate for them in the LOTL. */
    public SyntheticTrustedLists withNationalSigner(ListSigner signer) {
        this.nationalSigner = signer;
        return this;
    }

    /** Registers LOTL and TLs on {@code http}; each request returns the same signed bytes. */
    public void serveOn(FakeHttp http) {
        http.route(lotlUrl, lotl());
        http.route(itUrl, tl("IT", Entity.ROOT_CA, Entity.TSA));
        http.route(deUrl, tl("DE", Entity.OTHER_CA, null));
    }

    /** Writes a PKCS#12 trust store holding the LOTL signer, standing in for the OJ keystore. */
    public static Path writeOjKeystore(TestPki pki, Path file) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            ks.setCertificateEntry("lotl-signer", pki.x509(Entity.LOTL_SIGNER));
            Files.createDirectories(file.getParent());
            try (OutputStream out = Files.newOutputStream(file)) {
                ks.store(out, OJ_KEYSTORE_PASSWORD);
            }
            return file;
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public byte[] lotl() {
        return lotlSignedBy(Entity.LOTL_SIGNER);
    }

    /** The LOTL signed by {@code signer}; anything but the LOTL signer is absent from the OJ keystore. */
    public byte[] lotlSignedBy(Entity signer) {
        String body = schemeInformation(LOTL_TYPE, "EU", "European Commission (dss-native TEST)",
                "http://uri.etsi.org/TrstSvc/TrustedList/StatusDetn/EUlistofthelists",
                "http://uri.etsi.org/TrstSvc/TrustedList/schemerules/EUlistofthelists",
                pointer(lotlUrl, pki.x509(Entity.LOTL_SIGNER), LOTL_TYPE, "EU")
                        + pointer(itUrl, nationalSigner.cert(), GENERIC, "IT")
                        + pointer(deUrl, nationalSigner.cert(), GENERIC, "DE"),
                lotlUrl);
        return sign(document(body, ""), ListSigner.of(pki, signer));
    }

    public byte[] tl(String territory, Entity ca, Entity tsa) {
        return tlSignedBy(territory, ca, tsa, nationalSigner);
    }

    /** A national TL signed by {@code signer}, whatever certificate the LOTL announces. */
    public byte[] tlSignedBy(String territory, Entity ca, Entity tsa, Entity signer) {
        return tlSignedBy(territory, ca, tsa, ListSigner.of(pki, signer));
    }

    private byte[] tlSignedBy(String territory, Entity ca, Entity tsa, ListSigner signer) {
        String services = service("http://uri.etsi.org/TrstSvc/Svctype/CA/QC", "Test CA/QC", ca);
        if (tsa != null) {
            services += service("http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST", "Test QTSA", tsa);
        }
        String tsp = "<tsl:TrustServiceProviderList><tsl:TrustServiceProvider><tsl:TSPInformation>"
                + "<tsl:TSPName><tsl:Name xml:lang=\"en\">dss-native Test TSP " + territory + "</tsl:Name></tsl:TSPName>"
                + address(territory)
                + "<tsl:TSPInformationURI><tsl:URI xml:lang=\"en\">https://tsp.dss-native.test/</tsl:URI></tsl:TSPInformationURI>"
                + "</tsl:TSPInformation><tsl:TSPServices>" + services + "</tsl:TSPServices>"
                + "</tsl:TrustServiceProvider></tsl:TrustServiceProviderList>";
        String body = schemeInformation(GENERIC, territory, "Supervisory body " + territory + " (dss-native TEST)",
                "http://uri.etsi.org/TrstSvc/TrustedList/StatusDetn/EUappropriate",
                "http://uri.etsi.org/TrstSvc/TrustedList/schemerules/EUcommon",
                pointer(lotlUrl, pki.x509(Entity.LOTL_SIGNER), LOTL_TYPE, "EU"),
                territory.equals("IT") ? itUrl : deUrl);
        return sign(document(body, tsp), signer);
    }

    private String schemeInformation(String type, String territory, String operator, String statusApproach,
                                     String communityRules, String pointers, String distributionPoint) {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        return "<tsl:SchemeInformation>"
                + "<tsl:TSLVersionIdentifier>6</tsl:TSLVersionIdentifier>"
                + "<tsl:TSLSequenceNumber>" + sequenceNumber + "</tsl:TSLSequenceNumber>"
                + "<tsl:TSLType>" + type + "</tsl:TSLType>"
                + "<tsl:SchemeOperatorName><tsl:Name xml:lang=\"en\">" + operator + "</tsl:Name></tsl:SchemeOperatorName>"
                + "<tsl:SchemeOperatorAddress>" + addressBody(territory) + "</tsl:SchemeOperatorAddress>"
                + "<tsl:SchemeName><tsl:Name xml:lang=\"en\">" + territory + ":dss-native synthetic trusted list</tsl:Name></tsl:SchemeName>"
                + "<tsl:SchemeInformationURI><tsl:URI xml:lang=\"en\">" + OJ_URL + "</tsl:URI></tsl:SchemeInformationURI>"
                + "<tsl:StatusDeterminationApproach>" + statusApproach + "</tsl:StatusDeterminationApproach>"
                + "<tsl:SchemeTypeCommunityRules><tsl:URI xml:lang=\"en\">" + communityRules + "</tsl:URI></tsl:SchemeTypeCommunityRules>"
                + "<tsl:SchemeTerritory>" + territory + "</tsl:SchemeTerritory>"
                + "<tsl:PolicyOrLegalNotice><tsl:TSLLegalNotice xml:lang=\"en\">Synthetic test data. Not a real trusted list.</tsl:TSLLegalNotice></tsl:PolicyOrLegalNotice>"
                + "<tsl:HistoricalInformationPeriod>65535</tsl:HistoricalInformationPeriod>"
                + "<tsl:PointersToOtherTSL>" + pointers + "</tsl:PointersToOtherTSL>"
                + "<tsl:ListIssueDateTime>" + now.minus(1, ChronoUnit.DAYS) + "</tsl:ListIssueDateTime>"
                + "<tsl:NextUpdate><tsl:dateTime>" + now.plus(nextUpdateIn) + "</tsl:dateTime></tsl:NextUpdate>"
                + "<tsl:DistributionPoints><tsl:URI>" + distributionPoint + "</tsl:URI></tsl:DistributionPoints>"
                + "</tsl:SchemeInformation>";
    }

    private static String address(String territory) {
        return "<tsl:TSPAddress>" + addressBody(territory) + "</tsl:TSPAddress>";
    }

    private static String addressBody(String territory) {
        return "<tsl:PostalAddresses><tsl:PostalAddress xml:lang=\"en\">"
                + "<tsl:StreetAddress>1 Example Street</tsl:StreetAddress><tsl:Locality>Testville</tsl:Locality>"
                + "<tsl:CountryName>" + territory + "</tsl:CountryName></tsl:PostalAddress></tsl:PostalAddresses>"
                + "<tsl:ElectronicAddress><tsl:URI xml:lang=\"en\">mailto:tl@dss-native.test</tsl:URI></tsl:ElectronicAddress>";
    }

    private String pointer(String location, X509Certificate signer, String type, String territory) {
        return "<tsl:OtherTSLPointer>"
                + "<tsl:ServiceDigitalIdentities><tsl:ServiceDigitalIdentity><tsl:DigitalId><tsl:X509Certificate>"
                + b64(signer) + "</tsl:X509Certificate></tsl:DigitalId></tsl:ServiceDigitalIdentity></tsl:ServiceDigitalIdentities>"
                + "<tsl:TSLLocation>" + location + "</tsl:TSLLocation>"
                + "<tsl:AdditionalInformation>"
                + "<tsl:OtherInformation><tsl:TSLType>" + type + "</tsl:TSLType></tsl:OtherInformation>"
                + "<tsl:OtherInformation><tsl:SchemeOperatorName><tsl:Name xml:lang=\"en\">Operator " + territory
                + "</tsl:Name></tsl:SchemeOperatorName></tsl:OtherInformation>"
                + "<tsl:OtherInformation><tsl:SchemeTerritory>" + territory + "</tsl:SchemeTerritory></tsl:OtherInformation>"
                + "<tsl:OtherInformation><add:MimeType>" + MIME + "</add:MimeType></tsl:OtherInformation>"
                + "</tsl:AdditionalInformation>"
                + "</tsl:OtherTSLPointer>";
    }

    private String service(String type, String name, Entity cert) {
        return "<tsl:TSPService><tsl:ServiceInformation>"
                + "<tsl:ServiceTypeIdentifier>" + type + "</tsl:ServiceTypeIdentifier>"
                + "<tsl:ServiceName><tsl:Name xml:lang=\"en\">" + name + "</tsl:Name></tsl:ServiceName>"
                + "<tsl:ServiceDigitalIdentity><tsl:DigitalId><tsl:X509Certificate>" + b64(pki.x509(cert))
                + "</tsl:X509Certificate></tsl:DigitalId></tsl:ServiceDigitalIdentity>"
                + "<tsl:ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</tsl:ServiceStatus>"
                + "<tsl:StatusStartingTime>2020-01-01T00:00:00Z</tsl:StatusStartingTime>"
                + "</tsl:ServiceInformation></tsl:TSPService>";
    }

    private static String document(String schemeInformation, String providers) {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                + "<tsl:TrustServiceStatusList xmlns:tsl=\"" + TSL_NS + "\" xmlns:add=\"" + ADD_NS + "\""
                + " Id=\"TrustServiceStatusList-1\" TSLTag=\"http://uri.etsi.org/19612/TSLTag\">"
                + schemeInformation + providers
                + "</tsl:TrustServiceStatusList>";
    }

    private static String b64(X509Certificate cert) {
        try {
            return Base64.getEncoder().encodeToString(cert.getEncoded());
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static byte[] sign(String xml, ListSigner signer) {
        DSSDocument doc = new InMemoryDocument(xml.getBytes(StandardCharsets.UTF_8), "tl.xml");
        TrustedListV6SignatureParametersBuilder builder =
                new TrustedListV6SignatureParametersBuilder(new CertificateToken(signer.cert()), doc);
        if (signer.algorithm() != null) {
            builder.setEncryptionAlgorithm(signer.algorithm());
        }
        XAdESSignatureParameters params = builder.build();
        XAdESService service = new XAdESService(new CommonCertificateVerifier());
        ToBeSigned tbs = service.getDataToSign(doc, params);
        SignatureValue value = Signing.sign(tbs, params.getSignatureAlgorithm(), signer.key());
        return DSSUtils.toByteArray(service.signDocument(doc, params, value));
    }
}
