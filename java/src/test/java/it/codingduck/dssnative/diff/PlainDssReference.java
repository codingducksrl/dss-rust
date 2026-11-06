/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.diff;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import eu.europa.esig.dss.cades.validation.CMSDocumentValidator;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
import eu.europa.esig.dss.pdf.modifications.DefaultPdfDifferencesFinder;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.tsl.function.GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate;
import eu.europa.esig.dss.tsl.function.OfficialJournalSchemeInformationURI;
import eu.europa.esig.dss.tsl.function.TLPredicateFactory;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.sync.ExpirationAndSignatureCheckStrategy;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

import it.codingduck.dssnative.engine.EngineConfig;

/**
 * The reference side of the differential test: DSS used directly, as in the DSS cookbook, without any dss-native
 * engine code. Only {@link EngineConfig} is shared, to read the same {@code config_json}.
 *
 * <p>The few deliberate dss-native behaviours are reproduced here independently, so that "different" means a bug
 * rather than a design choice:
 * <ul>
 *   <li>trusted lists synchronized only when their signature is valid ({@code tl_sync});</li>
 *   <li>PDF visual comparison off;</li>
 *   <li>base64/PEM-wrapped input decoded before validation;</li>
 *   <li>a CAdES envelope inside the signed content validated as a nested level.</li>
 * </ul>
 */
public final class PlainDssReference implements AutoCloseable {

    private final EngineConfig config;
    private final TrustedListsCertificateSource trustedLists = new TrustedListsCertificateSource();
    private final CommonTrustedCertificateSource extraTrusted = new CommonTrustedCertificateSource();

    public PlainDssReference(Path cacheDir, EngineConfig config) throws IOException, GeneralSecurityException {
        this.config = config;

        LOTLSource lotl = new LOTLSource();
        lotl.setUrl(config.lotlUrl);
        lotl.setCertificateSource(new KeyStoreCertificateSource(config.ojKeystorePath.toFile(),
                config.ojKeystoreType, config.ojKeystorePassword));
        lotl.setPivotSupport(config.pivotSupport);
        lotl.setSigningCertificatesAnnouncementPredicate(new OfficialJournalSchemeInformationURI(config.ojUrl));
        if (config.useSunsetDate) {
            lotl.setTrustAnchorValidityPredicate(new GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate());
        }
        if (!config.tlVersions.isEmpty()) {
            lotl.setTLVersions(config.tlVersions);
        }
        if (!config.countries.isEmpty()) {
            lotl.setTlPredicate(TLPredicateFactory.createEUTLCountryCodePredicate(config.countries.toArray(String[]::new)));
        }
        FileCacheDataLoader offline = new FileCacheDataLoader();
        offline.setCacheExpirationTime(-1);
        offline.setDataLoader(new IgnoreDataLoader());
        offline.setFileCacheDirectory(cacheDir.resolve("tl").toFile());
        ExpirationAndSignatureCheckStrategy sync = new ExpirationAndSignatureCheckStrategy();
        sync.setAcceptInvalidListOfTrustedLists(config.tlAcceptInvalidSignature);
        sync.setAcceptInvalidTrustedList(config.tlAcceptInvalidSignature);
        sync.setAcceptExpiredListOfTrustedLists(config.tlAcceptExpired);
        sync.setAcceptExpiredTrustedList(config.tlAcceptExpired);

        TLValidationJob job = new TLValidationJob();
        job.setListOfTrustedListSources(lotl);
        job.setOfflineDataLoader(offline);
        job.setTrustedListCertificateSource(trustedLists);
        job.setSynchronizationStrategy(sync);
        job.offlineRefresh();

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        for (Path p : config.extraTrustedCertificates) {
            for (Certificate c : cf.generateCertificates(new ByteArrayInputStream(Files.readAllBytes(p)))) {
                extraTrusted.addCertificate(new CertificateToken((X509Certificate) c));
            }
        }
    }

    public int trustedListCertificates() {
        return trustedLists.getNumberOfCertificates();
    }

    public Outcome validate(byte[] input, List<Path> detached, Date validationTime) {
        try {
            return validate(decode(input), detached, validationTime, 0);
        } catch (RuntimeException e) {
            return Outcome.rejected(e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private Outcome validate(byte[] bytes, List<Path> detached, Date validationTime, int depth) {
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new InMemoryDocument(bytes));
        if (validator instanceof PDFDocumentValidator pdf) {
            IPdfObjFactory factory = new ServiceLoaderPdfObjFactory();
            DefaultPdfDifferencesFinder differences = new DefaultPdfDifferencesFinder();
            differences.setMaximalPagesAmountForVisualComparison(0);
            factory.setPdfDifferencesFinder(differences);
            pdf.setPdfObjFactory(factory);
        }
        validator.setCertificateVerifier(verifier());
        validator.setLocale(Locale.ENGLISH);
        if (validationTime != null) {
            validator.setValidationTime(validationTime);
        }
        if (depth == 0 && !detached.isEmpty()) {
            List<DSSDocument> docs = new ArrayList<>();
            detached.forEach(p -> docs.add(new FileDocument(p.toFile())));
            validator.setDetachedContents(docs);
        }
        Reports reports = validator.validateDocument();
        SimpleReport simple = reports.getSimpleReport();

        List<Outcome.SignatureRecord> sigs = new ArrayList<>();
        for (String id : simple.getSignatureIdList()) {
            var signature = reports.getDiagnosticData().getSignatureById(id);
            var cert = signature == null ? null : signature.getSigningCertificate();
            sigs.add(new Outcome.SignatureRecord(id,
                    simple.getIndication(id) == null ? null : simple.getIndication(id).name(),
                    simple.getSubIndication(id) == null ? null : simple.getSubIndication(id).name(),
                    simple.getSignatureFormat(id) == null ? null : simple.getSignatureFormat(id).toString(),
                    simple.getSignatureQualification(id) == null ? null : simple.getSignatureQualification(id).name(),
                    Outcome.iso(simple.getSigningTime(id)), cert == null ? null : cert.getCertificateDN()));
        }

        List<Outcome> nested = new ArrayList<>();
        if (validator instanceof CMSDocumentValidator && !sigs.isEmpty() && depth < 7) {
            byte[] inner = envelopedCms(validator, sigs.get(0).id());
            if (inner != null) {
                nested.add(validate(inner, List.of(), validationTime, depth + 1));
            }
        }
        return new Outcome(null, sigs, nested);
    }

    private CommonCertificateVerifier verifier() {
        CommonCertificateVerifier cv = new CommonCertificateVerifier();
        cv.setTrustedCertSources(trustedLists, extraTrusted);
        if (config.revocation == EngineConfig.Revocation.ONLINE) {
            cv.setCrlSource(new OnlineCRLSource());
            cv.setOcspSource(new OnlineOCSPSource());
        } else {
            cv.setCrlSource(null);
            cv.setOcspSource(null);
        }
        cv.setAIASource(config.aiaFetching ? new DefaultAIASource(new CommonsDataLoader()) : null);
        return cv;
    }

    private static byte[] envelopedCms(SignedDocumentValidator validator, String signatureId) {
        try {
            List<DSSDocument> originals = validator.getOriginalDocuments(signatureId);
            if (originals.size() != 1) {
                return null;
            }
            byte[] content = decode(DSSUtils.toByteArray(originals.get(0)));
            return content.length > 1 && (content[0] & 0xFF) == 0x30 ? content : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Base64 (optionally PEM-armoured) text to bytes; anything starting like DER or PDF is left alone. */
    static byte[] decode(byte[] input) {
        byte[] bytes = input;
        for (int round = 0; round < 3; round++) {
            if (bytes.length > 1 && (bytes[0] & 0xFF) == 0x30) {
                return bytes;
            }
            String head = new String(bytes, 0, Math.min(bytes.length, 1024), StandardCharsets.ISO_8859_1);
            if (head.contains("%PDF-")) {
                return bytes;
            }
            StringBuilder b64 = new StringBuilder();
            for (String line : new String(bytes, StandardCharsets.US_ASCII).split("\\R")) {
                if (!line.startsWith("-----")) {
                    b64.append(line.strip());
                }
            }
            try {
                bytes = Base64.getMimeDecoder().decode(b64.toString().replace('-', '+').replace('_', '/'));
            } catch (IllegalArgumentException e) {
                return input;
            }
        }
        return bytes;
    }

    @Override
    public void close() {
        // nothing to release: the offline job holds no threads beyond the refresh
    }
}
