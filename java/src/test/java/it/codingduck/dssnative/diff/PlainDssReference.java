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
 *   <li>base64/PEM-wrapped input decoded before validation (at most three layers), and input that is then neither
 *       a PDF nor a CMS {@code ContentInfo} refused as unsupported without asking DSS, by the same rules as the
 *       engine's input normalizer, written again here ({@link #looksLikeCms}, {@link #looksLikePdf});</li>
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

    /**
     * Rejections carry the code the engine is expected to give: INVALID_ARGUMENT for an empty document,
     * UNSUPPORTED_DOCUMENT for one that is neither a PDF nor a CMS after decoding, VALIDATION_FAILED when DSS
     * itself cannot process it.
     */
    public Outcome validate(byte[] input, List<Path> detached, Date validationTime) {
        if (input == null || input.length == 0) {
            return Outcome.rejected("INVALID_ARGUMENT", "document is empty");
        }
        byte[] bytes = decode(input);
        if (bytes == null) {
            return Outcome.rejected("UNSUPPORTED_DOCUMENT", "neither a PDF nor a CMS ContentInfo");
        }
        try {
            return validate(bytes, detached, validationTime, 0);
        } catch (RuntimeException e) {
            return Outcome.rejected("VALIDATION_FAILED", e.getClass().getSimpleName() + ": " + e.getMessage());
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
        return new Outcome(sigs, nested);
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
            return content != null && looksLikeCms(content) ? content : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Transport encodings removed at most, as in the engine (base64 of base64 of base64 still works). */
    private static final int MAX_DECODE_ROUNDS = 3;

    /**
     * The PDF or CMS inside up to {@value #MAX_DECODE_ROUNDS} layers of base64 (optionally PEM-armoured) text,
     * or null when there is none.
     */
    static byte[] decode(byte[] input) {
        byte[] bytes = input;
        for (int round = 0; ; round++) {
            if (looksLikeCms(bytes) || looksLikePdf(bytes)) {
                return bytes;
            }
            if (round == MAX_DECODE_ROUNDS) {
                return null;
            }
            String text = new String(bytes, StandardCharsets.ISO_8859_1);
            if (text.substring(0, Math.min(text.length(), 64 + 10)).contains("-----BEGIN")) {
                // PEM: the armour lines and any header lines ("Proc-Type: ...") are not base64
                StringBuilder body = new StringBuilder();
                for (String line : text.split("\\R")) {
                    if (!line.startsWith("-----") && !line.contains(":")) {
                        body.append(line);
                    }
                }
                text = body.toString();
            }
            text = text.replaceAll("[ \\t\\n\\r\\x0B\\f]+", "");
            if (text.length() < 4 || !text.matches("[A-Za-z0-9+/=_-]+")) {
                return null;
            }
            try {
                boolean urlSafe = text.indexOf('-') >= 0 || text.indexOf('_') >= 0;
                bytes = (urlSafe ? Base64.getUrlDecoder() : Base64.getDecoder()).decode(text);
            } catch (IllegalArgumentException e) {
                return null;
            }
        }
    }

    /** PDF 1.7 section 7.5.2: the header may be anywhere in the first 1024 bytes. */
    static boolean looksLikePdf(byte[] b) {
        String head = new String(b, 0, Math.min(b.length, 1024 + 5), StandardCharsets.ISO_8859_1);
        int at = head.indexOf("%PDF-");
        return at >= 0 && at <= 1024;
    }

    /**
     * A CMS {@code ContentInfo}: a SEQUENCE (0x30) with a well-formed length (short, long of one to four bytes, or
     * BER indefinite) whose first element is an OBJECT IDENTIFIER (0x06), the contentType. Text that starts with
     * '0' ("0 items in stock") or base64 that decodes to a 0x30 byte ("MAIL") is not; a truncated CMS still is.
     */
    static boolean looksLikeCms(byte[] b) {
        if (b.length < 4 || (b[0] & 0xFF) != 0x30) {
            return false;
        }
        int first = b[1] & 0xFF;
        int header = 2;
        if (first > 0x80) {
            int lengthBytes = first & 0x7F;
            if (lengthBytes > 4) {
                return false;
            }
            header += lengthBytes;
        }
        return header < b.length && (b[header] & 0xFF) == 0x06;
    }

    @Override
    public void close() {
        // nothing to release: the offline job holds no threads beyond the refresh
    }
}
