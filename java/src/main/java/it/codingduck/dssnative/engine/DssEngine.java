/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Date;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.cades.validation.CMSDocumentValidator;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pdf.modifications.DefaultPdfDifferencesFinder;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

import it.codingduck.dssnative.visible.AwtFreePdfObjFactory;

/**
 * The DSS validation engine. Pure Java: no GraalVM API here, so everything is testable on a normal JVM.
 *
 * <p>Thread-safe: {@link #validate}, {@link #extend}, {@link #prepareSignature} and {@link #completeSignature} may
 * run on any number of threads, concurrently with {@link #refreshTrustedListsOnline()}.
 */
public final class DssEngine implements AutoCloseable {

    private static final Logger LOG = LoggerFactory.getLogger(DssEngine.class);

    /** Bound on {@code .p7m.p7m…} unwrapping. */
    static final int MAX_NESTING = 8;

    private final EngineConfig config;
    private final DataLoader httpLoader;
    private final DataLoader ocspLoader;
    private final TrustedListManager trustedLists;
    private final CommonTrustedCertificateSource extraTrusted;
    private final TrustedListManager.RefreshRecord initialLoad;
    /** The configured TSA ({@code tsa.url}); null when there is none. */
    private final TSPSource tspSource;

    /**
     * Builds the engine and loads the trusted lists from {@code cacheDir} (offline; never touches the network).
     *
     * @param httpLoader used for CRL and AIA. Tests pass an in-memory loader.
     * @param ocspLoader used for OCSP requests (needs the OCSP content type); null means {@code httpLoader}.
     * @param tlLoader   used to download the LOTL and TLs; null means {@code httpLoader}.
     * @param tsaLoader  used for timestamp requests to {@code tsa.url} (needs the RFC 3161 content type); null
     *                   means {@code httpLoader}.
     */
    public DssEngine(Path cacheDir, EngineConfig config, DataLoader httpLoader, DataLoader ocspLoader,
                     DataLoader tlLoader, DataLoader tsaLoader) {
        this.config = config;
        this.httpLoader = httpLoader;
        this.ocspLoader = ocspLoader != null ? ocspLoader : httpLoader;
        this.tspSource = config.tsaUrl == null ? null
                : new OnlineTSPSource(config.tsaUrl.toString(), tsaLoader != null ? tsaLoader : httpLoader);
        this.extraTrusted = loadExtraTrusted(config.extraTrustedCertificates);
        this.trustedLists = new TrustedListManager(cacheDir, config, tlLoader != null ? tlLoader : httpLoader);
        try {
            this.initialLoad = config.tlSnapshot != null ? trustedLists.importSnapshot(config.tlSnapshot)
                    : trustedLists.offlineRefresh();
        } catch (RuntimeException e) {
            trustedLists.close(); // its trusted-list threads
            throw e;
        }
        LOG.info("Trusted lists loaded from {}: {} certificates",
                config.tlSnapshot != null ? "snapshot " + config.tlSnapshot : "cache", initialLoad.trustedCertificates());
    }

    public DssEngine(Path cacheDir, EngineConfig config, DataLoader httpLoader, DataLoader ocspLoader,
                     DataLoader tlLoader) {
        this(cacheDir, config, httpLoader, ocspLoader, tlLoader, null);
    }

    public DssEngine(Path cacheDir, EngineConfig config, DataLoader httpLoader, DataLoader ocspLoader) {
        this(cacheDir, config, httpLoader, ocspLoader, null);
    }

    /** Engine with DSS's Apache HttpClient loaders, configured from {@code config.http}. */
    public static DssEngine create(Path cacheDir, EngineConfig config) {
        CommonsDataLoader tlLoader = withTimeouts(new CommonsDataLoader(), config);
        if (!config.tlVerifyTls) {
            // Some national TL hosts use server certificates the JDK trust store does not cover (ES and HU in
            // 2026-10). TL authenticity comes from the XML signature, checked against the LOTL (itself checked
            // against the OJ keystore), and badly signed lists are never used, so TLS server authentication
            // adds nothing here. CRL/OCSP/AIA downloads keep normal TLS checks.
            tlLoader.setTrustStrategy(TrustAllStrategy.INSTANCE);
        }
        return new DssEngine(cacheDir, config, withTimeouts(new CommonsDataLoader(), config),
                withTimeouts(new OCSPDataLoader(), config), tlLoader, tsaLoader(config));
    }

    /** Sends RFC 3161 requests, with the TSA's credentials if it needs them. Same TLS trust as CRL/OCSP. */
    private static CommonsDataLoader tsaLoader(EngineConfig config) {
        CommonsDataLoader loader = withTimeouts(new TimestampDataLoader(), config);
        if (config.tsaUsername != null) {
            // Any auth scheme the server asks for, on the TSA's host and port (-1 when the URL has none: any port).
            loader.addAuthentication(config.tsaUrl.getHost(), config.tsaUrl.getPort(), null, config.tsaUsername,
                    config.tsaPassword);
            loader.setPreemptiveAuthentication(true);
        }
        return loader;
    }

    private static CommonsDataLoader withTimeouts(CommonsDataLoader loader, EngineConfig config) {
        loader.setTimeoutConnection(config.httpConnectTimeoutMs);
        loader.setTimeoutConnectionRequest(config.httpConnectTimeoutMs);
        loader.setTimeoutResponse(config.httpResponseTimeoutMs);
        loader.setTimeoutSocket(config.httpResponseTimeoutMs);
        if (config.httpsTrustStorePath != null) {
            // Replaces the default CA set (in the native library: the build JDK's cacerts, embedded at build time).
            if (!Files.isRegularFile(config.httpsTrustStorePath)) {
                throw new DssError(DssError.Code.INVALID_CONFIG,
                        "http.trust_store.path not found: " + config.httpsTrustStorePath);
            }
            loader.setSslTruststore(new FileDocument(config.httpsTrustStorePath.toFile()));
            loader.setSslTruststoreType(config.httpsTrustStoreType);
            loader.setSslTruststorePassword(config.httpsTrustStorePassword);
        }
        return loader;
    }

    private static CommonTrustedCertificateSource loadExtraTrusted(List<Path> paths) {
        CommonTrustedCertificateSource source = new CommonTrustedCertificateSource();
        for (Path p : paths) {
            try {
                for (CertificateToken token : readCertificates(Files.readAllBytes(p))) {
                    source.addCertificate(token);
                }
            } catch (IOException | RuntimeException e) {
                throw new DssError(DssError.Code.INVALID_CONFIG, "cannot read trusted certificate " + p + ": " + e);
            }
        }
        return source;
    }

    /** A PEM bundle (one or more CERTIFICATE blocks) or a single DER certificate. */
    static List<CertificateToken> readCertificates(byte[] bytes) {
        String text = new String(bytes, StandardCharsets.US_ASCII);
        List<CertificateToken> out = new ArrayList<>();
        if (!text.contains("-----BEGIN CERTIFICATE-----")) {
            out.add(DSSUtils.loadCertificate(bytes));
            return out;
        }
        Matcher m = PEM_CERT.matcher(text);
        while (m.find()) {
            out.add(DSSUtils.loadCertificateFromBase64EncodedString(m.group(1).replaceAll("\\s+", "")));
        }
        return out;
    }

    private static final Pattern PEM_CERT =
            Pattern.compile("-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", Pattern.DOTALL);

    public TrustedListManager.RefreshRecord initialLoad() {
        return initialLoad;
    }

    public TrustedListManager.RefreshRecord refreshTrustedListsOnline() {
        return trustedLists.onlineRefresh();
    }

    public Map<String, Object> trustedListStatus() {
        return trustedLists.status();
    }

    /** The loaded trusted lists as a trusted-list snapshot file ({@code tl_snapshot} in another engine's config). */
    public TrustedListManager.Exported exportTlSnapshot() {
        return trustedLists.exportSnapshot();
    }

    public ValidationResult validate(byte[] document, ValidationOptions options) {
        if (document == null || document.length == 0) {
            throw new DssError(DssError.Code.INVALID_ARGUMENT, "document is empty");
        }
        TrustedListManager.Snapshot snapshot = trustSnapshot();
        InputNormalizer.Normalized input = InputNormalizer.normalize(document);
        if (input.type() == InputNormalizer.Type.UNKNOWN) {
            throw new DssError(DssError.Code.UNSUPPORTED_DOCUMENT,
                    "not a PDF or CMS/CAdES document (also tried base64 and PEM decoding)");
        }
        Set<ReportKind> reports = options.reports != null ? options.reports : config.defaultReports;
        CommonCertificateVerifier verifier = certificateVerifier(snapshot);
        return validateLevel(input, options, reports, verifier, 0);
    }

    private ValidationResult validateLevel(InputNormalizer.Normalized input, ValidationOptions options,
                                           Set<ReportKind> reports, CommonCertificateVerifier verifier, int depth) {
        String name = options.filename != null ? options.filename
                : (input.type() == InputNormalizer.Type.PDF ? "document.pdf" : "document.p7m");
        if (depth > 0) {
            name = name + "#nested-" + depth;
        }
        DSSDocument doc = new InMemoryDocument(input.bytes(), name);

        SignedDocumentValidator validator;
        try {
            validator = input.type() == InputNormalizer.Type.PDF ? pdfValidator(doc) : new CMSDocumentValidator(doc);
        } catch (DSSException | IllegalInputException | IllegalArgumentException e) {
            throw new DssError(DssError.Code.VALIDATION_FAILED, "cannot parse document: " + e.getMessage(), e);
        }
        validator.setCertificateVerifier(verifier);
        validator.setLocale(Locale.ENGLISH);
        validator.setEnableEtsiValidationReport(reports.contains(ReportKind.ETSI));
        if (options.validationTime != null) {
            validator.setValidationTime(Date.from(options.validationTime));
        }
        if (depth == 0 && !options.detachedContents.isEmpty()) {
            validator.setDetachedContents(options.detachedContents);
        }

        Reports dssReports;
        try {
            dssReports = validator.validateDocument();
        } catch (DSSException | IllegalInputException e) {
            throw new DssError(DssError.Code.VALIDATION_FAILED, "DSS could not validate the document: "
                    + e.getMessage(), e);
        }

        Map<ReportKind, String> xml = new EnumMap<>(ReportKind.class);
        xml.put(ReportKind.SIMPLE, dssReports.getXmlSimpleReport());
        if (reports.contains(ReportKind.DETAILED)) {
            xml.put(ReportKind.DETAILED, dssReports.getXmlDetailedReport());
        }
        if (reports.contains(ReportKind.ETSI)) {
            xml.put(ReportKind.ETSI, dssReports.getXmlValidationReport());
        }
        if (reports.contains(ReportKind.DIAGNOSTIC)) {
            xml.put(ReportKind.DIAGNOSTIC, dssReports.getXmlDiagnosticData());
        }
        List<ValidationResult.SignatureSummary> signatures = ValidationResult.summarize(dssReports);

        List<ValidationResult> nested = new ArrayList<>();
        if (options.unwrapNested && input.type() == InputNormalizer.Type.CMS && depth + 1 < MAX_NESTING
                && !signatures.isEmpty()) {
            InputNormalizer.Normalized inner = signedContentIfCms(validator, signatures.get(0).id());
            if (inner != null) {
                nested.add(validateLevel(inner, options, reports, verifier, depth + 1));
            }
        }
        return new ValidationResult(input.type().name(), input.transformations(), signatures, xml, nested);
    }

    /**
     * Extends every signature of a PDF to {@code options.level} (PAdES-BASELINE-T, -LT or -LTA) with DSS's
     * {@link PAdESService}. The result is the PDF followed by an incremental update: a DSS dictionary with the
     * certificates, CRLs and OCSP responses DSS collected (online unless {@code revocation} is offline) and, for T
     * and LTA, a document timestamp from {@code tsa.url}.
     *
     * <p>DSS refuses ({@link DssError.Code#EXTENSION_FAILED}) when a signature or timestamp does not validate
     * cryptographically, a certificate is revoked, expired or not yet valid, revocation data is missing, or a
     * signature is already at a higher level. These are DSS's default {@code CertificateVerifier} alerts.
     */
    public ExtensionResult extend(byte[] document, ExtensionOptions options) {
        if (document == null || document.length == 0) {
            throw new DssError(DssError.Code.INVALID_ARGUMENT, "document is empty");
        }
        TrustedListManager.Snapshot snapshot = trustSnapshot();
        InputNormalizer.Normalized input = InputNormalizer.normalize(document);
        if (input.type() == InputNormalizer.Type.CMS) {
            throw new DssError(DssError.Code.UNSUPPORTED_DOCUMENT,
                    "only PAdES signatures (PDF) can be extended, this is a CMS/CAdES document");
        }
        if (input.type() != InputNormalizer.Type.PDF) {
            throw new DssError(DssError.Code.UNSUPPORTED_DOCUMENT,
                    "not a PDF document (also tried base64 and PEM decoding)");
        }
        PAdESService service = new PAdESService(certificateVerifier(snapshot));
        service.setPdfObjFactory(pdfObjFactory());
        service.setTspSource(tspSource != null ? tspSource : new NoTsa(DssError.Code.EXTENSION_FAILED));
        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setSignatureLevel(options.level.pades);
        DSSDocument doc = new InMemoryDocument(input.bytes(),
                options.filename != null ? options.filename : "document.pdf");

        byte[] extended;
        try {
            extended = DSSUtils.toByteArray(service.extendDocument(doc, parameters));
        } catch (DSSException | AlertException | IllegalInputException | IllegalArgumentException e) {
            DssError ours = wrappedDssError(e);
            if (ours != null) {
                throw ours;
            }
            throw new DssError(DssError.Code.EXTENSION_FAILED, "DSS could not extend the signatures: "
                    + e.getMessage(), e);
        }
        return new ExtensionResult(extended, input.type().name(), input.transformations(), options.level.pades);
    }

    /**
     * Signing with a key held elsewhere, step 1: the digest the external signer must sign (see
     * {@link ExternalSigning}). Needs no network and no trusted lists. Refuses ({@link DssError.Code#SIGNING_FAILED})
     * a signing certificate that is expired or not yet valid at the signing time, so that no external signature is
     * spent on a document that cannot be completed.
     */
    public PreparedSignature prepareSignature(byte[] document, SigningOptions options) {
        if (document == null || document.length == 0) {
            throw new DssError(DssError.Code.INVALID_ARGUMENT, "document is empty");
        }
        ExternalSigning signing = signing(trustedLists.current(), options);
        return signingCall(() -> signing.prepare(document, options));
    }

    /**
     * Signing with a key held elsewhere, step 2: the signed document, from the same document and options as
     * {@link #prepareSignature} (plus the signing time it returned) and what the external signer returned. The
     * external result is checked against the digest first. Levels T and LTA need {@code tsa.url} (T not when an
     * external CMS has its own signature timestamp); LT and LTA fetch revocation data like {@link #extend}, and need
     * the trusted lists when {@code require_trusted_lists} is on.
     */
    public SigningResult completeSignature(byte[] document, SigningOptions options, byte[] externalSignature) {
        if (document == null || document.length == 0) {
            throw new DssError(DssError.Code.INVALID_ARGUMENT, "document is empty");
        }
        if (externalSignature == null || externalSignature.length == 0) {
            throw new DssError(DssError.Code.INVALID_ARGUMENT, "the external signature is empty");
        }
        boolean validationData = options.level == SigningOptions.Level.LT || options.level == SigningOptions.Level.LTA;
        ExternalSigning signing = signing(validationData ? trustSnapshot() : trustedLists.current(), options);
        return signingCall(() -> signing.complete(document, options, externalSignature));
    }

    private ExternalSigning signing(TrustedListManager.Snapshot snapshot, SigningOptions options) {
        CommonCertificateVerifier verifier = certificateVerifier(snapshot);
        CommonCertificateSource given = new CommonCertificateSource();
        if (options.signingCertificate != null) {
            given.addCertificate(options.signingCertificate);
        }
        options.certificateChain.forEach(given::addCertificate);
        verifier.setAdjunctCertSources(given);
        return new ExternalSigning(verifier, tspSource != null ? tspSource : new NoTsa(DssError.Code.SIGNING_FAILED),
                pdfObjFactory());
    }

    private static <T> T signingCall(Supplier<T> body) {
        try {
            return body.get();
        } catch (DSSException | AlertException | IllegalInputException | IllegalArgumentException
                 | IllegalStateException e) {
            DssError ours = wrappedDssError(e);
            if (ours != null) {
                throw ours;
            }
            throw new DssError(DssError.Code.SIGNING_FAILED, "DSS could not create the signature: " + e.getMessage(),
                    e);
        }
    }

    /** Stands in for the TSA when {@code tsa.url} is not set, so that DSS fails clearly when it needs one. */
    private static final class NoTsa implements TSPSource {
        private static final long serialVersionUID = 1L;

        private final DssError.Code code;

        NoTsa(DssError.Code code) {
            this.code = code;
        }

        @Override
        public TimestampBinary getTimeStampResponse(DigestAlgorithm digestAlgorithm, byte[] digest) {
            throw new DssError(code, "a timestamp is needed (level T or LTA, or a signature without a timestamp "
                    + "yet) but no TSA is configured: set 'tsa.url' in config_json");
        }
    }

    /** A {@link DssError} raised by our own code inside DSS (see {@link NoTsa}), if DSS wrapped one. */
    private static DssError wrappedDssError(Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c instanceof DssError e) {
                return e;
            }
        }
        return null;
    }

    private TrustedListManager.Snapshot trustSnapshot() {
        TrustedListManager.Snapshot snapshot = trustedLists.current();
        if (config.requireTrustedLists && !snapshot.loaded()) {
            throw new DssError(DssError.Code.TRUSTED_LISTS_NOT_LOADED,
                    "trusted lists not loaded: the cache is empty or unreadable; run an online refresh first");
        }
        return snapshot;
    }

    /** The enveloped content of an attached CAdES signature, if it is itself a CMS structure. */
    private static InputNormalizer.Normalized signedContentIfCms(SignedDocumentValidator validator, String sigId) {
        try {
            List<DSSDocument> originals = validator.getOriginalDocuments(sigId);
            if (originals.size() != 1) {
                return null;
            }
            byte[] content = DSSUtils.toByteArray(originals.get(0));
            InputNormalizer.Normalized inner = InputNormalizer.normalize(content);
            return inner.type() == InputNormalizer.Type.CMS ? inner : null;
        } catch (RuntimeException e) {
            LOG.debug("No extractable signed content for {}: {}", sigId, e.toString());
            return null;
        }
    }

    private static PDFDocumentValidator pdfValidator(DSSDocument doc) {
        PDFDocumentValidator validator = new PDFDocumentValidator(doc);
        validator.setPdfObjFactory(pdfObjFactory());
        return validator;
    }

    /**
     * Instantiated directly (not via ServiceLoader) and with visual comparison off: rendering pages through
     * PDFBox/AWT is slow and drags java.desktop into the native image. Object-level modification detection
     * between revisions stays on. Visible signatures are drawn without AWT ({@link AwtFreePdfObjFactory}).
     */
    private static PdfBoxNativeObjectFactory pdfObjFactory() {
        PdfBoxNativeObjectFactory factory = new AwtFreePdfObjFactory();
        DefaultPdfDifferencesFinder differencesFinder = new DefaultPdfDifferencesFinder();
        differencesFinder.setMaximalPagesAmountForVisualComparison(0);
        factory.setPdfDifferencesFinder(differencesFinder);
        return factory;
    }

    private CommonCertificateVerifier certificateVerifier(TrustedListManager.Snapshot snapshot) {
        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        if (extraTrusted.getNumberOfCertificates() > 0) {
            verifier.setTrustedCertSources(snapshot.source(), extraTrusted);
        } else {
            verifier.setTrustedCertSources(snapshot.source());
        }
        if (config.revocation == EngineConfig.Revocation.ONLINE) {
            OnlineCRLSource crl = new OnlineCRLSource();
            crl.setDataLoader(httpLoader);
            verifier.setCrlSource(crl);
            OnlineOCSPSource ocsp = new OnlineOCSPSource();
            ocsp.setDataLoader(ocspLoader);
            verifier.setOcspSource(ocsp);
        } else {
            verifier.setCrlSource(null);
            verifier.setOcspSource(null);
        }
        verifier.setAIASource(config.aiaFetching ? new DefaultAIASource(httpLoader) : null);
        return verifier;
    }

    @Override
    public void close() {
        trustedLists.close();
    }
}
