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
import java.util.LinkedHashMap;
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
import org.slf4j.event.Level;

import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.cades.validation.CMSDocumentValidator;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.signature.PAdESSignatureRequirementsChecker;
import eu.europa.esig.dss.pades.validation.PDFDocumentAnalyzer;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pdf.modifications.DefaultPdfDifferencesFinder;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;
import eu.europa.esig.dss.service.SecureRandomNonceSource;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.http.proxy.ProxyConfig;
import eu.europa.esig.dss.service.http.proxy.ProxyProperties;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.client.http.Protocol;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.policy.SignaturePolicyProvider;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.validation.executor.CompleteValidationContextExecutor;
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
    /** The configured TSA ({@code tsa.url}), before the token checks; null when there is none. */
    private final TSPSource onlineTsp;
    private final CheckedTspSource.Settings tsaChecks;

    /**
     * Builds the engine and loads the trusted lists from {@code cacheDir} (offline; never touches the network).
     * The loaders are used as given: {@link #create} is where the outbound-fetch policy and the response cache
     * are put around DSS's HTTP clients, so tests can inject in-memory loaders without them.
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
        this.tsaChecks = new CheckedTspSource.Settings(config.tsaMaxClockSkewMs, config.tsaRequireTrusted);
        if (config.tsaUrl == null) {
            this.onlineTsp = null;
        } else {
            OnlineTSPSource tsp = new OnlineTSPSource(config.tsaUrl.toString(),
                    tsaLoader != null ? tsaLoader : httpLoader);
            // A nonce binds the response to this request, so a replayed or cached token is detected.
            tsp.setNonceSource(new SecureRandomNonceSource());
            this.onlineTsp = tsp;
        }
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

    /**
     * Engine with DSS's Apache HttpClient loaders, configured from {@code config.http}: timeouts, redirects, proxy
     * and trust store on the client, the {@link OutboundFetchPolicy} in front of every one of them (the URLs of
     * CRL, OCSP and AIA requests come from the documents being validated), and a response cache for CRL and AIA.
     */
    public static DssEngine create(Path cacheDir, EngineConfig config) {
        Loaders loaders = Loaders.of(config);
        return new DssEngine(cacheDir, config, loaders.http(), loaders.ocsp(), loaders.tl(), loaders.tsa());
    }

    /** The outbound loaders {@link #create} builds, as built; package-private so tests can see how. */
    record Loaders(DataLoader http, DataLoader ocsp, DataLoader tl, DataLoader tsa) {

        static Loaders of(EngineConfig config) {
            CommonsDataLoader tlLoader = httpClient(new CommonsDataLoader(), config);
            if (!config.tlVerifyTls) {
                // Some national TL hosts use server certificates the JDK trust store does not cover (ES and HU in
                // 2026-10). TL authenticity comes from the XML signature, checked against the LOTL (itself checked
                // against the OJ keystore), and badly signed lists are never used, so TLS server authentication
                // adds nothing here. CRL/OCSP/AIA downloads keep normal TLS checks.
                tlLoader.setTrustStrategy(TrustAllStrategy.INSTANCE);
            }
            DataLoader http = OutboundFetchPolicy.wrap(httpClient(new CommonsDataLoader(), config), config);
            if (config.httpCacheMs > 0) {
                http = new CachingDataLoader(http, config.httpCacheMs);
            }
            return new Loaders(http, OutboundFetchPolicy.wrap(httpClient(new OCSPDataLoader(), config), config),
                    OutboundFetchPolicy.wrap(tlLoader, config), OutboundFetchPolicy.wrap(tsaLoader(config), config));
        }
    }

    /** Sends RFC 3161 requests, with the TSA's credentials if it needs them. Same TLS trust as CRL/OCSP. */
    private static CommonsDataLoader tsaLoader(EngineConfig config) {
        CommonsDataLoader loader = httpClient(new TimestampDataLoader(), config);
        if (config.tsaUsername != null) {
            // Any auth scheme the server asks for, on the TSA's host and port (-1 when the URL has none: any port).
            loader.addAuthentication(config.tsaUrl.getHost(), config.tsaUrl.getPort(), null, config.tsaUsername,
                    config.tsaPassword);
            loader.setPreemptiveAuthentication(true);
        }
        return loader;
    }

    /** Timeouts, redirects, proxy and trust store from {@code config.http}, on one of DSS's HTTP clients. */
    private static <L extends CommonsDataLoader> L httpClient(L loader, EngineConfig config) {
        loader.setTimeoutConnection(config.httpConnectTimeoutMs);
        loader.setTimeoutConnectionRequest(config.httpConnectTimeoutMs);
        loader.setTimeoutResponse(config.httpResponseTimeoutMs);
        loader.setTimeoutSocket(config.httpResponseTimeoutMs);
        loader.setRedirectsEnabled(config.httpFollowRedirects);
        loader.setUseSystemProperties(config.httpUseSystemProxy);
        if (config.httpProxy != null) {
            loader.setProxyConfig(proxyConfig(config.httpProxy));
        }
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

    /** One proxy for both http and https targets, as {@code http.proxy} describes it. */
    static ProxyConfig proxyConfig(EngineConfig.Proxy proxy) {
        ProxyConfig c = new ProxyConfig();
        c.setHttpProperties(proxyProperties(proxy));
        c.setHttpsProperties(proxyProperties(proxy));
        return c;
    }

    private static ProxyProperties proxyProperties(EngineConfig.Proxy proxy) {
        ProxyProperties p = new ProxyProperties();
        p.setHost(proxy.host());
        p.setPort(proxy.port());
        p.setScheme(proxy.scheme());
        if (proxy.username() != null) {
            p.setUser(proxy.username());
            p.setPassword(proxy.password());
        }
        p.setExcludedHosts(proxy.noProxy());
        return p;
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

    /** The trusted-list status, plus {@code extra_trusted_certificates}: how many anchors the config adds. */
    public Map<String, Object> trustedListStatus() {
        Map<String, Object> status = new LinkedHashMap<>(trustedLists.status());
        status.put("extra_trusted_certificates", extraTrusted.getNumberOfCertificates());
        return status;
    }

    /**
     * The root of trust in use, as {@code dss_tl_status} reports it under {@code oj_keystore}: {@code path} (the
     * configured {@code oj_keystore.path}) and {@code sha256} (over the sorted digests of the keystore's
     * certificates, the value a trusted-list snapshot records as {@code settings.oj_keystore_sha256}).
     */
    public Map<String, Object> ojKeystore() {
        return trustedLists.ojKeystore();
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
        checkLimits(input, DssError.Code.VALIDATION_FAILED, "validating");
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
        // No data loader: a signature policy named by the document is never fetched (its URL is the signer's
        // choice; DSS's default provider would open it with a client that knows none of the http settings).
        validator.setSignaturePolicyProvider(new SignaturePolicyProvider());
        if (options.validationTime != null) {
            validator.setValidationTime(Date.from(options.validationTime));
        }
        if (depth == 0 && !options.detachedContents.isEmpty()) {
            validator.setDetachedContents(options.detachedContents);
        }

        Reports dssReports;
        try {
            dssReports = validator.validateDocument();
        } catch (DssError e) {
            throw e;
        } catch (RuntimeException e) {
            // DSS, PDFBox and BouncyCastle also fail on damaged input with IllegalArgument/IllegalState/
            // NullPointer/IndexOutOfBounds exceptions: all of them mean "this document", not "this engine".
            throw new DssError(DssError.Code.VALIDATION_FAILED, "DSS could not validate the document: "
                    + describe(e), e);
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
        List<ValidationResult.TimestampSummary> timestamps = ValidationResult.summarizeTimestamps(dssReports);

        List<ValidationResult> nested = new ArrayList<>();
        if (options.unwrapNested && input.type() == InputNormalizer.Type.CMS && depth + 1 < MAX_NESTING
                && !signatures.isEmpty()) {
            InputNormalizer.Normalized inner = signedContent(validator, signatures.get(0).id());
            if (inner != null) {
                ValidationResult innerResult = validateLevel(inner, options, reports, verifier, depth + 1);
                // A CMS inside is always reported; a PDF inside only when it carries signatures or timestamps
                // of its own (a plain .pdf.p7m is the common case, and its content has nothing to say).
                if (inner.type() == InputNormalizer.Type.CMS || !innerResult.signatures.isEmpty()
                        || !innerResult.timestamps.isEmpty()) {
                    nested.add(innerResult);
                }
            }
        }
        return new ValidationResult(input.type().name(), input.transformations(), signatures, timestamps, xml,
                nested);
    }

    /** The structural pre-checks of {@link DocumentLimits} for a normalised document. */
    private void checkLimits(InputNormalizer.Normalized input, DssError.Code limitCode, String operation) {
        if (input.type() == InputNormalizer.Type.PDF) {
            DocumentLimits.checkPdf(input.bytes(), config.limits, limitCode, operation);
        } else if (input.type() == InputNormalizer.Type.CMS) {
            DocumentLimits.checkCms(input.bytes(), config.limits, limitCode);
        }
    }

    /**
     * DSS's own message for its exceptions (the class name when DSS threw without one); the class name too for the
     * JDK's, which say little on their own.
     */
    static String describe(RuntimeException e) {
        if (e instanceof DSSException || e instanceof AlertException) {
            return e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
        }
        return e.getClass().getSimpleName() + (e.getMessage() == null ? "" : ": " + e.getMessage());
    }

    /**
     * Extends every signature of a PDF to {@code options.level} (PAdES-BASELINE-T, -LT or -LTA) with DSS's
     * {@link PAdESService}. The result is the PDF followed by an incremental update: a DSS dictionary with the
     * certificates, CRLs and OCSP responses DSS collected (online unless {@code revocation} is offline) and, for T
     * and LTA, a document timestamp from {@code tsa.url}.
     *
     * <p>Signatures already above the target are left as they are (with a warning in the log) while the others
     * are raised, so a B signature added to an LTA document can still be extended. DSS refuses ({@link
     * DssError.Code#EXTENSION_FAILED}) when a signature or timestamp does not validate cryptographically, a
     * certificate is revoked, expired or not yet valid, or revocation data is missing; the engine refuses, before
     * any timestamp is requested, when every signature is already at a higher level than the target, and when
     * {@code revocation} is offline and a signature below LT is to reach LT or LTA (it would need revocation
     * data the document does not hold). A TSA that fails or returns an unacceptable token is {@link
     * DssError.Code#TSA_FAILED}.
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
        checkLimits(input, DssError.Code.EXTENSION_FAILED, "extending");
        CommonCertificateVerifier verifier = certificateVerifier(snapshot);
        PAdESService service = new PAdESService(verifier);
        service.setPdfObjFactory(pdfObjFactory());
        service.setTspSource(tspSource(verifier, DssError.Code.EXTENSION_FAILED));
        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setSignatureLevel(options.level.pades);
        DSSDocument doc = new InMemoryDocument(input.bytes(),
                options.filename != null ? options.filename : "document.pdf");

        byte[] extended;
        try {
            assertExtensionPossible(doc, options.level, verifier, parameters);
            extended = DSSUtils.toByteArray(service.extendDocument(doc, parameters));
        } catch (DssError e) {
            throw e;
        } catch (RuntimeException e) {
            DssError ours = wrappedDssError(e);
            if (ours != null) {
                throw ours;
            }
            throw new DssError(DssError.Code.EXTENSION_FAILED, "DSS could not extend the signatures: "
                    + describe(e), e);
        }
        return new ExtensionResult(extended, input.type().name(), input.transformations(), options.level.pades);
    }

    /**
     * What can be known before DSS contacts the TSA: that at least one signature is below the target, and, with
     * {@code revocation} offline, that the signatures to be raised to LT already have their revocation data.
     * DSS itself would ask for the document timestamp first and refuse afterwards, spending a token for nothing.
     */
    private void assertExtensionPossible(DSSDocument doc, ExtensionOptions.Level level,
                                         CommonCertificateVerifier verifier, PAdESSignatureParameters parameters) {
        PDFDocumentAnalyzer analyzer = new PDFDocumentAnalyzer(doc);
        analyzer.setPdfObjFactory(pdfObjFactory());
        analyzer.setCertificateVerifier(verifier);
        // As DSS's extension configures its analyzer: the executor that refuses on missing revocation data.
        analyzer.setValidationContextExecutor(CompleteValidationContextExecutor.INSTANCE);
        List<AdvancedSignature> signatures = analyzer.getSignatures();
        if (signatures.isEmpty()) {
            return; // DSS reports "No signatures found to be extended!"
        }
        int target = rank(level.pades);
        boolean anyBelowOrAt = false;
        boolean anyBelowLt = false;
        for (AdvancedSignature signature : signatures) {
            int current = rank(signature.getDataFoundUpToLevel());
            anyBelowOrAt |= current <= target;
            anyBelowLt |= current < rank(SignatureLevel.PAdES_BASELINE_LT);
        }
        if (!anyBelowOrAt) {
            throw new DssError(DssError.Code.EXTENSION_FAILED, "DSS could not extend the signatures: every "
                    + "signature is already extended with a higher level than " + level.pades);
        }
        if (config.revocation == EngineConfig.Revocation.OFFLINE && anyBelowLt && target >= rank(
                SignatureLevel.PAdES_BASELINE_LT)) {
            // What DSS collects for the DSS dictionary after adding the T level, and refuses when revocation data
            // is missing; here with the document's own data only, which is all an offline engine will ever have.
            try {
                new PAdESSignatureRequirementsChecker(verifier, parameters).assertCertificateChainValidForLTLevel(
                        signatures);
                analyzer.getValidationData(signatures, analyzer.getDetachedTimestamps());
            } catch (AlertException | IllegalInputException e) {
                throw new DssError(DssError.Code.EXTENSION_FAILED, "DSS could not extend the signatures: "
                        + e.getMessage() + " (revocation is \"offline\", so the data cannot be fetched; the "
                        + "timestamp the extension needs was not requested)", e);
            }
        }
    }

    private static int rank(SignatureLevel level) {
        if (level == null) {
            return 0;
        }
        return switch (level) {
            case PAdES_BASELINE_T -> 1;
            case PAdES_BASELINE_LT -> 2;
            case PAdES_BASELINE_LTA -> 3;
            default -> 0;
        };
    }

    /**
     * Signing with a key held elsewhere, step 1: the digest the external signer must sign (see
     * {@link ExternalSigning}). Needs no network and no trusted lists. Everything {@code complete} would refuse
     * that can be known now is refused here, so that no external signature is spent on a document that cannot
     * be completed ({@link DssError.Code#SIGNING_FAILED}): when {@code signing_certificate} is given, in either
     * mode, a certificate that is expired or not yet valid at the signing time, a CA certificate, a key usage
     * without digitalSignature or nonRepudiation, or an extended key usage limited to timestamping, TLS or OCSP;
     * for PAdES at LT or LTA, and at T in mode "cms", a PDF whose existing signatures DSS would refuse to extend
     * together with the new one; a PDF encrypted with a user password ({@link
     * DssError.Code#UNSUPPORTED_DOCUMENT}) or over the structural {@code limits}. In mode "signature_value" a
     * {@code pades.content_size} the CMS DSS builds cannot fit is {@link DssError.Code#INVALID_ARGUMENT}.
     */
    public PreparedSignature prepareSignature(byte[] document, SigningOptions options) {
        if (document == null || document.length == 0) {
            throw new DssError(DssError.Code.INVALID_ARGUMENT, "document is empty");
        }
        checkSigningInput(document, options);
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
        checkSigningInput(document, options);
        boolean validationData = options.level == SigningOptions.Level.LT || options.level == SigningOptions.Level.LTA;
        ExternalSigning signing = signing(validationData ? trustSnapshot() : trustedLists.current(), options);
        return signingCall(() -> signing.complete(document, options, externalSignature));
    }

    /** The PDF pre-checks (password, limits) when the document is to be signed as PAdES. */
    private void checkSigningInput(byte[] document, SigningOptions options) {
        boolean pdf = InputNormalizer.sniff(document) == InputNormalizer.Type.PDF;
        boolean pades = options.format == SigningOptions.Format.PADES || (options.format == null && pdf);
        if (pades && pdf) {
            DocumentLimits.checkPdf(document, config.limits, DssError.Code.SIGNING_FAILED, "signing");
        }
    }

    private ExternalSigning signing(TrustedListManager.Snapshot snapshot, SigningOptions options) {
        CommonCertificateVerifier verifier = certificateVerifier(snapshot);
        CommonCertificateSource given = new CommonCertificateSource();
        if (options.signingCertificate != null) {
            given.addCertificate(options.signingCertificate);
        }
        options.certificateChain.forEach(given::addCertificate);
        verifier.setAdjunctCertSources(given);
        return new ExternalSigning(verifier, tspSource(verifier, DssError.Code.SIGNING_FAILED), pdfObjFactory());
    }

    private static <T> T signingCall(Supplier<T> body) {
        try {
            return body.get();
        } catch (DssError e) {
            throw e;
        } catch (RuntimeException e) {
            // Besides DSS's own exceptions, PDFBox and FontBox fail on damaged input with ArrayIndexOutOfBounds,
            // NegativeArraySize or NullPointer exceptions while drawing an appearance: the document's fault.
            DssError ours = wrappedDssError(e);
            if (ours != null) {
                throw ours;
            }
            throw new DssError(DssError.Code.SIGNING_FAILED, "DSS could not create the signature: " + describe(e),
                    e);
        }
    }

    /**
     * The TSA for one operation: the configured one behind {@link CheckedTspSource}, judging trust against the
     * verifier's trust anchors, or a stand-in that fails clearly when {@code tsa.url} is not set.
     */
    private TSPSource tspSource(CommonCertificateVerifier verifier, DssError.Code noTsaCode) {
        if (onlineTsp == null) {
            return new NoTsa(noTsaCode);
        }
        return new CheckedTspSource(onlineTsp, config.tsaUrl.toString(), tsaChecks, verifier.getTrustedCertSources());
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
                    "trusted lists not loaded: no list yielded trust anchors (empty cache, a LOTL that could not be "
                    + "used, or countries that match no list: see dss_tl_status, last_*_refresh.error, "
                    + "countries_unmatched and alerts)");
        }
        return snapshot;
    }

    /** The enveloped content of an attached CAdES signature, if it is itself a CMS structure or a PDF. */
    private static InputNormalizer.Normalized signedContent(SignedDocumentValidator validator, String sigId) {
        try {
            List<DSSDocument> originals = validator.getOriginalDocuments(sigId);
            if (originals.size() != 1) {
                return null;
            }
            byte[] content = DSSUtils.toByteArray(originals.get(0));
            InputNormalizer.Normalized inner = InputNormalizer.normalize(content);
            return inner.type() == InputNormalizer.Type.UNKNOWN ? null : inner;
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
     * PDFBox/AWT is slow and drags java.desktop into the native image, and under DSS's default policy a visual
     * difference is a warning that changes no verdict anyway. Object-level modification detection between
     * revisions stays on; its findings are reported per signature as {@code changes_after_signing}. Visible
     * signatures are drawn without AWT ({@link AwtFreePdfObjFactory}).
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
        // DSS's default throws as soon as any signature of a PDF is above the level being added, which blocks
        // raising the others ([LTA, B] to LTA). A warning in the log is enough: that signature is left as it is.
        verifier.setAugmentationAlertOnHigherSignatureLevel(new LogOnStatusAlert(Level.WARN));
        if (config.revocation == EngineConfig.Revocation.ONLINE) {
            OnlineCRLSource crl = new OnlineCRLSource();
            crl.setDataLoader(httpLoader);
            verifier.setCrlSource(crl);
            OnlineOCSPSource ocsp = new OnlineOCSPSource();
            ocsp.setDataLoader(ocspLoader);
            // A nonce binds each response to its request (a responder that ignores it only gets a warning), and
            // a response outside its thisUpdate/nextUpdate window is at least logged instead of passing silently.
            ocsp.setNonceSource(new SecureRandomNonceSource());
            ocsp.setAlertOnInvalidUpdateTime(new LogOnStatusAlert(Level.WARN));
            verifier.setOcspSource(ocsp);
        } else {
            verifier.setCrlSource(null);
            verifier.setOcspSource(null);
        }
        verifier.setAIASource(config.aiaFetching ? aiaSource(httpLoader) : null);
        return verifier;
    }

    /** AIA over HTTP(S) only: caIssuers URLs come from the document, and DSS would also open ldap, ftp and file. */
    static DefaultAIASource aiaSource(DataLoader loader) {
        DefaultAIASource aia = new DefaultAIASource(loader);
        aia.setAcceptedProtocols(List.of(Protocol.HTTP, Protocol.HTTPS));
        return aia;
    }

    @Override
    public void close() {
        trustedLists.close();
    }

    /** After {@link #close()}: whether every trusted-list thread ended in time (see the shutdown result). */
    public boolean trustedListThreadsStopped() {
        return trustedLists.threadsStopped();
    }
}
