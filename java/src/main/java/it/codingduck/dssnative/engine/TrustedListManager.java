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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.alert.Alert;
import eu.europa.esig.dss.alert.detector.AlertDetector;
import eu.europa.esig.dss.alert.handler.AlertHandler;
import eu.europa.esig.dss.model.job.InfoRecord;
import eu.europa.esig.dss.model.job.ValidationInfoRecord;
import eu.europa.esig.dss.model.tsl.CertificateTrustTime;
import eu.europa.esig.dss.model.tsl.LOTLInfo;
import eu.europa.esig.dss.model.tsl.PivotInfo;
import eu.europa.esig.dss.model.tsl.TLInfo;
import eu.europa.esig.dss.model.tsl.TLParsingInfoRecord;
import eu.europa.esig.dss.model.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.model.tsl.TrustProperties;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.tsl.alerts.LOTLAlert;
import eu.europa.esig.dss.tsl.alerts.TLAlert;
import eu.europa.esig.dss.tsl.alerts.detections.LOTLLocationChangeDetection;
import eu.europa.esig.dss.tsl.alerts.detections.OJUrlChangeDetection;
import eu.europa.esig.dss.tsl.alerts.detections.TLExpirationDetection;
import eu.europa.esig.dss.tsl.alerts.detections.TLSignatureErrorDetection;
import eu.europa.esig.dss.tsl.function.GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate;
import eu.europa.esig.dss.tsl.function.OfficialJournalSchemeInformationURI;
import eu.europa.esig.dss.tsl.function.TLPredicateFactory;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.sync.ExpirationAndSignatureCheckStrategy;
import eu.europa.esig.dss.validation.job.sync.SynchronizationStrategy;

/**
 * Owns the EU trusted lists: a DSS {@link TLValidationJob} over a file cache ({@link TlCacheLoader}), refreshed
 * offline at startup and online on demand.
 *
 * <p>Concurrency: DSS's synchronizer clears and refills its {@link TrustedListsCertificateSource} in place, so a
 * validation running during a refresh could see an empty or half-built trust pool. The job therefore writes to a
 * private <em>staging</em> source, and after each refresh a full copy is published as an immutable
 * {@link Snapshot} through a volatile field. Validators only ever read snapshots. Refreshes are serialized.
 *
 * <p>Fail-safe publication: a refresh is published only when the pool it produced is usable, that is, every
 * trust anchor's list is in the list summary (not so when the LOTL could not be downloaded after a start from a
 * snapshot: DSS then empties the summary but keeps the anchors) and the LOTL itself is usable whenever the pool
 * came out empty (a badly signed or garbled LOTL empties it). Otherwise the previously published lists, and
 * where they came from, stay as they were, and the refresh reports {@code completed: false} with the reason;
 * the same reason is raised as a {@code refresh_not_published} alert. Downloads reach the cache only once the
 * refresh found them usable ({@link TlCacheLoader#promote}).
 *
 * <p>Rollback protection: trusted lists are downloaded without TLS server authentication by default
 * ({@code http.tl_verify_tls}), so an attacker on the path could replay an older, validly signed list, one
 * that still lists a CA since withdrawn. Every list handed to DSS, downloaded or read from the cache, is first
 * compared with the list last published for the same URL ({@link #admit}): a lower sequence number, or the same
 * one with an earlier issue date, is refused as a download error for that list (DSS keeps its previous result
 * for it) and raised as a {@code tl_rollback} alert. The sequence numbers of the lists in use are persisted in
 * {@value #SEQUENCE_FILE} next to the cache after every publication, so a restart cannot be used to replay
 * either; only lists whose signature validated are ever recorded, so a forged list cannot raise the bar.
 */
final class TrustedListManager implements AutoCloseable {

    private static final Logger LOG = LoggerFactory.getLogger(TrustedListManager.class);

    /**
     * What validators read: a trust source that never changes after publication.
     *
     * @param loadedBy   the load that produced it (null before the first one)
     * @param tlSnapshot when it came from a trusted-list snapshot file: that file's header, path and size
     */
    record Snapshot(TrustedListsCertificateSource source, TLValidationJobSummary summary, Instant publishedAt,
                    RefreshRecord loadedBy, Map<String, Object> tlSnapshot) {
        boolean loaded() {
            return source.getNumberOfCertificates() > 0;
        }
    }

    /** A trusted-list snapshot file, and what describes it: its header plus its size. */
    record Exported(byte[] bytes, Map<String, Object> info) {
    }

    /**
     * Outcome of one refresh run. {@code completed} is false when the run produced nothing publishable (DSS's job
     * threw, or the pool it built was unusable; see the class comment) and the previous lists were kept; {@code
     * error} then says why. Problems of single lists are in the TL status, not here.
     *
     * <p>{@code startedAt}/{@code finishedAt} are wall-clock instants; {@code durationMs} is measured on the
     * monotonic clock ({@link System#nanoTime()}), so a clock step during the run cannot make it negative.
     */
    record RefreshRecord(String mode, Instant startedAt, Instant finishedAt, boolean completed, String error,
                         int trustedCertificates, long durationMs) {
        RefreshRecord {
            durationMs = Math.max(0, durationMs);
        }

        /** Without a monotonic measurement: the wall-clock difference, clamped at zero. */
        RefreshRecord(String mode, Instant startedAt, Instant finishedAt, boolean completed, String error,
                      int trustedCertificates) {
            this(mode, startedAt, finishedAt, completed, error, trustedCertificates,
                    finishedAt.toEpochMilli() - startedAt.toEpochMilli());
        }

        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("mode", mode);
            m.put("started_at", startedAt.toString());
            m.put("finished_at", finishedAt.toString());
            m.put("duration_ms", durationMs);
            m.put("completed", completed);
            m.put("error", error);
            m.put("trusted_certificates", trustedCertificates);
            return m;
        }
    }

    private static final int MAX_ALERTS = 100;
    /** Where the sequence numbers of the published lists are kept, in the cache directory ({@code <cache_dir>/}). */
    static final String SEQUENCE_FILE = "tl-sequence-numbers.json";
    private static final Duration DEFAULT_CLOSE_WAIT = Duration.ofSeconds(5);

    /** An issue of a list, as published: what a later list of the same URL must not fall behind. */
    record ListVersion(long sequenceNumber, Instant issueDate) {
    }

    private final TLValidationJob job;
    private final SyncPolicy syncStrategy;
    /** The settings a trusted-list snapshot records and must match: {@link EngineConfig#trustedListSettings} + OJ. */
    private final Map<String, Object> snapshotSettings;
    /** The root of trust in use: {@code {path, sha256}} of the OJ keystore, as reported by {@link #status()}. */
    private final Map<String, Object> ojKeystoreInfo;
    private final TrustedListsCertificateSource staging = new TrustedListsCertificateSource();
    private final TlCacheLoader cacheLoader;
    private final ExecutorService executor;
    private final ReentrantLock refreshLock = new ReentrantLock();
    /** Alerts keyed by type and URL, oldest first; see {@link #alert}. Guarded by itself. */
    private final LinkedHashMap<String, Map<String, Object>> alerts = new LinkedHashMap<>();
    private final String lotlUrl;
    private final List<String> countries;
    private final Duration closeWait;
    /** The persisted record of {@link #published}; null when there is no cache directory to keep it in. */
    private final Path sequenceFile;
    /** The lists published so far, by URL: the floor of the rollback protection. Only ever raised. */
    private final ConcurrentHashMap<String, ListVersion> published = new ConcurrentHashMap<>();

    private volatile Snapshot current;
    private volatile RefreshRecord lastOffline;
    private volatile RefreshRecord lastOnline;
    private volatile Instant onlineRefreshStartedAt;
    private volatile boolean threadsStopped;

    TrustedListManager(Path cacheDir, EngineConfig config, DataLoader httpLoader) {
        this(cacheDir, config, httpLoader, DEFAULT_CLOSE_WAIT);
    }

    /** @param closeWait how long {@link #close()} waits for a running download or validation to end */
    TrustedListManager(Path cacheDir, EngineConfig config, DataLoader httpLoader, Duration closeWait) {
        this.closeWait = closeWait;
        Path tlCache = cacheDir.resolve("tl");
        cacheLoader = new TlCacheLoader(tlCache, this::admit);
        String cacheError = cacheLoader.ensureDirectory();
        if (cacheError != null) {
            if (config.tlSnapshot == null) {
                throw new DssError(DssError.Code.INVALID_CONFIG,
                        "cannot create cache directory " + tlCache + ": " + cacheError);
            }
            // A snapshot start needs no cache (a read-only deployment, say): online refreshes will still work,
            // and will try again to create the directory when they have lists to store.
            LOG.warn("Trusted-list cache directory {} is not available; lists come from the snapshot only", tlCache);
        }
        sequenceFile = cacheDir.resolve(SEQUENCE_FILE);
        published.putAll(readPublished(sequenceFile));
        lotlUrl = config.lotlUrl;
        countries = config.countries;

        KeyStoreCertificateSource ojKeystore;
        try {
            ojKeystore = new KeyStoreCertificateSource(config.ojKeystorePath.toFile(), config.ojKeystoreType,
                    config.ojKeystorePassword);
        } catch (IOException | RuntimeException e) {
            throw new DssError(DssError.Code.INVALID_CONFIG,
                    "cannot load OJ keystore " + config.ojKeystorePath + ": " + e.getMessage(), e);
        }
        if (ojKeystore.getNumberOfCertificates() == 0) {
            throw new DssError(DssError.Code.INVALID_CONFIG, "OJ keystore " + config.ojKeystorePath + " is empty");
        }
        snapshotSettings = config.trustedListSettings();
        String ojKeystoreSha256 = certificatesSha256(ojKeystore.getCertificates());
        snapshotSettings.put("oj_keystore_sha256", ojKeystoreSha256);
        Map<String, Object> keystoreInfo = new LinkedHashMap<>();
        keystoreInfo.put("path", config.ojKeystorePath.toString());
        keystoreInfo.put("sha256", ojKeystoreSha256);
        ojKeystoreInfo = Collections.unmodifiableMap(keystoreInfo);
        LOG.info("OJ keystore {}: {} LOTL signing certificate(s), sha256 {}", config.ojKeystorePath,
                ojKeystore.getNumberOfCertificates(), ojKeystoreSha256);

        LOTLSource lotl = new LOTLSource();
        lotl.setUrl(config.lotlUrl);
        lotl.setCertificateSource(ojKeystore);
        lotl.setPivotSupport(config.pivotSupport);
        lotl.setSigningCertificatesAnnouncementPredicate(new OfficialJournalSchemeInformationURI(config.ojUrl));
        if (config.useSunsetDate) {
            lotl.setTrustAnchorValidityPredicate(new GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate());
        }
        lotl.setTLVersions(config.tlVersions); // never empty: EngineConfig maps [] to DSS's default
        if (!config.countries.isEmpty()) {
            lotl.setTlPredicate(TLPredicateFactory.createEUTLCountryCodePredicate(
                    config.countries.toArray(new String[0])));
        }

        AtomicInteger threadId = new AtomicInteger();
        // Loading from the cache re-validates every list's XAdES signature: CPU-bound, ~32 lists for the full LOTL.
        executor = Executors.newFixedThreadPool(config.tlThreads, r -> {
            Thread t = new Thread(() -> {
                // BouncyCastle tests every RSA modulus it meets (about 4 ms each, ~5,000 certificates in the EU
                // lists). The anchors come from lists whose signature is checked before they are trusted, and the
                // LOTL signers from the OJ keystore, built above with the tests on; see TlSnapshotFile.contents.
                org.bouncycastle.util.Properties.setThreadOverride(TlSnapshotFile.BC_ALLOW_UNSAFE_MOD, true);
                r.run();
            }, "dss-tl-" + threadId.incrementAndGet());
            t.setDaemon(true); // must not keep a host process (or an isolate teardown) waiting
            return t;
        });

        // DSS's default (AcceptAllStrategy) turns every TL into trust anchors even when the LOTL or TL signature
        // does not validate: a tampered cache or download would inject trust. Only signature-valid lists count.
        ExpirationAndSignatureCheckStrategy base = new ExpirationAndSignatureCheckStrategy();
        base.setAcceptInvalidListOfTrustedLists(config.tlAcceptInvalidSignature);
        base.setAcceptInvalidTrustedList(config.tlAcceptInvalidSignature);
        base.setAcceptExpiredListOfTrustedLists(config.tlAcceptExpired);
        base.setAcceptExpiredTrustedList(config.tlAcceptExpired);
        syncStrategy = new SyncPolicy(base, config.tlAcceptStructureErrors);

        job = new TLValidationJob();
        job.setSynchronizationStrategy(syncStrategy);
        job.setExecutorService(executor);
        job.setListOfTrustedListSources(lotl);
        job.setOfflineDataLoader(cacheLoader.offline());
        job.setOnlineDataLoader(cacheLoader.online(httpLoader, config.onlineCacheExpirationMs));
        job.setTrustedListCertificateSource(staging);
        AlertDetector<TLInfo> signatureError = new TLSignatureErrorDetection();
        AlertDetector<TLInfo> expiration = new TLExpirationDetection();
        job.setLOTLAlerts(List.of(
                new LOTLAlert(new OJUrlChangeDetection(lotl), collect("oj_url_changed",
                        i -> "LOTL announces new signing certificates at "
                                + i.getParsingCacheInfo().getSigningCertificateAnnouncementUrl()
                                + "; update oj_url and the OJ keystore")),
                new LOTLAlert(new LOTLLocationChangeDetection(lotl), collect("lotl_location_changed",
                        i -> "LOTL location changed; check lotl_url")),
                new LOTLAlert(signatureError::detect, collect("lotl_signature_error",
                        i -> "LOTL signature is not valid: " + validationOutcome(i))),
                new LOTLAlert(expiration::detect, collect("lotl_expired",
                        i -> "LOTL is past its next update date")),
                new LOTLAlert(TrustedListManager::hasStructureMessages, collect("lotl_structure_error",
                        i -> "LOTL structure is not valid: " + structureMessages(i)))));
        job.setTLAlerts(List.<Alert<TLInfo>>of(
                new TLAlert(signatureError, collect("tl_signature_error",
                        i -> "trusted list signature is not valid: " + validationOutcome(i))),
                new TLAlert(expiration, collect("tl_expired",
                        i -> "trusted list is past its next update date")),
                new TLAlert(TrustedListManager::hasStructureMessages, collect("tl_structure_error",
                        i -> "trusted list structure is not valid: " + structureMessages(i)))));

        current = new Snapshot(new TrustedListsCertificateSource(), null, Instant.now(), null, null);
    }

    /**
     * {@link ExpirationAndSignatureCheckStrategy} ({@code tl_sync}), plus {@code accept_structure_errors}: when
     * off, a list DSS flags for its structure (a version outside {@code tl_versions}, schema deviations) is not
     * a trust source either. DSS itself only ever reports those messages per signature.
     */
    private static final class SyncPolicy implements SynchronizationStrategy<TLInfo, LOTLInfo> {
        private final ExpirationAndSignatureCheckStrategy base;
        private final boolean acceptStructureErrors;

        SyncPolicy(ExpirationAndSignatureCheckStrategy base, boolean acceptStructureErrors) {
            this.base = base;
            this.acceptStructureErrors = acceptStructureErrors;
        }

        @Override
        public boolean canBeSynchronized(TLInfo trustedList) {
            return base.canBeSynchronized(trustedList) && (acceptStructureErrors || !hasStructureMessages(trustedList));
        }

        @Override
        public boolean canBeSynchronized(LOTLInfo listOfTrustedList) {
            return base.canBeSynchronized(listOfTrustedList)
                    && (acceptStructureErrors || !hasStructureMessages(listOfTrustedList));
        }
    }

    private static boolean hasStructureMessages(TLInfo info) {
        return !structureMessageList(info).isEmpty();
    }

    private static List<String> structureMessageList(TLInfo info) {
        TLParsingInfoRecord p = info.getParsingCacheInfo();
        if (p == null || !p.isResultExist() || p.getStructureValidationMessages() == null) {
            return List.of();
        }
        return p.getStructureValidationMessages();
    }

    private static String structureMessages(TLInfo info) {
        return String.join("; ", structureMessageList(info));
    }

    private static String validationOutcome(TLInfo info) {
        ValidationInfoRecord v = info.getValidationCacheInfo();
        if (v == null || !v.isResultExist()) {
            return v != null && v.isError() ? v.getExceptionMessage() : "no validation result";
        }
        return v.getIndication() + (v.getSubIndication() == null ? "" : "/" + v.getSubIndication());
    }

    /** SHA-256 over the sorted SHA-256 digests of the certificates: the same for the same set, in any order. */
    private static String certificatesSha256(List<CertificateToken> certificates) {
        HexFormat hex = HexFormat.of();
        MessageDigest all = sha256();
        certificates.stream()
                .map(c -> hex.formatHex(sha256().digest(c.getEncoded())))
                .sorted()
                .forEach(h -> all.update(h.getBytes(StandardCharsets.US_ASCII)));
        return hex.formatHex(all.digest());
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private <T extends TLInfo> AlertHandler<T> collect(String type, Function<T, String> message) {
        return info -> alert(type, info.getUrl(), message.apply(info));
    }

    /**
     * Records an alert. DSS runs its detections on every refresh, so a lasting condition (a chronically late
     * list) would otherwise add an identical entry each time and push one-off alerts such as
     * {@code oj_url_changed} out of the ring. Alerts are keyed by type and URL instead: a repeat updates
     * {@code last_seen} (and {@code at}), {@code count} and the message; the oldest key goes when there are more
     * than {@value #MAX_ALERTS}.
     */
    private void alert(String type, String url, String message) {
        alert(type, url, message, Map.of());
    }

    /** As {@link #alert(String, String, String)}, with {@code details} as further fields of the entry. */
    private void alert(String type, String url, String message, Map<String, Object> details) {
        String now = Instant.now().toString();
        synchronized (alerts) {
            String key = type + "\n" + url;
            Map<String, Object> a = alerts.get(key);
            if (a == null) {
                LOG.warn("Trusted list alert {} for {}: {}", type, url, message);
                a = new LinkedHashMap<>();
                a.put("type", type);
                a.put("url", url);
                a.put("message", message);
                a.put("at", now);
                a.put("first_seen", now);
                a.put("last_seen", now);
                a.put("count", 1);
                a.putAll(details);
                alerts.put(key, a);
                while (alerts.size() > MAX_ALERTS) {
                    alerts.remove(alerts.keySet().iterator().next());
                }
            } else {
                LOG.info("Trusted list alert {} for {} again: {}", type, url, message);
                a.put("message", message);
                a.put("at", now);
                a.put("last_seen", now);
                a.put("count", ((Number) a.getOrDefault("count", 1)).intValue() + 1);
                a.putAll(details);
            }
        }
    }

    private List<Map<String, Object>> alertList() {
        synchronized (alerts) {
            List<Map<String, Object>> out = new ArrayList<>(alerts.size());
            for (Map<String, Object> a : alerts.values()) {
                out.add(new LinkedHashMap<>(a));
            }
            return out;
        }
    }

    /** Replaces the alerts with those of a snapshot, keyed the same way (older snapshots lack the counters). */
    private void replaceAlerts(List<Map<String, Object>> imported) {
        synchronized (alerts) {
            alerts.clear();
            for (Map<String, Object> a : imported) {
                Map<String, Object> copy = new LinkedHashMap<>(a);
                Object at = copy.get("at");
                copy.putIfAbsent("first_seen", at);
                copy.putIfAbsent("last_seen", at);
                copy.putIfAbsent("count", 1);
                alerts.put(copy.get("type") + "\n" + copy.get("url"), copy);
            }
            while (alerts.size() > MAX_ALERTS) {
                alerts.remove(alerts.keySet().iterator().next());
            }
        }
    }

    Snapshot current() {
        return current;
    }

    /** Loads whatever the file cache holds. No network access. */
    RefreshRecord offlineRefresh() {
        refreshLock.lock();
        try {
            lastOffline = run("offline", job::offlineRefresh);
            return lastOffline;
        } finally {
            refreshLock.unlock();
        }
    }

    /** Downloads and validates the LOTL and TLs. Blocking; fails fast if another online refresh is running. */
    RefreshRecord onlineRefresh() {
        if (!refreshLock.tryLock()) {
            throw new DssError(DssError.Code.REFRESH_IN_PROGRESS,
                    "a trusted-list refresh started at " + onlineRefreshStartedAt + " is still running");
        }
        try {
            onlineRefreshStartedAt = Instant.now();
            lastOnline = run("online", job::onlineRefresh);
            return lastOnline;
        } finally {
            onlineRefreshStartedAt = null;
            refreshLock.unlock();
        }
    }

    private RefreshRecord run(String mode, Runnable refresh) {
        Instant start = Instant.now();
        long startNanos = System.nanoTime();
        cacheLoader.beginRefresh();
        try {
            refresh.run();
        } catch (RejectedExecutionException e) {
            // The executor was shut down under the job: close() or a re-init while it ran. The exception text
            // describes a ThreadPoolExecutor, which says nothing to the caller.
            LOG.warn("{} trusted-list refresh interrupted: the engine was closed or replaced while it ran", mode);
            return keepPrevious(mode, start, startNanos,
                    "the refresh was interrupted: the engine was closed or replaced while it ran");
        } catch (RuntimeException e) {
            // DSS records per-list failures itself; reaching here means the job could not run at all. Staging may
            // be half-refilled, so the published lists, and where they came from, stay as they were.
            LOG.error("{} trusted-list refresh failed", mode, e);
            return keepPrevious(mode, start, startNanos, e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        TLValidationJobSummary summary = staging.getSummary();
        TlCacheLoader.Promotion promotion = cacheLoader.promote(url -> promotable(summary, url));
        if (promotion.promoted() + promotion.skipped() + promotion.errors().size() > 0) {
            LOG.info("Trusted-list cache: {} list(s) stored, {} not usable and left out, {} write error(s)",
                    promotion.promoted(), promotion.skipped(), promotion.errors().size());
        }
        for (Map.Entry<String, String> error : promotion.errors().entrySet()) {
            alert("cache_write_error", error.getKey(), "cannot store the list in the cache: " + error.getValue());
        }
        String problem = publishProblem(summary);
        if (problem != null) {
            LOG.error("{} trusted-list refresh produced no usable trust pool: {}; the previous lists are kept", mode,
                    problem);
            alert("refresh_not_published", lotlUrl, problem);
            return keepPrevious(mode, start, startNanos, problem);
        }
        List<String> unmatched = unmatchedCountries(summary);
        if (!unmatched.isEmpty()) {
            alert("countries_unmatched", lotlUrl, "no trusted list in the LOTL for " + unmatched
                    + " (the LOTL uses the scheme territory codes, e.g. EL for Greece)");
        }
        RefreshRecord record = new RefreshRecord(mode, start, Instant.now(), true, null,
                staging.getNumberOfCertificates(), elapsedMs(startNanos));
        publishSnapshot(record, null);
        recordPublished(summary);
        return record;
    }

    private RefreshRecord keepPrevious(String mode, Instant start, long startNanos, String error) {
        return new RefreshRecord(mode, start, Instant.now(), false, error, current.source().getNumberOfCertificates(),
                elapsedMs(startNanos));
    }

    /** Milliseconds since {@code startNanos} on the monotonic clock. */
    private static long elapsedMs(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000L;
    }

    /**
     * The rollback protection ({@link TlCacheLoader.Guard}): refuses a list that falls behind the one last
     * published for its URL. Runs on the trusted-list threads, before DSS parses the document.
     */
    private void admit(String url, TlDocumentCheck.Identity identity, String source) {
        ListVersion previous = published.get(url);
        if (previous == null || identity.sequenceNumber() == null) {
            return;
        }
        long sequence = identity.sequenceNumber();
        boolean older = sequence < previous.sequenceNumber()
                || (sequence == previous.sequenceNumber() && identity.issueDate() != null
                && identity.issueDate().truncatedTo(ChronoUnit.SECONDS)
                        .isBefore(previous.issueDate().truncatedTo(ChronoUnit.SECONDS)));
        if (!older) {
            return;
        }
        String message = ("download".equals(source) ? "the downloaded list" : "the cached file " + source)
                + " is sequence number " + sequence + " (issued " + identity.issueDate() + "), behind the published "
                + previous.sequenceNumber() + " (issued " + previous.issueDate() + "): a replayed older list is not used";
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("previous_sequence_number", previous.sequenceNumber());
        details.put("previous_issue_date", previous.issueDate().toString());
        details.put("sequence_number", sequence);
        details.put("issue_date", identity.issueDate() == null ? null : identity.issueDate().toString());
        alert("tl_rollback", url, message, details);
        throw new DSSExternalResourceException("rollback refused: " + message);
    }

    /**
     * Records the lists the published pool trusts as the new floor of the rollback protection, and persists the
     * record. Only lists whose signature validated count: a list DSS does not use must not raise the bar either.
     */
    private void recordPublished(TLValidationJobSummary summary) {
        if (summary == null) {
            return;
        }
        boolean changed = false;
        for (LOTLInfo lotl : summary.getLOTLInfos()) {
            boolean lotlUsed = usable(lotl);
            if (lotlUsed) {
                changed |= raise(lotl);
            }
            if (lotl.getPivotInfos() != null) {
                for (PivotInfo pivot : lotl.getPivotInfos()) {
                    if (usable(pivot)) {
                        changed |= raise(pivot);
                    }
                }
            }
            if (lotlUsed && lotl.getTLInfos() != null) {
                for (TLInfo tl : lotl.getTLInfos()) {
                    if (usable(tl)) {
                        changed |= raise(tl);
                    }
                }
            }
        }
        for (TLInfo tl : summary.getOtherTLInfos()) {
            if (usable(tl)) {
                changed |= raise(tl);
            }
        }
        if (changed) {
            writePublished();
        }
    }

    /** Raises the floor for a list's URL to its parsed sequence number; false when nothing changed. */
    private boolean raise(TLInfo info) {
        TLParsingInfoRecord p = info.getParsingCacheInfo();
        if (p == null || !p.isResultExist() || p.getSequenceNumber() == null || info.getUrl() == null) {
            return false;
        }
        ListVersion version = new ListVersion(p.getSequenceNumber().longValue(),
                p.getIssueDate() == null ? Instant.EPOCH : p.getIssueDate().toInstant());
        ListVersion before = published.get(info.getUrl());
        if (before != null && (before.sequenceNumber() > version.sequenceNumber()
                || (before.sequenceNumber() == version.sequenceNumber()
                && !before.issueDate().isBefore(version.issueDate())))) {
            return false;
        }
        published.put(info.getUrl(), version);
        return true;
    }

    /** The persisted floor; empty when the file is absent, and (with a warning) when it cannot be read. */
    private static Map<String, ListVersion> readPublished(Path file) {
        Map<String, ListVersion> out = new HashMap<>();
        if (!Files.isRegularFile(file)) {
            return out;
        }
        try {
            Map<String, Object> parsed = Json.parseObject(Files.readString(file, StandardCharsets.UTF_8));
            for (Map.Entry<String, Object> e : parsed.entrySet()) {
                if (e.getValue() instanceof Map<?, ?> m && m.get("sequence_number") instanceof Number n) {
                    Object issued = m.get("issue_date");
                    out.put(e.getKey(), new ListVersion(n.longValue(),
                            issued == null ? Instant.EPOCH : Instant.parse(issued.toString())));
                }
            }
        } catch (IOException | RuntimeException e) {
            LOG.warn("Cannot read the trusted-list sequence numbers in {}: rollback protection starts afresh ({})",
                    file, e.toString());
        }
        return out;
    }

    /** Writes {@link #published} to {@link #sequenceFile}; a failure is a {@code cache_write_error} alert. */
    private void writePublished() {
        Map<String, Object> out = new TreeMap<>();
        for (Map.Entry<String, ListVersion> e : published.entrySet()) {
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("sequence_number", e.getValue().sequenceNumber());
            v.put("issue_date", e.getValue().issueDate().toString());
            out.put(e.getKey(), v);
        }
        try {
            Files.createDirectories(sequenceFile.getParent());
            TlCacheLoader.writeAtomically(sequenceFile, Json.write(out).getBytes(StandardCharsets.UTF_8));
        } catch (IOException | RuntimeException e) {
            LOG.warn("Cannot write the trusted-list sequence numbers to {}: {}", sequenceFile, e.toString());
            alert("cache_write_error", null, "cannot write the sequence numbers of the published lists to "
                    + sequenceFile + " (rollback protection will not survive a restart): " + e);
        }
    }

    /**
     * Why the staging pool must not be published, or null when it may be: every anchor's list must be in the
     * summary (DiagnosticDataBuilder throws for a trusted chain otherwise), and an empty pool may only replace a
     * loaded one when the LOTL itself is fine, that is, when it is the lists, not a bad LOTL, that dropped out.
     */
    private String publishProblem(TLValidationJobSummary summary) {
        int certificates = staging.getNumberOfCertificates();
        if (summary == null) {
            return certificates == 0 ? null : "DSS produced no trusted-list summary for " + certificates + " trust anchors";
        }
        Set<String> missing = new TreeSet<>();
        for (CertificateToken token : staging.getCertificates()) {
            for (TrustProperties p : staging.getTrustServices(token)) {
                if (p.getTLInfo() != null && summary.getTLInfoById(p.getTLInfo().getDSSId()) == null) {
                    missing.add(p.getTLInfo().getUrl());
                }
                if (p.getLOTLInfo() != null && summary.getLOTLInfoById(p.getLOTLInfo().getDSSId()) == null) {
                    missing.add(p.getLOTLInfo().getUrl());
                }
            }
        }
        if (!missing.isEmpty()) {
            return "the trust anchors reference lists the refresh has no result for (" + String.join(", ", missing)
                    + "): " + lotlOutcome(summary);
        }
        if (certificates == 0 && current.loaded()) {
            boolean lotlUsable = false;
            int lists = 0;
            int unprocessed = 0;
            for (LOTLInfo lotl : summary.getLOTLInfos()) {
                if (!usable(lotl)) {
                    continue;
                }
                lotlUsable = true;
                if (lotl.getTLInfos() != null) {
                    for (TLInfo tl : lotl.getTLInfos()) {
                        lists++;
                        if (!processed(tl)) {
                            unprocessed++;
                        }
                    }
                }
            }
            if (!lotlUsable) {
                return "the refresh would drop every trust anchor because the LOTL cannot be used: " + lotlOutcome(summary);
            }
            if (unprocessed > 0) {
                // After a start from a snapshot DSS has no earlier result to fall back on: lists that did not
                // download are simply absent. Dropping everything over that is worse than keeping the snapshot.
                return "the refresh would drop every trust anchor: " + unprocessed + " of " + lists
                        + " trusted lists could not be downloaded or parsed";
            }
        }
        return null;
    }

    /** Whether DSS has a parsing result for the list, from this refresh or an earlier one. */
    private static boolean processed(TLInfo tl) {
        TLParsingInfoRecord p = tl.getParsingCacheInfo();
        return p != null && p.isResultExist();
    }

    /** One line on the state of each LOTL in the summary, for messages. */
    private static String lotlOutcome(TLValidationJobSummary summary) {
        List<String> parts = new ArrayList<>();
        for (LOTLInfo lotl : summary.getLOTLInfos()) {
            StringBuilder sb = new StringBuilder(lotl.getUrl()).append(": ");
            InfoRecord d = lotl.getDownloadCacheInfo();
            if (d != null && d.isError()) {
                sb.append("download failed (").append(d.getExceptionMessage()).append(")");
            } else {
                InfoRecord p = lotl.getParsingCacheInfo();
                if (p != null && p.isError()) {
                    sb.append("parsing failed (").append(p.getExceptionMessage()).append(")");
                } else {
                    sb.append("signature ").append(validationOutcome(lotl));
                }
            }
            parts.add(sb.toString());
        }
        return parts.isEmpty() ? "no LOTL in the summary" : String.join("; ", parts);
    }

    /** A list whose signature validated, or that {@code tl_sync} lets through anyway. */
    private boolean usable(TLInfo info) {
        ValidationInfoRecord v = info.getValidationCacheInfo();
        boolean valid = v != null && v.isResultExist() && v.isValid();
        return valid || (info instanceof LOTLInfo l ? syncStrategy.canBeSynchronized(l) : syncStrategy.canBeSynchronized(info));
    }

    /**
     * Whether a download of this refresh may replace the cached copy: the LOTL and pivots when usable, a national
     * list when it and the LOTL that points to it are. A forged LOTL announces its own TL signers, so the lists
     * it points to are never stored on its word.
     */
    private boolean promotable(TLValidationJobSummary summary, String url) {
        if (summary == null) {
            return false;
        }
        for (LOTLInfo lotl : summary.getLOTLInfos()) {
            boolean lotlUsable = usable(lotl);
            if (url.equals(lotl.getUrl())) {
                return lotlUsable;
            }
            if (lotl.getPivotInfos() != null) {
                for (PivotInfo pivot : lotl.getPivotInfos()) {
                    if (url.equals(pivot.getUrl())) {
                        return usable(pivot);
                    }
                }
            }
            if (lotl.getTLInfos() != null) {
                for (TLInfo tl : lotl.getTLInfos()) {
                    if (url.equals(tl.getUrl())) {
                        return lotlUsable && usable(tl);
                    }
                }
            }
        }
        for (TLInfo tl : summary.getOtherTLInfos()) {
            if (url.equals(tl.getUrl())) {
                return usable(tl);
            }
        }
        return false;
    }

    /**
     * Configured {@code countries} that match no list in the LOTL (a typo, or GR where the LOTL says EL); empty
     * when none, or when the LOTL has not been parsed, or when no filter is configured.
     */
    private List<String> unmatchedCountries(TLValidationJobSummary summary) {
        if (countries.isEmpty() || summary == null) {
            return List.of();
        }
        Set<String> matched = new HashSet<>();
        boolean parsed = false;
        for (LOTLInfo lotl : summary.getLOTLInfos()) {
            TLParsingInfoRecord p = lotl.getParsingCacheInfo();
            if (p == null || !p.isResultExist()) {
                continue;
            }
            parsed = true;
            if (lotl.getTLInfos() != null) {
                for (TLInfo tl : lotl.getTLInfos()) {
                    String territory = tl.getOtherTSLPointer() != null ? tl.getOtherTSLPointer().getSchemeTerritory() : null;
                    if (territory == null && tl.getParsingCacheInfo() != null && tl.getParsingCacheInfo().isResultExist()) {
                        territory = tl.getParsingCacheInfo().getTerritory();
                    }
                    if (territory != null) {
                        matched.add(territory.toUpperCase(java.util.Locale.ROOT));
                    }
                }
            }
        }
        if (!parsed) {
            return List.of();
        }
        List<String> unmatched = new ArrayList<>();
        for (String c : countries) {
            if (!matched.contains(c)) {
                unmatched.add(c);
            }
        }
        return unmatched;
    }

    /**
     * Loads a trusted-list snapshot file ({@link TlSnapshotFile}) instead of the cache. No network, no list parsed
     * or validated. Fails with {@code TL_SNAPSHOT_REJECTED}, before anything is published, when the file cannot be
     * used. Whether its contents can be trusted is for the caller to decide.
     */
    RefreshRecord importSnapshot(Path file) {
        refreshLock.lock();
        try {
            Instant start = Instant.now();
            long startNanos = System.nanoTime();
            byte[] bytes;
            try {
                bytes = Files.readAllBytes(file);
            } catch (IOException | RuntimeException e) {
                throw TlSnapshotFile.rejected("cannot read " + file + ": " + e);
            }
            Map<String, Object> header = TlSnapshotFile.header(bytes);
            checkCompatible(header);
            TlSnapshotFile.Contents contents = TlSnapshotFile.contents(bytes);
            checkConsistent(contents);
            checkUsable(contents);

            // Staging too, so that a later refresh that cannot run keeps these lists, as it keeps cached ones.
            staging.setTrustPropertiesByCertificates(contents.trustProperties());
            staging.setTrustTimeByCertificates(contents.trustTimes());
            staging.setSummary(contents.summary());
            replaceAlerts(contents.alerts());
            RefreshRecord record = new RefreshRecord("snapshot", start, Instant.now(), true, null,
                    staging.getNumberOfCertificates(), elapsedMs(startNanos));
            Map<String, Object> info = new LinkedHashMap<>();
            info.put("path", file.toString());
            info.put("size", bytes.length);
            info.putAll(header);
            publishSnapshot(record, info);
            recordPublished(contents.summary());
            lastOffline = record;
            return record;
        } finally {
            refreshLock.unlock();
        }
    }

    /** Same DSS version (the payload is DSS's own serialized model) and same trusted-list settings. */
    private void checkCompatible(Map<String, Object> header) {
        Object dss = header.get("dss");
        if (!Objects.equals(dss, BuildInfo.dss())) {
            throw TlSnapshotFile.rejected("written with DSS " + dss + "; this library uses DSS " + BuildInfo.dss());
        }
        if (!(header.get("settings") instanceof Map<?, ?> theirs)) {
            throw TlSnapshotFile.rejected("the snapshot header has no trusted-list settings");
        }
        Map<String, Object> ours = Json.parseObject(Json.write(snapshotSettings)); // same value types as theirs
        List<String> differences = new ArrayList<>();
        for (String key : ours.keySet()) {
            if (!Objects.equals(ours.get(key), theirs.get(key))) {
                differences.add(key + " (snapshot: " + Json.write(theirs.get(key)) + ", this engine: "
                        + Json.write(ours.get(key)) + ")");
            }
        }
        for (Object key : theirs.keySet()) {
            if (!ours.containsKey(String.valueOf(key))) {
                differences.add(key + " (only in the snapshot)");
            }
        }
        if (!differences.isEmpty()) {
            throw TlSnapshotFile.rejected("written with other trusted-list settings: " + String.join("; ", differences));
        }
    }

    /** Every anchor's list must be in the summary, or validating a trusted chain would fail (see the class comment). */
    private static void checkConsistent(TlSnapshotFile.Contents contents) {
        TLValidationJobSummary summary = contents.summary();
        Set<String> missing = new TreeSet<>();
        for (List<TrustProperties> properties : contents.trustProperties().values()) {
            for (TrustProperties p : properties) {
                if (p.getTLInfo() != null && summary.getTLInfoById(p.getTLInfo().getDSSId()) == null) {
                    missing.add(p.getTLInfo().getUrl());
                }
                if (p.getLOTLInfo() != null && summary.getLOTLInfoById(p.getLOTLInfo().getDSSId()) == null) {
                    missing.add(p.getLOTLInfo().getUrl());
                }
            }
        }
        if (!missing.isEmpty()) {
            throw TlSnapshotFile.rejected("the snapshot's trust anchors reference lists its summary does not hold ("
                    + String.join(", ", missing) + "); write a new snapshot after a successful refresh");
        }
    }

    /**
     * Applies {@code tl_sync} again, at the current time. DSS decides at every load whether a list may be used, and
     * a list past its next update is dropped when {@code accept_expired} is false. A snapshot must not keep
     * trusting a list that a load from the cache would now drop, so such a snapshot is refused as a whole.
     */
    private void checkUsable(TlSnapshotFile.Contents contents) {
        Set<String> trusting = new HashSet<>();
        for (List<TrustProperties> properties : contents.trustProperties().values()) {
            for (TrustProperties p : properties) {
                if (p.getTLInfo() != null) {
                    trusting.add(p.getTLInfo().getUrl());
                }
            }
        }
        TLValidationJobSummary summary = contents.summary();
        for (LOTLInfo lotl : summary.getLOTLInfos()) {
            boolean lotlUsable = syncStrategy.canBeSynchronized(lotl);
            if (lotl.getTLInfos() != null) {
                for (TLInfo tl : lotl.getTLInfos()) {
                    requireUsable(tl, lotlUsable, trusting);
                }
            }
        }
        for (TLInfo tl : summary.getOtherTLInfos()) {
            requireUsable(tl, true, trusting);
        }
    }

    private void requireUsable(TLInfo tl, boolean parentUsable, Set<String> trusting) {
        if (trusting.contains(tl.getUrl()) && !(parentUsable && syncStrategy.canBeSynchronized(tl))) {
            TLParsingInfoRecord p = tl.getParsingCacheInfo();
            throw TlSnapshotFile.rejected("the snapshot trusts " + tl.getUrl() + ", which tl_sync no longer allows"
                    + (p != null && p.getNextUpdateDate() != null ? " (next update was " + iso(p.getNextUpdateDate())
                    + ")" : "") + "; write a new snapshot");
        }
    }

    /**
     * The published lists as a trusted-list snapshot file. A snapshot of lists that themselves came from a snapshot
     * keeps the original {@code lists_loaded}, the load that validated them.
     */
    Exported exportSnapshot() {
        Snapshot snap = current;
        if (!snap.loaded()) {
            throw new DssError(DssError.Code.TRUSTED_LISTS_NOT_LOADED, "no trusted list is loaded: nothing to export");
        }
        TrustedListsCertificateSource source = snap.source();
        Map<CertificateToken, List<TrustProperties>> properties = new HashMap<>();
        Map<CertificateToken, List<CertificateTrustTime>> trustTimes = new HashMap<>();
        for (CertificateToken token : source.getCertificates()) {
            properties.put(token, new ArrayList<>(source.getTrustServices(token)));
            trustTimes.put(token, new ArrayList<>(List.of(source.getTrustTime(token))));
        }
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("format", TlSnapshotFile.FORMAT);
        header.put("library", BuildInfo.library());
        header.put("dss", BuildInfo.dss());
        header.put("created_at", Instant.now().toString());
        header.put("lists_loaded", snap.tlSnapshot() != null ? snap.tlSnapshot().get("lists_loaded")
                : snap.loadedBy().toMap());
        header.put("trusted_certificates", source.getNumberOfCertificates());
        header.put("settings", snapshotSettings);
        byte[] bytes = TlSnapshotFile.write(header,
                new TlSnapshotFile.Contents(properties, trustTimes, snap.summary(), alertList()));
        Map<String, Object> info = new LinkedHashMap<>(header);
        info.put("size", bytes.length);
        return new Exported(bytes, info);
    }

    /** Copies the staging source into a fresh one. Caller holds {@link #refreshLock}, so staging is quiescent. */
    private void publishSnapshot(RefreshRecord loadedBy, Map<String, Object> tlSnapshot) {
        Map<CertificateToken, List<TrustProperties>> properties = new HashMap<>();
        Map<CertificateToken, List<CertificateTrustTime>> trustTimes = new HashMap<>();
        for (CertificateToken token : staging.getCertificates()) {
            properties.put(token, new ArrayList<>(staging.getTrustServices(token)));
            trustTimes.put(token, List.of(staging.getTrustTime(token)));
        }
        TrustedListsCertificateSource copy = new TrustedListsCertificateSource();
        copy.setTrustPropertiesByCertificates(properties);
        copy.setTrustTimeByCertificates(trustTimes);
        copy.setSummary(staging.getSummary());
        current = new Snapshot(copy, staging.getSummary(), Instant.now(), loadedBy, tlSnapshot);
    }

    /**
     * The root of trust in use: {@code path} (as configured) and {@code sha256} (over the sorted digests of the
     * keystore's certificates, the value snapshots record as {@code oj_keystore_sha256}).
     */
    Map<String, Object> ojKeystore() {
        return ojKeystoreInfo;
    }

    /** Status from the last published snapshot; never blocks on a running refresh. */
    Map<String, Object> status() {
        Snapshot snap = current;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("loaded", snap.loaded());
        m.put("oj_keystore", ojKeystoreInfo);
        m.put("trusted_certificates", snap.source().getNumberOfCertificates());
        m.put("snapshot_published_at", snap.publishedAt().toString());
        m.put("tl_snapshot", snap.tlSnapshot());
        Instant running = onlineRefreshStartedAt;
        m.put("refresh_in_progress", running != null);
        m.put("refresh_started_at", running == null ? null : running.toString());
        m.put("last_offline_refresh", lastOffline == null ? null : lastOffline.toMap());
        m.put("last_online_refresh", lastOnline == null ? null : lastOnline.toMap());
        m.put("countries_unmatched", unmatchedCountries(snap.summary()));

        List<Object> lotls = new ArrayList<>();
        List<Object> tls = new ArrayList<>();
        TLValidationJobSummary summary = snap.summary();
        if (summary != null) {
            for (LOTLInfo lotl : summary.getLOTLInfos()) {
                boolean lotlUsed = syncStrategy.canBeSynchronized(lotl);
                Map<String, Object> lm = describe(lotl);
                lm.put("used_for_trust", lotlUsed);
                List<Object> pivots = new ArrayList<>();
                if (lotl.getPivotInfos() != null) {
                    for (PivotInfo p : lotl.getPivotInfos()) {
                        pivots.add(describe(p));
                    }
                }
                lm.put("pivots", pivots);
                lotls.add(lm);
                if (lotl.getTLInfos() != null) {
                    for (TLInfo tl : lotl.getTLInfos()) {
                        Map<String, Object> tm = describe(tl);
                        tm.put("used_for_trust", lotlUsed && syncStrategy.canBeSynchronized(tl));
                        tls.add(tm);
                    }
                }
            }
            for (TLInfo tl : summary.getOtherTLInfos()) {
                Map<String, Object> tm = describe(tl);
                tm.put("used_for_trust", syncStrategy.canBeSynchronized(tl));
                tls.add(tm);
            }
        }
        m.put("lotls", lotls);
        m.put("tls", tls);
        m.put("alerts", alertList());
        return m;
    }

    private Map<String, Object> describe(TLInfo info) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("url", info.getUrl());
        ListVersion floor = info.getUrl() == null ? null : published.get(info.getUrl());
        m.put("last_published_sequence_number", floor == null ? null : floor.sequenceNumber());
        TLParsingInfoRecord p = info.getParsingCacheInfo();
        if (p != null && p.isResultExist()) {
            m.put("territory", p.getTerritory());
            m.put("sequence_number", p.getSequenceNumber());
            m.put("version", p.getVersion());
            m.put("issue_date", iso(p.getIssueDate()));
            m.put("next_update", iso(p.getNextUpdateDate()));
            m.put("expired", p.getNextUpdateDate() != null && p.getNextUpdateDate().before(new Date()));
            m.put("tsp_count", p.getTSPNumber());
            m.put("service_count", p.getTSNumber());
            m.put("certificate_count", p.getCertNumber());
            m.put("structure_messages", new ArrayList<>(structureMessageList(info)));
        }
        m.put("download", record(info.getDownloadCacheInfo()));
        m.put("parsing", record(p));
        Map<String, Object> v = record(info.getValidationCacheInfo());
        ValidationInfoRecord vr = info.getValidationCacheInfo();
        if (vr != null && vr.isResultExist()) {
            v.put("indication", vr.getIndication() == null ? null : vr.getIndication().name());
            v.put("sub_indication", vr.getSubIndication() == null ? null : vr.getSubIndication().name());
            v.put("signing_time", iso(vr.getSigningTime()));
            v.put("signed_by", vr.getSigningCertificate() == null ? null
                    : vr.getSigningCertificate().getSubject().getRFC2253());
        }
        m.put("validation", v);
        return m;
    }

    private static Map<String, Object> record(InfoRecord r) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (r == null) {
            return m;
        }
        m.put("status", r.getStatusName());
        m.put("last_state_transition", iso(r.getLastStateTransitionTime()));
        m.put("last_success_synchronization", iso(r.getLastSuccessSynchronizationTime()));
        if (r.isError()) {
            m.put("error", r.getExceptionMessage());
            m.put("error_first_seen", iso(r.getExceptionFirstOccurrenceTime()));
            m.put("error_last_seen", iso(r.getExceptionLastOccurrenceTime()));
        }
        return m;
    }

    static String iso(Date d) {
        return d == null ? null : d.toInstant().toString();
    }

    /**
     * Stops the trusted-list threads (waiting up to 5 s, by default, for a running download or validation) and
     * removes the staging directory. {@link #threadsStopped()} says whether they all ended in time: a thread still
     * inside an HTTP read ends when the socket timeout does, and an isolate teardown waits for it.
     */
    @Override
    public void close() {
        executor.shutdownNow();
        boolean stopped = false;
        try {
            stopped = executor.awaitTermination(closeWait.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        threadsStopped = stopped;
        if (!stopped) {
            LOG.warn("Trusted-list threads did not stop within {} ms (a refresh is still running); shutdown may wait "
                    + "for them", closeWait.toMillis());
        }
        cacheLoader.close();
    }

    /** Whether {@link #close()} saw every trusted-list thread end. */
    boolean threadsStopped() {
        return threadsStopped;
    }
}
