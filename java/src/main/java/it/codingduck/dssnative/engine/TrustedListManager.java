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
import java.time.Instant;
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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.alert.Alert;
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
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
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

/**
 * Owns the EU trusted lists: a DSS {@link TLValidationJob} over a file cache, refreshed offline at startup and
 * online on demand.
 *
 * <p>Concurrency: DSS's synchronizer clears and refills its {@link TrustedListsCertificateSource} in place, so a
 * validation running during a refresh could see an empty or half-built trust pool. The job therefore writes to a
 * private <em>staging</em> source, and after each refresh a full copy is published as an immutable
 * {@link Snapshot} through a volatile field. Validators only ever read snapshots. Refreshes are serialized.
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

    /** Outcome of one refresh run. Per-list problems are in the TL status, not here. */
    record RefreshRecord(String mode, Instant startedAt, Instant finishedAt, boolean completed, String error,
                         int trustedCertificates) {
        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("mode", mode);
            m.put("started_at", startedAt.toString());
            m.put("finished_at", finishedAt.toString());
            m.put("duration_ms", finishedAt.toEpochMilli() - startedAt.toEpochMilli());
            m.put("completed", completed);
            m.put("error", error);
            m.put("trusted_certificates", trustedCertificates);
            return m;
        }
    }

    private static final int MAX_ALERTS = 100;

    private final TLValidationJob job;
    private final ExpirationAndSignatureCheckStrategy syncStrategy;
    /** The settings a trusted-list snapshot records and must match: {@link EngineConfig#trustedListSettings} + OJ. */
    private final Map<String, Object> snapshotSettings;
    private final TrustedListsCertificateSource staging = new TrustedListsCertificateSource();
    private final ExecutorService executor;
    private final ReentrantLock refreshLock = new ReentrantLock();
    private final List<Map<String, Object>> alerts = Collections.synchronizedList(new ArrayList<>());

    private volatile Snapshot current;
    private volatile RefreshRecord lastOffline;
    private volatile RefreshRecord lastOnline;
    private volatile Instant onlineRefreshStartedAt;

    TrustedListManager(Path cacheDir, EngineConfig config, DataLoader httpLoader) {
        Path tlCache = cacheDir.resolve("tl");
        try {
            Files.createDirectories(tlCache);
        } catch (IOException e) {
            throw new DssError(DssError.Code.INVALID_CONFIG, "cannot create cache directory " + tlCache + ": " + e);
        }

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
        snapshotSettings.put("oj_keystore_sha256", certificatesSha256(ojKeystore.getCertificates()));

        LOTLSource lotl = new LOTLSource();
        lotl.setUrl(config.lotlUrl);
        lotl.setCertificateSource(ojKeystore);
        lotl.setPivotSupport(config.pivotSupport);
        lotl.setSigningCertificatesAnnouncementPredicate(new OfficialJournalSchemeInformationURI(config.ojUrl));
        if (config.useSunsetDate) {
            lotl.setTrustAnchorValidityPredicate(new GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate());
        }
        if (!config.tlVersions.isEmpty()) {
            lotl.setTLVersions(config.tlVersions);
        }
        if (!config.countries.isEmpty()) {
            lotl.setTlPredicate(TLPredicateFactory.createEUTLCountryCodePredicate(
                    config.countries.toArray(new String[0])));
        }

        FileCacheDataLoader offline = new FileCacheDataLoader();
        offline.setCacheExpirationTime(-1); // never expires: read whatever the last online refresh stored
        offline.setDataLoader(new IgnoreDataLoader());
        offline.setFileCacheDirectory(tlCache.toFile());

        FileCacheDataLoader online = new FileCacheDataLoader();
        online.setCacheExpirationTime(config.onlineCacheExpirationMs);
        online.setDataLoader(httpLoader);
        online.setFileCacheDirectory(tlCache.toFile());

        AtomicInteger threadId = new AtomicInteger();
        // Loading from the cache re-validates every list's XAdES signature: CPU-bound, ~32 lists for the full LOTL.
        executor = Executors.newFixedThreadPool(config.tlThreads, r -> {
            Thread t = new Thread(r, "dss-tl-" + threadId.incrementAndGet());
            t.setDaemon(true); // must not keep a host process (or an isolate teardown) waiting
            return t;
        });

        // DSS's default (AcceptAllStrategy) turns every TL into trust anchors even when the LOTL or TL signature
        // does not validate: a tampered cache or download would inject trust. Only signature-valid lists count.
        syncStrategy = new ExpirationAndSignatureCheckStrategy();
        syncStrategy.setAcceptInvalidListOfTrustedLists(config.tlAcceptInvalidSignature);
        syncStrategy.setAcceptInvalidTrustedList(config.tlAcceptInvalidSignature);
        syncStrategy.setAcceptExpiredListOfTrustedLists(config.tlAcceptExpired);
        syncStrategy.setAcceptExpiredTrustedList(config.tlAcceptExpired);

        job = new TLValidationJob();
        job.setSynchronizationStrategy(syncStrategy);
        job.setExecutorService(executor);
        job.setListOfTrustedListSources(lotl);
        job.setOfflineDataLoader(offline);
        job.setOnlineDataLoader(online);
        job.setTrustedListCertificateSource(staging);
        job.setLOTLAlerts(List.of(
                new LOTLAlert(new OJUrlChangeDetection(lotl), collect("oj_url_changed",
                        i -> "LOTL announces new signing certificates at "
                                + i.getParsingCacheInfo().getSigningCertificateAnnouncementUrl()
                                + "; update oj_url and the OJ keystore")),
                new LOTLAlert(new LOTLLocationChangeDetection(lotl), collect("lotl_location_changed",
                        i -> "LOTL location changed; check lotl_url"))));
        job.setTLAlerts(List.<Alert<TLInfo>>of(
                new TLAlert(new TLSignatureErrorDetection(), collect("tl_signature_error",
                        i -> "trusted list signature is not valid")),
                new TLAlert(new TLExpirationDetection(), collect("tl_expired",
                        i -> "trusted list is past its next update date"))));

        current = new Snapshot(new TrustedListsCertificateSource(), null, Instant.now(), null, null);
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

    private <T extends TLInfo> AlertHandler<T> collect(String type, java.util.function.Function<T, String> message) {
        return info -> {
            Map<String, Object> a = new LinkedHashMap<>();
            a.put("type", type);
            a.put("url", info.getUrl());
            a.put("message", message.apply(info));
            a.put("at", Instant.now().toString());
            LOG.warn("Trusted list alert {} for {}: {}", type, info.getUrl(), a.get("message"));
            synchronized (alerts) {
                alerts.add(a);
                if (alerts.size() > MAX_ALERTS) {
                    alerts.remove(0);
                }
            }
        };
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
        try {
            refresh.run();
        } catch (RuntimeException e) {
            // DSS records per-list failures itself; reaching here means the job could not run at all. Staging may
            // be half-refilled, so the published lists, and where they came from, stay as they were.
            LOG.error("{} trusted-list refresh failed", mode, e);
            return new RefreshRecord(mode, start, Instant.now(), false,
                    e.getClass().getSimpleName() + ": " + e.getMessage(), current.source().getNumberOfCertificates());
        }
        RefreshRecord record = new RefreshRecord(mode, start, Instant.now(), true, null,
                staging.getNumberOfCertificates());
        publishSnapshot(record, null);
        return record;
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
            byte[] bytes;
            try {
                bytes = Files.readAllBytes(file);
            } catch (IOException | RuntimeException e) {
                throw TlSnapshotFile.rejected("cannot read " + file + ": " + e);
            }
            Map<String, Object> header = TlSnapshotFile.header(bytes);
            checkCompatible(header);
            TlSnapshotFile.Contents contents = TlSnapshotFile.contents(bytes);
            checkUsable(contents);

            // Staging too, so that a later refresh that cannot run keeps these lists, as it keeps cached ones.
            staging.setTrustPropertiesByCertificates(contents.trustProperties());
            staging.setTrustTimeByCertificates(contents.trustTimes());
            staging.setSummary(contents.summary());
            synchronized (alerts) {
                alerts.clear();
                alerts.addAll(contents.alerts());
            }
            RefreshRecord record = new RefreshRecord("snapshot", start, Instant.now(), true, null,
                    staging.getNumberOfCertificates());
            Map<String, Object> info = new LinkedHashMap<>();
            info.put("path", file.toString());
            info.put("size", bytes.length);
            info.putAll(header);
            publishSnapshot(record, info);
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
        List<Map<String, Object>> alertsNow;
        synchronized (alerts) {
            alertsNow = new ArrayList<>(alerts);
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
                new TlSnapshotFile.Contents(properties, trustTimes, snap.summary(), alertsNow));
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

    /** Status from the last published snapshot; never blocks on a running refresh. */
    Map<String, Object> status() {
        Snapshot snap = current;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("loaded", snap.loaded());
        m.put("trusted_certificates", snap.source().getNumberOfCertificates());
        m.put("snapshot_published_at", snap.publishedAt().toString());
        m.put("tl_snapshot", snap.tlSnapshot());
        Instant running = onlineRefreshStartedAt;
        m.put("refresh_in_progress", running != null);
        m.put("refresh_started_at", running == null ? null : running.toString());
        m.put("last_offline_refresh", lastOffline == null ? null : lastOffline.toMap());
        m.put("last_online_refresh", lastOnline == null ? null : lastOnline.toMap());

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
        synchronized (alerts) {
            m.put("alerts", new ArrayList<>(alerts));
        }
        return m;
    }

    private static Map<String, Object> describe(TLInfo info) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("url", info.getUrl());
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

    @Override
    public void close() {
        executor.shutdownNow();
        try {
            executor.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
