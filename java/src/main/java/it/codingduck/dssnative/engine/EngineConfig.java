/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Engine configuration, parsed from {@code config_json}. Every field has a default except the OJ keystore path.
 * See README.md for the JSON shape; defaults follow the DSS 6.5.1 demo webapp unless noted.
 */
public final class EngineConfig {

    /** EU LOTL location. */
    public static final String DEFAULT_LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";
    /**
     * Official Journal publication announcing the current LOTL signing certificates
     * ({@code current.oj.url} in the DSS 6.5.1 demo). Changes whenever the EC publishes new certificates;
     * the {@code oj_url_changed} alert in the TL status says when.
     */
    public static final String DEFAULT_OJ_URL = "https://eur-lex.europa.eu/eli/C/2026/1944/oj";

    public enum Revocation { ONLINE, OFFLINE }

    public final String lotlUrl;
    public final String ojUrl;
    public final Path ojKeystorePath;
    public final String ojKeystoreType;
    public final char[] ojKeystorePassword;
    /** ISO 3166 codes of the national TLs to load; empty means every TL the LOTL points to. */
    public final List<String> countries;
    public final List<Integer> tlVersions;
    public final boolean pivotSupport;
    public final boolean useSunsetDate;
    /** Use LOTL/TL whose signature is not valid as trust sources (DSS default: yes; ours: no). */
    public final boolean tlAcceptInvalidSignature;
    /** Use LOTL/TL past their next-update date as trust sources (qualification still flags them). */
    public final boolean tlAcceptExpired;
    /** Threads that download, parse and validate trusted lists (default: CPUs, at most 16). */
    public final int tlThreads;
    /** Expiry of the online loader's file cache: 0 re-downloads on every online refresh. */
    public final long onlineCacheExpirationMs;
    public final int httpConnectTimeoutMs;
    public final int httpResponseTimeoutMs;
    /** Verify the HTTPS server certificate when downloading the LOTL/TLs (off: their XML signature is what counts). */
    public final boolean tlVerifyTls;
    /**
     * CA certificates for HTTPS (CRL, OCSP, AIA; TL downloads only with {@code tl_verify_tls}). Null: the CA set
     * built into the library (the build JDK's cacerts). When set it <em>replaces</em> that set.
     */
    public final Path httpsTrustStorePath;
    public final String httpsTrustStoreType;
    public final char[] httpsTrustStorePassword;
    public final Revocation revocation;
    public final boolean aiaFetching;
    public final Set<ReportKind> defaultReports;
    public final boolean requireTrustedLists;
    public final List<Path> extraTrustedCertificates;
    /** RFC 3161 timestamping service used by {@code extend} (PAdES T and LTA); null when none is configured. */
    public final URI tsaUrl;
    /** HTTP Basic credentials for the TSA; both null when it needs none. */
    public final String tsaUsername;
    public final char[] tsaPassword;
    public final String logLevel;
    /**
     * Trusted-list snapshot to load at startup instead of {@code <cache_dir>/tl} (written by
     * {@code dss_tl_export_snapshot}); null loads the cache.
     */
    public final Path tlSnapshot;

    private EngineConfig(JsonFields f) {
        f.allowOnly(Set.of("lotl_url", "oj_url", "oj_keystore", "countries", "tl_versions", "pivot_support",
                "use_sunset_date", "tl_sync", "tl_threads", "online_cache_expiration_ms", "http", "revocation", "aia", "reports",
                "require_trusted_lists", "extra_trusted_certificates", "tsa", "log_level", "tl_snapshot"));
        lotlUrl = f.string("lotl_url", DEFAULT_LOTL_URL);
        ojUrl = f.string("oj_url", DEFAULT_OJ_URL);

        JsonFields ks = f.object("oj_keystore").allowOnly(Set.of("path", "type", "password"));
        ojKeystorePath = Path.of(ks.requiredString("path"));
        ojKeystoreType = ks.string("type", "PKCS12");
        // The keystore holds only public certificates; DSS ships it with this password.
        ojKeystorePassword = ks.string("password", "dss-password").toCharArray();

        countries = f.strings("countries", List.of()).stream().map(c -> c.toUpperCase(Locale.ROOT)).toList();
        for (String c : countries) {
            if (!c.matches("[A-Z]{2}")) {
                throw f.error("'countries' entries must be 2-letter codes, got '" + c + "'");
            }
        }
        tlVersions = f.integers("tl_versions", List.of(6));
        pivotSupport = f.bool("pivot_support", true);
        useSunsetDate = f.bool("use_sunset_date", true);
        JsonFields sync = f.object("tl_sync").allowOnly(Set.of("accept_invalid_signature", "accept_expired"));
        tlAcceptInvalidSignature = sync.bool("accept_invalid_signature", false);
        tlAcceptExpired = sync.bool("accept_expired", true);
        onlineCacheExpirationMs = f.integer("online_cache_expiration_ms", 0);
        long threads = f.integer("tl_threads", Math.min(16, Runtime.getRuntime().availableProcessors()));
        if (threads < 1 || threads > 64) {
            throw f.error("'tl_threads' must be between 1 and 64");
        }
        tlThreads = (int) threads;

        JsonFields http = f.object("http").allowOnly(Set.of("connect_timeout_ms", "response_timeout_ms",
                "tl_verify_tls", "trust_store"));
        httpConnectTimeoutMs = (int) http.integer("connect_timeout_ms", 30_000);
        httpResponseTimeoutMs = (int) http.integer("response_timeout_ms", 60_000);
        tlVerifyTls = http.bool("tl_verify_tls", false);
        JsonFields ts = http.object("trust_store").allowOnly(Set.of("path", "type", "password"));
        String tsPath = ts.string("path", null);
        httpsTrustStorePath = tsPath == null ? null : Path.of(tsPath);
        httpsTrustStoreType = ts.string("type", "PKCS12");
        httpsTrustStorePassword = ts.string("password", "").toCharArray();

        String rev = f.string("revocation", "online");
        try {
            revocation = Revocation.valueOf(rev.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw f.error("'revocation' must be \"online\" or \"offline\"");
        }
        aiaFetching = f.bool("aia", revocation == Revocation.ONLINE);
        defaultReports = ReportKind.parse(f.strings("reports", List.of()), DssError.Code.INVALID_CONFIG, "config");
        requireTrustedLists = f.bool("require_trusted_lists", true);
        extraTrustedCertificates = f.strings("extra_trusted_certificates", List.of()).stream().map(Path::of).toList();

        JsonFields tsa = f.object("tsa").allowOnly(Set.of("url", "username", "password"));
        tsaUrl = tsa.has("url") ? httpUrl(tsa, "url") : null;
        tsaUsername = tsa.string("username", null);
        String tsaPw = tsa.string("password", null);
        if ((tsaUsername == null) != (tsaPw == null)) {
            throw tsa.error("'username' and 'password' must be given together");
        }
        if (tsaUsername != null && tsaUrl == null) {
            throw tsa.error("'url' is required with 'username'");
        }
        tsaPassword = tsaPw == null ? null : tsaPw.toCharArray();
        logLevel = f.string("log_level", "warn");
        String snapshot = f.string("tl_snapshot", null);
        if (snapshot != null && snapshot.isBlank()) {
            throw f.error("'tl_snapshot' must be a file path");
        }
        tlSnapshot = snapshot == null ? null : Path.of(snapshot);
    }

    /**
     * The settings that decide which trusted lists end up trusted, as a trusted-list snapshot records them: a
     * snapshot is only loaded by an engine whose settings are the same. Countries are sorted, so their order in
     * {@code config_json} does not matter.
     */
    Map<String, Object> trustedListSettings() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("lotl_url", lotlUrl);
        m.put("oj_url", ojUrl);
        m.put("countries", countries.stream().sorted().toList());
        m.put("tl_versions", tlVersions);
        m.put("pivot_support", pivotSupport);
        m.put("use_sunset_date", useSunsetDate);
        Map<String, Object> sync = new LinkedHashMap<>();
        sync.put("accept_invalid_signature", tlAcceptInvalidSignature);
        sync.put("accept_expired", tlAcceptExpired);
        m.put("tl_sync", sync);
        return m;
    }

    private static URI httpUrl(JsonFields f, String key) {
        String value = f.requiredString(key);
        try {
            URI uri = new URI(value);
            String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
            if ((scheme.equals("http") || scheme.equals("https")) && uri.getHost() != null) {
                return uri;
            }
        } catch (URISyntaxException e) {
            // reported below
        }
        throw f.error("'" + key + "' must be an http or https URL, got '" + value + "'");
    }

    public static EngineConfig fromJson(String json) {
        Map<String, Object> map;
        try {
            map = Json.parseObject(json);
        } catch (Json.ParseException e) {
            throw new DssError(DssError.Code.INVALID_CONFIG, "config_json is not valid JSON: " + e.getMessage());
        }
        return new EngineConfig(new JsonFields(map, "config", DssError.Code.INVALID_CONFIG));
    }
}
