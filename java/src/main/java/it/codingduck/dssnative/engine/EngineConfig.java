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
    /** What DSS accepts when {@code tl_versions} is empty: its own default, made explicit. */
    public static final List<Integer> DSS_DEFAULT_TL_VERSIONS = List.of(5, 6);
    /** slf4j-simple's level names; anything else would silently mean INFO. */
    public static final Set<String> LOG_LEVELS = Set.of("off", "error", "warn", "info", "debug", "trace");
    /** Largest HTTP response body the outbound-fetch policy accepts by default (64 MiB). */
    public static final long DEFAULT_MAX_RESPONSE_BYTES = 64L * 1024 * 1024;
    /** Wall-clock bound on one outbound request by default, redirects and retries included. */
    public static final long DEFAULT_REQUEST_DEADLINE_MS = 120_000;
    /** How long GET responses (CRLs, AIA certificates) are reused across calls by default (one hour). */
    public static final long DEFAULT_HTTP_CACHE_MS = 3_600_000;
    /** How far a timestamp token's time may be from this host's clock by default (five minutes). */
    public static final long DEFAULT_TSA_MAX_CLOCK_SKEW_MS = 300_000;

    /** An outgoing HTTP proxy ({@code http.proxy}); {@code username} and {@code password} both null when none. */
    public record Proxy(String host, int port, String scheme, String username, char[] password,
                        List<String> noProxy) {
    }

    public enum Revocation { ONLINE, OFFLINE }

    public final String lotlUrl;
    public final String ojUrl;
    public final Path ojKeystorePath;
    public final String ojKeystoreType;
    public final char[] ojKeystorePassword;
    /** ISO 3166 codes of the national TLs to load, distinct and upper-case; empty means every TL the LOTL points to. */
    public final List<String> countries;
    /** TL versions DSS accepts, sorted and distinct; never empty ({@code []} means {@link #DSS_DEFAULT_TL_VERSIONS}). */
    public final List<Integer> tlVersions;
    public final boolean pivotSupport;
    public final boolean useSunsetDate;
    /** Use LOTL/TL whose signature is not valid as trust sources (DSS default: yes; ours: no). */
    public final boolean tlAcceptInvalidSignature;
    /** Use LOTL/TL past their next-update date as trust sources (qualification still flags them). */
    public final boolean tlAcceptExpired;
    /**
     * Use lists whose structure DSS flags (a version outside {@code tl_versions}, schema deviations) as trust
     * sources. Default yes, as DSS does; the status and the {@code tl_structure_error} alert report them either way.
     */
    public final boolean tlAcceptStructureErrors;
    /** Threads that download, parse and validate trusted lists (default: CPUs, at most 16). */
    public final int tlThreads;
    /** Expiry of the online loader's file cache: 0 re-downloads on every online refresh. Never negative. */
    public final long onlineCacheExpirationMs;
    /** Connect (and connection-request) timeout, 1 ms to {@link Integer#MAX_VALUE}. */
    public final int httpConnectTimeoutMs;
    /** Response-headers and socket-read timeout, 1 ms to {@link Integer#MAX_VALUE}. */
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
    /** URL schemes the outbound-fetch policy lets through, lower-case (default {@code http}, {@code https}). */
    public final List<String> httpAllowedSchemes;
    /**
     * Refuse outbound requests to loopback, private, link-local, multicast and unspecified addresses (literal or
     * resolved). On by default: CRL, OCSP and AIA URLs come from the documents being validated.
     */
    public final boolean httpBlockPrivateAddresses;
    /** Largest response body accepted, in bytes; larger ones fail the request. */
    public final long httpMaxResponseBytes;
    /** Wall-clock bound on one outbound request, in ms; 0 disables it (the per-socket timeouts still apply). */
    public final long httpRequestDeadlineMs;
    /** Whether the HTTP client follows redirects (TL hosts do redirect; CRL/OCSP rarely do). */
    public final boolean httpFollowRedirects;
    /** Outgoing proxy for every HTTP client of the engine; null when none is configured. */
    public final Proxy httpProxy;
    /** Take the proxy from the JVM's {@code http(s).proxyHost} system properties (Apache HttpClient's rule). */
    public final boolean httpUseSystemProxy;
    /** How long GET responses (CRLs, AIA certificates) are reused across calls, in ms; 0 disables the cache. */
    public final long httpCacheMs;
    /** Bounds on document structure that drive DSS's super-linear costs ({@code limits}). */
    public final DocumentLimits.Limits limits;
    public final Revocation revocation;
    public final boolean aiaFetching;
    public final Set<ReportKind> defaultReports;
    public final boolean requireTrustedLists;
    public final List<Path> extraTrustedCertificates;
    /** RFC 3161 timestamping service used by {@code extend} (PAdES T and LTA); null when none is configured. */
    public final URI tsaUrl;
    /** HTTP Basic credentials for the TSA; both null when it needs none. Only accepted with an https {@link #tsaUrl}. */
    public final String tsaUsername;
    public final char[] tsaPassword;
    /** Refuse timestamp tokens whose TSA certificate does not chain to the trust anchors (when there are any). */
    public final boolean tsaRequireTrusted;
    /** Refuse timestamp tokens dated further than this from the host's clock, in ms. */
    public final long tsaMaxClockSkewMs;
    /** One of {@link #LOG_LEVELS}, lower-case. */
    public final String logLevel;
    /**
     * Trusted-list snapshot to load at startup instead of {@code <cache_dir>/tl} (written by
     * {@code dss_tl_export_snapshot}); null loads the cache.
     */
    public final Path tlSnapshot;

    private EngineConfig(JsonFields f) {
        f.allowOnly(Set.of("lotl_url", "oj_url", "oj_keystore", "countries", "tl_versions", "pivot_support",
                "use_sunset_date", "tl_sync", "tl_threads", "online_cache_expiration_ms", "http", "revocation", "aia", "reports",
                "require_trusted_lists", "extra_trusted_certificates", "tsa", "log_level", "tl_snapshot", "limits"));
        lotlUrl = f.string("lotl_url", DEFAULT_LOTL_URL);
        ojUrl = f.string("oj_url", DEFAULT_OJ_URL);

        JsonFields ks = f.object("oj_keystore").allowOnly(Set.of("path", "type", "password"));
        ojKeystorePath = Path.of(ks.requiredString("path"));
        ojKeystoreType = ks.string("type", "PKCS12");
        // The keystore holds only public certificates; DSS ships it with this password.
        ojKeystorePassword = ks.string("password", "dss-password").toCharArray();

        // Distinct and sorted: a set, as the snapshot settings compare them.
        countries = f.strings("countries", List.of()).stream().map(c -> c.toUpperCase(Locale.ROOT)).distinct()
                .sorted().toList();
        for (String c : countries) {
            if (!c.matches("[A-Z]{2}")) {
                throw f.error("'countries' entries must be 2-letter codes, got '" + c + "'");
            }
            if (c.equals("GR")) {
                throw f.error("'countries': the LOTL names Greece \"EL\" (its scheme territory), not \"GR\"");
            }
        }
        List<Integer> versions = f.integers("tl_versions", List.of(6)).stream().distinct().sorted().toList();
        for (Integer v : versions) {
            if (v < 1) {
                throw f.error("'tl_versions' entries must be positive, got " + v);
            }
        }
        tlVersions = versions.isEmpty() ? DSS_DEFAULT_TL_VERSIONS : versions;
        pivotSupport = f.bool("pivot_support", true);
        useSunsetDate = f.bool("use_sunset_date", true);
        JsonFields sync = f.object("tl_sync").allowOnly(Set.of("accept_invalid_signature", "accept_expired",
                "accept_structure_errors"));
        tlAcceptInvalidSignature = sync.bool("accept_invalid_signature", false);
        tlAcceptExpired = sync.bool("accept_expired", true);
        tlAcceptStructureErrors = sync.bool("accept_structure_errors", true);
        onlineCacheExpirationMs = f.integer("online_cache_expiration_ms", 0);
        if (onlineCacheExpirationMs < 0) {
            // DSS reads a negative expiry as "never expires": online refreshes would only ever read the cache.
            throw f.error("'online_cache_expiration_ms' must be 0 (always re-download) or a positive number of ms");
        }
        long threads = f.integer("tl_threads", Math.min(16, Runtime.getRuntime().availableProcessors()));
        if (threads < 1 || threads > 64) {
            throw f.error("'tl_threads' must be between 1 and 64");
        }
        tlThreads = (int) threads;

        JsonFields http = f.object("http").allowOnly(Set.of("connect_timeout_ms", "response_timeout_ms",
                "tl_verify_tls", "trust_store", "allowed_schemes", "block_private_addresses", "max_response_bytes",
                "request_deadline_ms", "follow_redirects", "proxy", "use_system_proxy", "cache_ms"));
        httpConnectTimeoutMs = timeout(http, "connect_timeout_ms", 30_000);
        httpResponseTimeoutMs = timeout(http, "response_timeout_ms", 60_000);
        tlVerifyTls = http.bool("tl_verify_tls", false);
        JsonFields ts = http.object("trust_store").allowOnly(Set.of("path", "type", "password"));
        String tsPath = ts.string("path", null);
        httpsTrustStorePath = tsPath == null ? null : Path.of(tsPath);
        httpsTrustStoreType = ts.string("type", "PKCS12");
        httpsTrustStorePassword = ts.string("password", "").toCharArray();
        httpAllowedSchemes = http.strings("allowed_schemes", List.of("http", "https")).stream()
                .map(s -> s.toLowerCase(Locale.ROOT)).distinct().toList();
        if (httpAllowedSchemes.isEmpty()) {
            throw http.error("'allowed_schemes' must name at least one scheme");
        }
        for (String s : httpAllowedSchemes) {
            if (!s.matches("[a-z][a-z0-9+.-]*")) {
                throw http.error("'allowed_schemes' holds an invalid scheme '" + s + "'");
            }
        }
        httpBlockPrivateAddresses = http.bool("block_private_addresses", true);
        httpMaxResponseBytes = http.integer("max_response_bytes", DEFAULT_MAX_RESPONSE_BYTES);
        if (httpMaxResponseBytes < 1) {
            throw http.error("'max_response_bytes' must be positive");
        }
        httpRequestDeadlineMs = http.integer("request_deadline_ms", DEFAULT_REQUEST_DEADLINE_MS);
        if (httpRequestDeadlineMs < 0) {
            throw http.error("'request_deadline_ms' must be 0 (no deadline) or a positive number of ms");
        }
        httpFollowRedirects = http.bool("follow_redirects", true);
        httpUseSystemProxy = http.bool("use_system_proxy", false);
        httpProxy = http.has("proxy") ? proxy(http.object("proxy")) : null;
        if (httpProxy != null && httpUseSystemProxy) {
            throw http.error("'proxy' and 'use_system_proxy' exclude each other");
        }
        httpCacheMs = http.integer("cache_ms", DEFAULT_HTTP_CACHE_MS);
        if (httpCacheMs < 0) {
            throw http.error("'cache_ms' must be 0 (no cache) or a positive number of ms");
        }
        limits = DocumentLimits.Limits.parse(f.object("limits"));

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

        JsonFields tsa = f.object("tsa").allowOnly(Set.of("url", "username", "password", "require_trusted",
                "max_clock_skew_ms"));
        tsaUrl = tsa.has("url") ? httpUrl(tsa, "url") : null;
        tsaRequireTrusted = tsa.bool("require_trusted", true);
        tsaMaxClockSkewMs = tsa.integer("max_clock_skew_ms", DEFAULT_TSA_MAX_CLOCK_SKEW_MS);
        if (tsaMaxClockSkewMs < 0) {
            throw tsa.error("'max_clock_skew_ms' must be 0 or a positive number of ms");
        }
        tsaUsername = tsa.string("username", null);
        String tsaPw = tsa.string("password", null);
        if ((tsaUsername == null) != (tsaPw == null)) {
            throw tsa.error("'username' and 'password' must be given together");
        }
        if (tsaUsername != null && tsaUrl == null) {
            throw tsa.error("'url' is required with 'username'");
        }
        if (tsaUsername != null && !"https".equalsIgnoreCase(tsaUrl.getScheme())) {
            // HTTP Basic sends the password in clear text (preemptively here, or after a 401 anyway).
            throw tsa.error("'username' and 'password' need an https 'url': Basic credentials would travel in clear text");
        }
        tsaPassword = tsaPw == null ? null : tsaPw.toCharArray();
        String level = f.string("log_level", "warn").toLowerCase(Locale.ROOT);
        if (!LOG_LEVELS.contains(level)) {
            throw f.error("'log_level' must be one of off, error, warn, info, debug, trace; got '" + level + "'");
        }
        logLevel = level;
        String snapshot = f.string("tl_snapshot", null);
        if (snapshot != null && snapshot.isBlank()) {
            throw f.error("'tl_snapshot' must be a file path");
        }
        tlSnapshot = snapshot == null ? null : Path.of(snapshot);
    }

    /** {@code http.proxy}: host and port are required; credentials both or neither; {@code no_proxy} lists hosts. */
    private static Proxy proxy(JsonFields p) {
        p.allowOnly(Set.of("host", "port", "scheme", "username", "password", "no_proxy"));
        String host = p.requiredString("host").trim();
        long port = p.integer("port", -1);
        if (port < 1 || port > 65_535) {
            throw p.error("'port' is required and must be between 1 and 65535");
        }
        String scheme = p.string("scheme", "http").toLowerCase(Locale.ROOT);
        if (!(scheme.equals("http") || scheme.equals("https"))) {
            throw p.error("'scheme' must be \"http\" or \"https\"");
        }
        String username = p.string("username", null);
        String password = p.string("password", null);
        if ((username == null) != (password == null)) {
            throw p.error("'username' and 'password' must be given together");
        }
        List<String> noProxy = p.strings("no_proxy", List.of()).stream().map(String::trim)
                .filter(s -> !s.isEmpty()).toList();
        return new Proxy(host, (int) port, scheme, username, password == null ? null : password.toCharArray(),
                noProxy);
    }

    /** A timeout in ms for Apache HttpClient: 0 would mean "no timeout" and anything beyond an int overflows. */
    private static int timeout(JsonFields http, String key, long def) {
        long value = http.integer(key, def);
        if (value < 1 || value > Integer.MAX_VALUE) {
            throw http.error("'" + key + "' must be between 1 and " + Integer.MAX_VALUE + " ms");
        }
        return (int) value;
    }

    /**
     * The settings that decide which trusted lists end up trusted, as a trusted-list snapshot records them: a
     * snapshot is only loaded by an engine whose settings are the same. Countries and TL versions are sets
     * (sorted, distinct), so their order and repetitions in {@code config_json} do not matter, and an empty
     * {@code tl_versions} is recorded as the DSS default it stands for.
     */
    Map<String, Object> trustedListSettings() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("lotl_url", lotlUrl);
        m.put("oj_url", ojUrl);
        m.put("countries", countries);
        m.put("tl_versions", tlVersions);
        m.put("pivot_support", pivotSupport);
        m.put("use_sunset_date", useSunsetDate);
        Map<String, Object> sync = new LinkedHashMap<>();
        sync.put("accept_invalid_signature", tlAcceptInvalidSignature);
        sync.put("accept_expired", tlAcceptExpired);
        if (!tlAcceptStructureErrors) {
            // Only recorded when it departs from the default, so snapshots written before the key existed still load.
            sync.put("accept_structure_errors", false);
        }
        m.put("tl_sync", sync);
        return m;
    }

    private static URI httpUrl(JsonFields f, String key) {
        String value = f.requiredString(key);
        URI uri;
        try {
            uri = new URI(value);
        } catch (URISyntaxException e) {
            throw f.error("'" + key + "' must be an http or https URL, got '" + withoutUserInfo(value) + "'");
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!(scheme.equals("http") || scheme.equals("https")) || uri.getHost() == null) {
            throw f.error("'" + key + "' must be an http or https URL, got '" + withoutUserInfo(value) + "'");
        }
        if (uri.getRawUserInfo() != null) {
            // HttpClient 5 refuses such URLs at request time, in a message that would echo the secret.
            throw f.error("'" + key + "' must not carry credentials in the URL; use 'username' and 'password'");
        }
        return uri;
    }

    /**
     * The value with any {@code user:password@} between the first {@code //} and the authority's end removed, so
     * that a message about a malformed URL never echoes a password. Textual: the value may not parse as a URI.
     */
    static String withoutUserInfo(String value) {
        int authority = value.indexOf("//");
        if (authority < 0) {
            return value.contains("@") ? value.replaceFirst("^[^/?#]*@", "") : value;
        }
        int end = authority + 2;
        while (end < value.length() && "/?#".indexOf(value.charAt(end)) < 0) {
            end++;
        }
        int at = value.lastIndexOf('@', end - 1);
        if (at < authority) {
            return value;
        }
        return value.substring(0, authority + 2) + value.substring(at + 1);
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
