/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import it.codingduck.dssnative.testsupport.TestEngines;

/** Range and consistency checks of {@code config_json}: a mistake fails loudly instead of changing behaviour. */
class EngineConfigTest {

    @TempDir
    Path tmp;

    private EngineConfig parse(String extra) {
        return EngineConfig.fromJson(new TestEngines(tmp).configJson(extra));
    }

    private String rejected(String extra) {
        DssError e = assertThrows(DssError.class, () -> parse(extra), extra);
        assertEquals(DssError.Code.INVALID_CONFIG, e.code(), extra);
        return e.getMessage();
    }

    @Test
    void negativeCacheExpirationIsRejected() {
        // DSS reads a negative expiry as "never expires": every online refresh would only read the cache.
        assertTrue(rejected("\"online_cache_expiration_ms\":-1").contains("online_cache_expiration_ms"));
        assertEquals(0, parse("\"online_cache_expiration_ms\":0").onlineCacheExpirationMs);
        assertEquals(3_600_000, parse("\"online_cache_expiration_ms\":3600000").onlineCacheExpirationMs);
    }

    @Test
    void timeoutsMustBePositiveInts() {
        for (String bad : List.of("0", "-5", "2147483648", "99999999999")) {
            assertTrue(rejected("\"http\":{\"connect_timeout_ms\":" + bad + "}").contains("connect_timeout_ms"), bad);
            assertTrue(rejected("\"http\":{\"response_timeout_ms\":" + bad + "}").contains("response_timeout_ms"), bad);
        }
        EngineConfig c = parse("\"http\":{\"connect_timeout_ms\":1,\"response_timeout_ms\":2147483647}");
        assertEquals(1, c.httpConnectTimeoutMs);
        assertEquals(Integer.MAX_VALUE, c.httpResponseTimeoutMs);
    }

    @Test
    void logLevelMustBeOneSlf4jSimpleKnows() {
        // slf4j-simple falls back to INFO for a name it does not know, so "warning" would mean noisy logs.
        assertTrue(rejected("\"log_level\":\"warning\"").contains("log_level"));
        rejected("\"log_level\":\"\"");
        for (String ok : List.of("off", "error", "warn", "info", "debug", "trace", "WARN", "Debug")) {
            assertEquals(ok.toLowerCase(), parse("\"log_level\":\"" + ok + "\"").logLevel, ok);
        }
        assertEquals("warn", parse(null).logLevel);
    }

    @Test
    void tsaCredentialsNeedHttps() {
        String message = rejected("\"tsa\":{\"url\":\"http://tsa.example.test/tsr\",\"username\":\"u\",\"password\":\"p\"}");
        assertTrue(message.contains("https"), message);
        // Without credentials, plain http is still allowed (the test TSA uses it).
        assertEquals("http", parse("\"tsa\":{\"url\":\"http://tsa.example.test/tsr\"}").tsaUrl.getScheme());
        assertEquals("u", parse("\"tsa\":{\"url\":\"https://tsa.example.test/tsr\",\"username\":\"u\",\"password\":\"p\"}")
                .tsaUsername);
    }

    @Test
    void tsaUrlMustNotCarryCredentials() {
        // HttpClient 5 refuses userinfo at request time, in a message that would echo the secret.
        String message = rejected("\"tsa\":{\"url\":\"https://tsa-user:tsa-secret@tsa.example.test/tsr\"}");
        assertFalse(message.contains("tsa-secret"), message);
        assertTrue(message.contains("username"), message);
        // A URL that fails earlier checks (no host, or not even a URI) is echoed, but never with its credentials.
        for (String url : List.of("https://tsa-user:tsa-secret@/tsr", "https://tsa-user:tsa-secret@", "tsa-user:tsa-secret@tsa.example.test/tsr",
                "https://tsa-user:tsa-secret@tsa.example.test/tsr?q=a b", "https://tsa-user:tsa-secret@[bad")) {
            String echoed = rejected("\"tsa\":{\"url\":\"" + url + "\"}");
            assertFalse(echoed.contains("tsa-secret"), url + " -> " + echoed);
            assertTrue(echoed.contains("'url'"), echoed);
        }
        assertEquals("https:///tsr", EngineConfig.withoutUserInfo("https://u:p@/tsr"));
        assertEquals("https://h/a@b", EngineConfig.withoutUserInfo("https://h/a@b"));
        assertEquals("https://h?x=u:p@h", EngineConfig.withoutUserInfo("https://h?x=u:p@h"));
        assertEquals("tsa.example.test/tsr", EngineConfig.withoutUserInfo("u:p@tsa.example.test/tsr"));
        assertEquals("plain", EngineConfig.withoutUserInfo("plain"));
    }

    @Test
    void countriesAndTlVersionsAreSets() {
        EngineConfig c = parse("\"countries\":[\"it\",\"DE\",\"IT\"],\"tl_versions\":[6,5,6]");
        assertEquals(List.of("DE", "IT"), c.countries);
        assertEquals(List.of(5, 6), c.tlVersions);
        assertEquals(List.of("DE", "IT"), c.trustedListSettings().get("countries"));
        assertEquals(List.of(5, 6), c.trustedListSettings().get("tl_versions"));
        // An empty list leaves DSS's own default in force, so that is what the snapshot settings record.
        assertEquals(EngineConfig.DSS_DEFAULT_TL_VERSIONS, parse("\"tl_versions\":[]").tlVersions);
        assertEquals(parse("\"tl_versions\":[]").trustedListSettings(), parse("\"tl_versions\":[6,5]").trustedListSettings());
        assertEquals(List.of(6), parse(null).tlVersions);
        rejected("\"tl_versions\":[0]");
    }

    @Test
    void greeceIsElInTheLotl() {
        assertTrue(rejected("\"countries\":[\"GR\"]").contains("EL"));
        assertEquals(List.of("EL"), parse("\"countries\":[\"el\"]").countries);
    }

    @Test
    void outboundPolicyKeysAreValidatedAndDefaulted() {
        EngineConfig c = parse(null);
        assertEquals(List.of("http", "https"), c.httpAllowedSchemes);
        assertTrue(c.httpBlockPrivateAddresses);
        assertEquals(EngineConfig.DEFAULT_MAX_RESPONSE_BYTES, c.httpMaxResponseBytes);
        assertEquals(EngineConfig.DEFAULT_REQUEST_DEADLINE_MS, c.httpRequestDeadlineMs);
        assertTrue(c.httpFollowRedirects);

        EngineConfig custom = parse("\"http\":{\"allowed_schemes\":[\"HTTPS\",\"ldap\"],\"block_private_addresses\":false,"
                + "\"max_response_bytes\":1024,\"request_deadline_ms\":0,\"follow_redirects\":false}");
        assertEquals(List.of("https", "ldap"), custom.httpAllowedSchemes);
        assertFalse(custom.httpBlockPrivateAddresses);
        assertEquals(1024, custom.httpMaxResponseBytes);
        assertEquals(0, custom.httpRequestDeadlineMs);
        assertFalse(custom.httpFollowRedirects);

        rejected("\"http\":{\"allowed_schemes\":[]}");
        rejected("\"http\":{\"allowed_schemes\":[\"not a scheme\"]}");
        rejected("\"http\":{\"max_response_bytes\":0}");
        rejected("\"http\":{\"request_deadline_ms\":-1}");
    }

    @Test
    void limitsProxyCacheAndTsaChecksAreParsed() {
        EngineConfig c = parse(null);
        assertEquals(DocumentLimits.Limits.DEFAULT, c.limits);
        assertEquals(EngineConfig.DEFAULT_HTTP_CACHE_MS, c.httpCacheMs);
        assertEquals(null, c.httpProxy);
        assertFalse(c.httpUseSystemProxy);
        assertTrue(c.tsaRequireTrusted);
        assertEquals(EngineConfig.DEFAULT_TSA_MAX_CLOCK_SKEW_MS, c.tsaMaxClockSkewMs);

        EngineConfig custom = parse("\"limits\":{\"max_pdf_pages\":10,\"max_pdf_signatures\":2,"
                + "\"max_pdf_annotations_per_page\":3,\"max_cms_certificates\":4},"
                + "\"http\":{\"cache_ms\":0,\"proxy\":{\"host\":\"proxy.example.test\",\"port\":8080,"
                + "\"scheme\":\"HTTPS\",\"no_proxy\":[\"a.example.test\",\" \"]}},"
                + "\"tsa\":{\"url\":\"http://tsa.example.test\",\"require_trusted\":false,\"max_clock_skew_ms\":0}");
        assertEquals(new DocumentLimits.Limits(10, 2, 3, 4), custom.limits);
        assertEquals(0, custom.httpCacheMs);
        assertEquals("proxy.example.test", custom.httpProxy.host());
        assertEquals(8080, custom.httpProxy.port());
        assertEquals("https", custom.httpProxy.scheme());
        assertEquals(null, custom.httpProxy.username());
        assertEquals(List.of("a.example.test"), custom.httpProxy.noProxy());
        assertFalse(custom.tsaRequireTrusted);
        assertEquals(0, custom.tsaMaxClockSkewMs);
        assertTrue(parse("\"http\":{\"use_system_proxy\":true}").httpUseSystemProxy);

        rejected("\"limits\":{\"max_pdf_pages\":0}");
        rejected("\"limits\":{\"pages\":5}");
        rejected("\"http\":{\"cache_ms\":-1}");
        rejected("\"http\":{\"proxy\":{\"port\":8080}}");
        rejected("\"http\":{\"proxy\":{\"host\":\"p\"}}");
        rejected("\"http\":{\"proxy\":{\"host\":\"p\",\"port\":70000}}");
        rejected("\"http\":{\"proxy\":{\"host\":\"p\",\"port\":1,\"scheme\":\"socks\"}}");
        rejected("\"http\":{\"proxy\":{\"host\":\"p\",\"port\":1,\"username\":\"u\"}}");
        rejected("\"http\":{\"proxy\":{\"host\":\"p\",\"port\":1},\"use_system_proxy\":true}");
        rejected("\"tsa\":{\"url\":\"http://tsa.example.test\",\"max_clock_skew_ms\":-5}");
    }

    @Test
    void structureErrorAcceptanceIsRecordedOnlyWhenStrict() {
        assertTrue(parse(null).tlAcceptStructureErrors);
        assertFalse(((java.util.Map<?, ?>) parse(null).trustedListSettings().get("tl_sync")).containsKey("accept_structure_errors"));
        EngineConfig strict = parse("\"tl_sync\":{\"accept_structure_errors\":false}");
        assertFalse(strict.tlAcceptStructureErrors);
        assertEquals(Boolean.FALSE,
                ((java.util.Map<?, ?>) strict.trustedListSettings().get("tl_sync")).get("accept_structure_errors"));
    }
}
