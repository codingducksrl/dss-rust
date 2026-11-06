/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.testsupport;

import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;

import it.codingduck.dssnative.engine.DssEngine;
import it.codingduck.dssnative.engine.EngineConfig;

/**
 * Wires a {@link DssEngine} to the synthetic LOTL/TLs, CRL and TSA served by a {@link FakeHttp}: the full
 * trusted-list path (offline cache, online refresh, LOTL signature against an "OJ" keystore) with no network.
 */
public final class TestEngines {

    public final TestPki pki = TestPki.load();
    public final FakeHttp http = new FakeHttp();
    public final Path ojKeystore;

    public TestEngines(Path workDir) {
        this.ojKeystore = SyntheticTrustedLists.writeOjKeystore(pki, workDir.resolve("oj-keystore.p12"));
        http.route(TestPki.CRL_URL, pki::freshCrl);
        http.postRoute(TestPki.TSA_URL, pki::timestampResponse);
        new SyntheticTrustedLists(pki, 1).serveOn(http);
    }

    /** {@code config_json} pointing at the synthetic LOTL; {@code extra} is spliced in as more JSON members. */
    public String configJson(String extra) {
        return "{\"lotl_url\":\"" + SyntheticTrustedLists.LOTL_URL + "\","
                + "\"oj_url\":\"" + SyntheticTrustedLists.OJ_URL + "\","
                + "\"oj_keystore\":{\"path\":\"" + json(ojKeystore.toString()) + "\",\"password\":\"dss-password\"}"
                + (extra == null || extra.isBlank() ? "" : "," + extra)
                + "}";
    }

    /** {@code config_json} members that point {@code extend} at the in-memory test TSA. */
    public static String tsa() {
        return "\"tsa\":{\"url\":\"" + TestPki.TSA_URL + "\"}";
    }

    public static String countries(List<String> codes) {
        return "\"countries\":[" + codes.stream().map(c -> "\"" + c + "\"").collect(Collectors.joining(",")) + "]";
    }

    public DssEngine engine(Path cacheDir, String extraConfig) {
        return new DssEngine(cacheDir, EngineConfig.fromJson(configJson(extraConfig)), http, http);
    }

    /** An engine whose trusted lists were just loaded online from the synthetic LOTL. */
    public DssEngine onlineLoaded(Path cacheDir, String extraConfig) {
        DssEngine engine = engine(cacheDir, extraConfig);
        engine.refreshTrustedListsOnline();
        return engine;
    }

    private static String json(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
