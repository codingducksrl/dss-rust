/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.testsupport;

import java.nio.file.Files;
import java.nio.file.Path;

import it.codingduck.dssnative.engine.DssEngine;

/**
 * Writes a trusted-list cache filled from the synthetic LOTL/TLs, plus the matching OJ keystore and
 * {@code config.json}, for testing the native library from outside the JVM (C smoke test, Rust tests).
 *
 * <pre>SyntheticCacheSeeder &lt;out_dir&gt;   →   out_dir/{cache/, oj-keystore.p12, config.json}</pre>
 *
 * The lists are valid for 180 days from generation. The config uses offline revocation (the CRL endpoint is
 * fictitious), so only LT/LTA fixtures validate as TOTAL_PASSED.
 */
public final class SyntheticCacheSeeder {

    private SyntheticCacheSeeder() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("usage: SyntheticCacheSeeder <out_dir>");
            System.exit(64);
        }
        Path out = Path.of(args[0]).toAbsolutePath();
        Files.createDirectories(out);
        TestEngines t = new TestEngines(out);
        try (DssEngine engine = t.onlineLoaded(out.resolve("cache"), null)) {
            if (!Boolean.TRUE.equals(engine.trustedListStatus().get("loaded"))) {
                throw new IllegalStateException("synthetic trusted lists did not load");
            }
        }
        Files.writeString(out.resolve("config.json"), t.configJson("\"revocation\":\"offline\",\"aia\":false"));
        System.out.println("Synthetic TL cache in " + out);
    }
}
