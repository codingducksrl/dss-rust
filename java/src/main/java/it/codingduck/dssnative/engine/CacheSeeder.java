/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * Builds a trusted-list cache snapshot to ship with the application: an online refresh into {@code cache_dir}.
 * Used by {@code scripts/seed-tl-cache.sh} (on the JVM) until the native CLI exists.
 *
 * <pre>CacheSeeder &lt;cache_dir&gt; &lt;config.json&gt;</pre>
 *
 * Exit status: 0 when every list downloaded and validated, 1 when some list has a problem (the snapshot is still
 * written), 2 when nothing could be loaded.
 */
public final class CacheSeeder {

    private CacheSeeder() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.err.println("usage: CacheSeeder <cache_dir> <config.json>");
            System.exit(64);
        }
        EngineConfig config = EngineConfig.fromJson(Files.readString(Path.of(args[1])));
        try (DssEngine engine = DssEngine.create(Path.of(args[0]), config)) {
            TrustedListManager.RefreshRecord rec = engine.refreshTrustedListsOnline();
            Map<String, Object> status = engine.trustedListStatus();
            System.out.println(Json.write(status));
            if (!rec.completed() || !Boolean.TRUE.equals(status.get("loaded"))) {
                System.err.println("No trusted list could be loaded");
                System.exit(2);
            }
            int problems = 0;
            for (String key : List.of("lotls", "tls")) {
                for (Object o : (List<?>) status.get(key)) {
                    Map<?, ?> tl = (Map<?, ?>) o;
                    Map<?, ?> validation = (Map<?, ?>) tl.get("validation");
                    boolean valid = "TOTAL_PASSED".equals(validation.get("indication"));
                    boolean downloaded = ((Map<?, ?>) tl.get("download")).get("error") == null;
                    if (!valid || !downloaded || Boolean.TRUE.equals(tl.get("expired"))) {
                        problems++;
                        System.err.println("Problem with " + tl.get("url") + ": " + Json.write(tl));
                    }
                }
            }
            System.err.println("Seeded " + status.get("trusted_certificates") + " trusted certificates into "
                    + args[0] + (problems > 0 ? " (" + problems + " lists with problems)" : ""));
            System.exit(problems > 0 ? 1 : 0);
        }
    }
}
