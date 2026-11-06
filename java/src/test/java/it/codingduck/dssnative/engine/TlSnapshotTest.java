/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Stream;
import java.util.zip.CRC32C;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import it.codingduck.dssnative.testsupport.Fixtures;
import it.codingduck.dssnative.testsupport.SyntheticTrustedLists;
import it.codingduck.dssnative.testsupport.TestEngines;
import it.codingduck.dssnative.testsupport.TestPki;

/** Trusted-list snapshots: export from one engine, start another from the file, and every way that can fail. */
class TlSnapshotTest {

    private static final List<String> FIXTURES = List.of("pades/b-b.pdf", "pades/b-t.pdf", "pades/b-lt.pdf",
            "pades/b-lta.pdf", "cades/attached-der.p7m", "cades/multi-signer.p7m", "cades/nested.p7m.p7m");
    /** A fixed validation time, so that two engines' reports can be compared byte for byte. */
    private static final String REPORTS = "{\"reports\":[\"detailed\",\"diagnostic\"],\"validation_time\":\""
            + Instant.now().minus(Duration.ofMinutes(1)).truncatedTo(ChronoUnit.SECONDS) + "\"}";

    @TempDir
    Path tmp;

    @Test
    void snapshotStartsAnEngineWithTheSameTrustWithoutCacheOrNetwork() throws IOException {
        TestEngines t = new TestEngines(tmp);
        // Only revocation data embedded in the signatures: the test CRL endpoint issues a new CRL on every
        // request, which would make two validations' reports differ whatever the trust.
        String embeddedRevocation = "\"revocation\":\"offline\",\"aia\":false";
        try (DssEngine source = t.onlineLoaded(tmp.resolve("cache"), embeddedRevocation)) {
            TrustedListManager.Exported exported = source.exportTlSnapshot();
            Map<String, Object> info = exported.info();
            assertEquals(TlSnapshotFile.FORMAT, info.get("format"));
            assertEquals(BuildInfo.dss(), info.get("dss"));
            assertEquals(3, info.get("trusted_certificates"));
            assertEquals(exported.bytes().length, info.get("size"));
            assertEquals("online", map(info, "lists_loaded").get("mode"));
            assertEquals(SyntheticTrustedLists.LOTL_URL, map(info, "settings").get("lotl_url"));
            assertNotNull(map(info, "settings").get("oj_keystore_sha256"));
            Path file = write("lists.tlsnap", exported.bytes());

            t.http.offline(true);
            int hits = t.http.totalHits();
            Path emptyCache = tmp.resolve("empty-cache");
            try (DssEngine loaded = t.engine(emptyCache, embeddedRevocation + "," + snapshot(file))) {
                assertEquals(hits, t.http.totalHits(), "starting from a snapshot must not touch the network");
                try (Stream<Path> files = Files.list(emptyCache.resolve("tl"))) {
                    assertEquals(0, files.count(), "nor read or write the cache");
                }
                assertEquals("snapshot", loaded.initialLoad().mode());
                assertTrue(loaded.initialLoad().completed());
                assertEquals(3, loaded.initialLoad().trustedCertificates());
                t.http.offline(false);

                Map<String, Object> before = source.trustedListStatus();
                Map<String, Object> after = loaded.trustedListStatus();
                for (String key : List.of("loaded", "trusted_certificates", "lotls", "tls", "alerts")) {
                    assertEquals(before.get(key), after.get(key), key);
                }
                assertNull(before.get("tl_snapshot"));
                Map<String, Object> described = map(after, "tl_snapshot");
                assertEquals(file.toString(), described.get("path"));
                assertEquals(info.get("created_at"), described.get("created_at"));
                assertEquals("snapshot", map(after, "last_offline_refresh").get("mode"));

                for (String fixture : FIXTURES) {
                    assertEquals(Json.write(source.validate(Fixtures.read(fixture), ValidationOptions.fromJson(REPORTS)).toMap()),
                            Json.write(loaded.validate(Fixtures.read(fixture), ValidationOptions.fromJson(REPORTS)).toMap()),
                            fixture);
                }

                // Exporting again keeps the load that validated the lists, not the snapshot's own load.
                Map<String, Object> again = loaded.exportTlSnapshot().info();
                assertEquals(Json.write(info.get("lists_loaded")), Json.write(again.get("lists_loaded")));
                assertEquals(Json.write(info.get("settings")), Json.write(again.get("settings")));
            }
        }
    }

    @Test
    void onlineRefreshAfterASnapshotReplacesItsLists() {
        TestEngines t = new TestEngines(tmp);
        Path file = exportFrom(t, null);
        try (DssEngine engine = t.engine(tmp.resolve("empty"), snapshot(file))) {
            assertNotNull(engine.trustedListStatus().get("tl_snapshot"));
            assertTrue(engine.refreshTrustedListsOnline().completed());
            Map<String, Object> status = engine.trustedListStatus();
            assertNull(status.get("tl_snapshot"));
            assertEquals(3, status.get("trusted_certificates"));
            assertEquals("online", map(engine.exportTlSnapshot().info(), "lists_loaded").get("mode"));
        }
    }

    @Test
    void exportNeedsLoadedLists() {
        TestEngines t = new TestEngines(tmp);
        try (DssEngine engine = t.engine(tmp.resolve("empty"), null)) {
            DssError e = assertThrows(DssError.class, engine::exportTlSnapshot);
            assertEquals(DssError.Code.TRUSTED_LISTS_NOT_LOADED, e.code());
        }
    }

    @Test
    void unreadableOrDamagedFilesAreRejected() throws IOException {
        TestEngines t = new TestEngines(tmp);
        byte[] good = Files.readAllBytes(exportFrom(t, null));

        assertRejected(t, tmp.resolve("missing.tlsnap"), "cannot read");
        assertRejected(t, write("empty", new byte[0]), "not a trusted-list snapshot");
        assertRejected(t, write("other", "%PDF-1.7 not a snapshot at all".getBytes(StandardCharsets.US_ASCII)),
                "not a trusted-list snapshot");
        assertRejected(t, write("truncated", Arrays.copyOf(good, good.length / 2)), "checksum");
        byte[] flipped = good.clone();
        flipped[flipped.length / 2] ^= 0x01;
        assertRejected(t, write("flipped", flipped), "checksum");
        assertRejected(t, write("format2", rebuilt(good, 2, h -> { })), "format 2");
        assertRejected(t, write("badjson", assemble(TlSnapshotFile.FORMAT,
                "{not json".getBytes(StandardCharsets.UTF_8), payload(good))), "not valid JSON");
        assertRejected(t, write("nopayload", assemble(TlSnapshotFile.FORMAT, header(good), new byte[] {1, 2, 3})),
                "cannot read the snapshot");
    }

    @Test
    void otherDssVersionOrTrustedListSettingsAreRejected() throws Exception {
        TestEngines t = new TestEngines(tmp);
        byte[] good = Files.readAllBytes(exportFrom(t, null));

        assertRejected(t, write("dss", rebuilt(good, TlSnapshotFile.FORMAT, h -> h.put("dss", "5.0"))),
                "written with DSS 5.0");
        assertRejected(t, write("countries", good), TestEngines.countries(List.of("IT")), "countries");
        assertRejected(t, write("sync", good), "\"tl_sync\":{\"accept_expired\":false}", "tl_sync");
        assertRejected(t, write("pivots", good), "\"pivot_support\":false", "pivot_support");

        // The same lists under another OJ keystore: the snapshot was built against other LOTL signers.
        Path otherKeystore = tmp.resolve("other-oj.p12");
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setCertificateEntry("someone-else", t.pki.x509(TestPki.Entity.OTHER_CA));
        try (OutputStream out = Files.newOutputStream(otherKeystore)) {
            ks.store(out, SyntheticTrustedLists.OJ_KEYSTORE_PASSWORD);
        }
        String config = t.configJson(snapshot(write("oj", good)))
                .replace(t.ojKeystore.toString(), otherKeystore.toString());
        DssError e = assertThrows(DssError.class,
                () -> new DssEngine(tmp.resolve("c"), EngineConfig.fromJson(config), t.http, t.http).close());
        assertEquals(DssError.Code.TL_SNAPSHOT_REJECTED, e.code());
        assertTrue(e.getMessage().contains("oj_keystore_sha256"), e.getMessage());

        // Country order does not matter.
        Path itDe = exportFrom(t, TestEngines.countries(List.of("IT", "DE")));
        try (DssEngine engine = t.engine(tmp.resolve("de-it"),
                TestEngines.countries(List.of("DE", "IT")) + "," + snapshot(itDe))) {
            assertEquals(3, engine.trustedListStatus().get("trusted_certificates"));
        }
    }

    @Test
    void unexpectedClassesAreRefusedBeforeTheyAreInstantiated() throws IOException {
        TestEngines t = new TestEngines(tmp);
        byte[] good = Files.readAllBytes(exportFrom(t, null));
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(stream)) {
            Map<String, Object> map = new HashMap<>();
            map.put("x", new Canary());
            out.writeObject(map);
        }
        Canary.deserialized = false;
        assertRejected(t, write("canary", assemble(TlSnapshotFile.FORMAT, header(good), stream.toByteArray())),
                Canary.class.getName());
        assertFalse(Canary.deserialized);
    }

    @Test
    void listsThatExpiredSinceTheExportAreRejectedWhenExpiredListsAreRefused() throws Exception {
        TestEngines t = new TestEngines(tmp);
        Instant built = Instant.now();
        new SyntheticTrustedLists(t.pki, 2).withNextUpdateIn(Duration.ofSeconds(5)).serveOn(t.http);
        String refuseExpired = "\"tl_sync\":{\"accept_expired\":false}";
        Path strict = exportFrom(t, refuseExpired);
        Path lenient = exportFrom(t, null);

        Thread.sleep(Math.max(0, Duration.between(Instant.now(), built.plusSeconds(6)).toMillis()));

        DssError e = assertThrows(DssError.class, () -> t.engine(tmp.resolve("strict"),
                refuseExpired + "," + snapshot(strict)).close());
        assertEquals(DssError.Code.TL_SNAPSHOT_REJECTED, e.code());
        assertTrue(e.getMessage().contains("no longer allows"), e.getMessage());

        // accept_expired (the default): an expired list stays usable, as it would from the cache.
        try (DssEngine engine = t.engine(tmp.resolve("lenient"), snapshot(lenient))) {
            Map<String, Object> status = engine.trustedListStatus();
            assertEquals(3, status.get("trusted_certificates"));
            for (Map<String, Object> tl : TrustedListTest.list(status, "tls")) {
                assertEquals(Boolean.TRUE, tl.get("expired"), tl.get("url").toString());
                assertEquals(Boolean.TRUE, tl.get("used_for_trust"), tl.get("url").toString());
            }
        }
    }

    // ------------------------------------------------------------------ helpers

    /** Writes the snapshot of an engine loaded online with {@code extraConfig}, and returns its path. */
    private Path exportFrom(TestEngines t, String extraConfig) {
        Path cache = tmp.resolve("source-" + System.nanoTime());
        try (DssEngine engine = t.onlineLoaded(cache, extraConfig)) {
            return write("export-" + System.nanoTime() + ".tlsnap", engine.exportTlSnapshot().bytes());
        }
    }

    private static String snapshot(Path file) {
        return "\"tl_snapshot\":\"" + file.toString().replace("\\", "\\\\") + "\"";
    }

    private Path write(String name, byte[] bytes) {
        try {
            return Files.write(tmp.resolve(name), bytes);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private void assertRejected(TestEngines t, Path file, String messagePart) {
        assertRejected(t, file, null, messagePart);
    }

    private void assertRejected(TestEngines t, Path file, String extraConfig, String messagePart) {
        String config = (extraConfig == null ? "" : extraConfig + ",") + snapshot(file);
        DssError e = assertThrows(DssError.class,
                () -> t.engine(tmp.resolve("rejected-" + System.nanoTime()), config).close(), file.toString());
        assertEquals(DssError.Code.TL_SNAPSHOT_REJECTED, e.code(), e.getMessage());
        assertTrue(e.getMessage().contains(messagePart), file + ": " + e.getMessage());
    }

    /** The header bytes of a snapshot file. */
    private static byte[] header(byte[] file) {
        int length = ByteBuffer.wrap(file).getInt(12);
        return Arrays.copyOfRange(file, 16, 16 + length);
    }

    private static byte[] payload(byte[] file) {
        int length = ByteBuffer.wrap(file).getInt(12);
        return Arrays.copyOfRange(file, 16 + length, file.length - 4);
    }

    /** The same payload under a changed header and format version, with a CRC that matches again. */
    private static byte[] rebuilt(byte[] file, int format, Consumer<Map<String, Object>> change) {
        Map<String, Object> header = Json.parseObject(new String(header(file), StandardCharsets.UTF_8));
        change.accept(header);
        return assemble(format, Json.write(header).getBytes(StandardCharsets.UTF_8), payload(file));
    }

    private static byte[] assemble(int format, byte[] header, byte[] payload) {
        ByteBuffer out = ByteBuffer.allocate(16 + header.length + payload.length + 4);
        out.put("DSSTLSNP".getBytes(StandardCharsets.US_ASCII)).putInt(format).putInt(header.length)
                .put(header).put(payload);
        CRC32C crc = new CRC32C();
        crc.update(out.array(), 0, out.position());
        out.putInt((int) crc.getValue());
        return out.array();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Map<String, Object> m, String key) {
        return (Map<String, Object>) m.get(key);
    }

    /** Records whether it was ever deserialized. */
    static final class Canary implements Serializable {
        private static final long serialVersionUID = 1L;
        static volatile boolean deserialized;

        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            deserialized = true;
            in.defaultReadObject();
        }
    }
}
