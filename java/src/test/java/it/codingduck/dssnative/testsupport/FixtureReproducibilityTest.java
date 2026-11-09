/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.testsupport;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledInNativeImage;
import org.junit.jupiter.api.io.TempDir;

import it.codingduck.dssnative.engine.DssEngine;
import it.codingduck.dssnative.engine.ValidationOptions;
import it.codingduck.dssnative.engine.ValidationResult;
import it.codingduck.dssnative.testsupport.TestPki.Entity;

/**
 * Regenerating the fixtures is reproducible: the same PKI and fixture time give the same bytes, file for file, in
 * two separate JVMs started with {@link FixtureGenerator#JVM_OPTIONS}, so a regeneration can be reviewed as a byte
 * diff. Generating the PKI is reproducible too (keys and certificates).
 * Not in the native test image: the generator encrypts a PDF with PDFBox's protection policy, writes a PKCS#12
 * and signs with DSS's own services, none of which the native test image is configured for.
 */
@DisabledInNativeImage
class FixtureReproducibilityTest {

    @TempDir
    Path tmp;

    @Test
    void regeneratingTheFixturesGivesTheSameBytes() throws Exception {
        // In two JVMs, as scripts/generate-fixtures.sh would run it twice: what stays the same within one JVM
        // (caches, identity hash codes) cannot hide a difference. The second JVM does other work first, as the
        // Maven JVM running the script does, so that its identity hash codes would differ without JVM_OPTIONS.
        Path a = tmp.resolve("a");
        Path b = tmp.resolve("b");
        generateInAnotherJvm(a, FixtureGenerator.class);
        generateInAnotherJvm(b, AfterOtherWork.class);

        Map<String, byte[]> first = files(a);
        Map<String, byte[]> second = files(b);
        assertEquals(first.keySet(), second.keySet());
        assertTrue(first.keySet().containsAll(List.of("pades/b-lta.pdf", "cades/nested.p7m.p7m",
                "content/protected.pdf", "signing/cades-cms.sig", "signing/pades-visible-cms.sig")), first.keySet()
                .toString());
        for (String name : first.keySet()) {
            assertArrayEquals(first.get(name), second.get(name), name + " differs between two regenerations");
        }
        // --signing-only, from the same content, writes the same signing/ as the full run.
        Path d = tmp.resolve("d");
        for (String name : first.keySet()) {
            if (name.startsWith("content/")) {
                Files.createDirectories(d.resolve(name).getParent());
                Files.write(d.resolve(name), first.get(name));
            }
        }
        generateInAnotherJvm(d, FixtureGenerator.class, "--signing-only");
        Map<String, byte[]> signingOnly = files(d);
        for (String name : first.keySet()) {
            if (name.startsWith("signing/")) {
                assertArrayEquals(first.get(name), signingOnly.get(name), name + " differs with --signing-only");
            }
        }

        // --out copies the committed PKI and JPEG rather than replacing them.
        assertArrayEquals(Files.readAllBytes(TestPki.defaultLocation()), first.get("pki/test-pki.p12"));
        assertArrayEquals(Fixtures.read("content/stamp.jpg"), first.get("content/stamp.jpg"));
        assertTrue(new String(first.get("signing/pades-cms.json"), StandardCharsets.UTF_8)
                .contains("\"signing_time\":\"" + FixtureGenerator.DEFAULT_TIME + "\""));

        // The time is an input: another one gives other signatures.
        Path c = tmp.resolve("c");
        FixtureGenerator.prepareOutput(c, false);
        FixtureGenerator.generateAll(c, TestPki.load(), FixtureGenerator.DEFAULT_TIME.plusSeconds(3600));
        assertFalse(Arrays.equals(first.get("cades/attached-der.p7m"),
                Files.readAllBytes(c.resolve("cades/attached-der.p7m"))));

        // What the fixture clock produced is still what the fixture expectations describe.
        try (DssEngine engine = new TestEngines(tmp).onlineLoaded(tmp.resolve("cache"),
                "\"revocation\":\"offline\"")) {
            for (String name : List.of("pades/b-lt.pdf", "pades/b-lta.pdf")) {
                ValidationResult r = engine.validate(first.get(name), ValidationOptions.DEFAULT);
                assertEquals(1, r.signatures.size(), name);
                ValidationResult.SignatureSummary s = r.signatures.get(0);
                assertEquals("TOTAL_PASSED", s.indication().name(), name + ": " + s.errors());
            }
        }
    }

    @Test
    void generatingThePkiGivesTheSameKeysAndCertificates() throws Exception {
        TestPki first = TestPki.generate(tmp.resolve("one/test-pki.p12"));
        TestPki second = TestPki.generate(tmp.resolve("two/test-pki.p12"));
        for (Entity e : Entity.values()) {
            assertArrayEquals(first.x509(e).getEncoded(), second.x509(e).getEncoded(), e.alias);
            assertArrayEquals(first.key(e).getEncoded(), second.key(e).getEncoded(), e.alias);
        }
        assertEquals(TestPki.PKI_NOT_BEFORE, first.x509(Entity.ROOT_CA).getNotBefore().toInstant());
    }

    /** {@code FixtureGenerator --out=<out>} in a new JVM with {@link FixtureGenerator#JVM_OPTIONS}. */
    private void generateInAnotherJvm(Path out, Class<?> main, String... extraArgs) throws Exception {
        List<String> command = new ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
        command.addAll(FixtureGenerator.JVM_OPTIONS);
        command.addAll(List.of("-Ddssnative.repoRoot=" + Fixtures.repoRoot(), "-cp",
                System.getProperty("java.class.path"), main.getName(), "--out=" + out,
                "--time=" + FixtureGenerator.DEFAULT_TIME));
        command.addAll(List.of(extraArgs));
        Path log = tmp.resolve(out.getFileName() + ".log");
        Process p = new ProcessBuilder(command).redirectErrorStream(true).redirectOutput(log.toFile()).start();
        if (!p.waitFor(5, TimeUnit.MINUTES)) {
            p.destroyForcibly();
            throw new AssertionError("the generator did not finish within 5 minutes");
        }
        String output = Files.readString(log);
        assertEquals(0, p.exitValue(), output);
        assertFalse(output.contains("warning: not reproducible"), output);
    }

    private static Map<String, byte[]> files(Path root) throws IOException {
        Map<String, byte[]> out = new TreeMap<>();
        try (Stream<Path> walk = Files.walk(root)) {
            walk.filter(Files::isRegularFile).forEach(p -> {
                try {
                    out.put(root.relativize(p).toString().replace('\\', '/'), Files.readAllBytes(p));
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            });
        }
        return out;
    }

    /** The generator, after asking the JVM for some identity hash codes (which shifts every later one). */
    public static final class AfterOtherWork {
        private AfterOtherWork() {
        }

        public static void main(String[] args) throws Exception {
            int sum = 0;
            for (int i = 0; i < 1000; i++) {
                sum += System.identityHashCode(new Object());
            }
            System.out.println("identity hash codes drawn: " + sum);
            FixtureGenerator.main(args);
        }
    }
}
