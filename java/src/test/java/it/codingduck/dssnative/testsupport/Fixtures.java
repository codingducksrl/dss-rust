/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.testsupport;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Locates the repository's {@code testdata/} folder. */
public final class Fixtures {

    private Fixtures() {
    }

    public static Path repoRoot() {
        String prop = System.getProperty("dssnative.repoRoot");
        Path root = prop != null ? Path.of(prop) : Path.of("..");
        return root.toAbsolutePath().normalize();
    }

    public static Path dir() {
        return repoRoot().resolve("testdata/fixtures");
    }

    public static Path privateDir() {
        return repoRoot().resolve("testdata/private");
    }

    public static Path path(String relative) {
        return dir().resolve(relative);
    }

    public static byte[] read(String relative) {
        try {
            return Files.readAllBytes(path(relative));
        } catch (IOException e) {
            throw new UncheckedIOException("missing fixture " + relative + " (run scripts/generate-fixtures.sh)", e);
        }
    }
}
