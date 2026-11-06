/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.Properties;

/** Library and DSS versions, from the Maven-filtered {@code version.properties}. */
final class BuildInfo {

    private static final Properties PROPERTIES = load();

    private BuildInfo() {
    }

    static String library() {
        return PROPERTIES.getProperty("library");
    }

    static String dss() {
        return PROPERTIES.getProperty("dss");
    }

    private static Properties load() {
        Properties p = new Properties();
        try (InputStream in = BuildInfo.class.getResourceAsStream("/it/codingduck/dssnative/version.properties")) {
            if (in != null) {
                p.load(in);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return p;
    }
}
