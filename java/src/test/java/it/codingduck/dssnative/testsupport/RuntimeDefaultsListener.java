/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.testsupport;

import org.junit.platform.launcher.LauncherSession;
import org.junit.platform.launcher.LauncherSessionListener;

import it.codingduck.dssnative.engine.RuntimeDefaults;

/**
 * Applies {@link RuntimeDefaults} before any test runs, as the native library's entry points do when its isolate
 * starts. Registered in META-INF/services; runs on the JVM and in the native test image alike.
 */
public final class RuntimeDefaultsListener implements LauncherSessionListener {

    @Override
    public void launcherSessionOpened(LauncherSession session) {
        RuntimeDefaults.apply();
    }
}
