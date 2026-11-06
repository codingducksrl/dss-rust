/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import java.util.Locale;

/**
 * Process-wide settings the native library pins when its isolate starts, so behaviour does not depend on the
 * host process's environment.
 *
 * <p>Locale: JDK date/number formatting used inside DSS and JAXB loads CLDR locale data reflectively for the
 * default locale. The native image only carries {@code en-US} (see {@code -H:DefaultLocale} in
 * native-image.properties), so a host running with, say, {@code LANG=it_IT} would otherwise hit a
 * {@code MissingReflectionRegistrationError}. Including every locale instead costs about 50 MB.
 * Reports are English anyway ({@code Locale.ENGLISH} is set on each validator).
 *
 * <p>Headless AWT: PDFBox's {@code PDDocument} static initializer touches {@code java.awt.image}, which tries to
 * load {@code libawt}. The library ships without it (PDFBox catches the {@code UnsatisfiedLinkError}). Should a
 * libawt be found anyway on the library search path, headless keeps it from loading X11 because the host has a
 * {@code DISPLAY}.
 *
 * <p>Call it from the native entry points only: on a JVM it would change the default locale of the host
 * application. The native isolate's heap, and so its default locale, is private to the library.
 */
public final class RuntimeDefaults {

    private RuntimeDefaults() {
    }

    public static void apply() {
        Locale.setDefault(Locale.US);
        System.setProperty("java.awt.headless", "true");
    }
}
