/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.visible;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;

/**
 * DSS's image parameters carrying our {@link Appearance} instead of DSS's own image and text settings, which
 * {@link AwtFreeSignatureDrawer} draws. DSS still reads the field parameters (the field to fill, the page) and
 * runs its field checks.
 *
 * <p>{@link #toString()} is a digest of the appearance: DSS seeds the encryption of an encrypted PDF with it
 * ({@code PdfBoxSignatureService.buildSeed}), and DSS's own {@code toString} includes identity hash codes, so a
 * visible signature on an encrypted PDF would come out differently in prepare and complete.
 */
public final class VisibleImageParameters extends SignatureImageParameters {
    private static final long serialVersionUID = 1L;

    private final transient Appearance appearance;
    private final transient Placement placement;
    private final String fingerprint;

    private VisibleImageParameters(Appearance appearance, Placement placement) {
        this.appearance = appearance;
        this.placement = placement;
        SignatureFieldParameters field = new SignatureFieldParameters();
        field.setFieldId(placement.field());
        field.setPage(placement.page());
        setFieldParameters(field);
        this.fingerprint = fingerprint(appearance, placement);
    }

    /**
     * Resolves where {@code appearance} goes in {@code pdf}.
     *
     * @throws it.codingduck.dssnative.engine.DssError {@code INVALID_ARGUMENT} for a page or field that does not
     *         fit the document
     */
    public static VisibleImageParameters of(byte[] pdf, Appearance appearance) {
        return new VisibleImageParameters(appearance, Placement.resolve(pdf, appearance));
    }

    Appearance appearance() {
        return appearance;
    }

    Placement placement() {
        return placement;
    }

    @Override
    public boolean isEmpty() {
        return false;
    }

    @Override
    public String toString() {
        return "VisibleImageParameters[" + fingerprint + "]";
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof VisibleImageParameters other && fingerprint.equals(other.fingerprint);
    }

    @Override
    public int hashCode() {
        return fingerprint.hashCode();
    }

    private static String fingerprint(Appearance a, Placement p) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        update(md, p.toString());
        update(md, a.field());
        update(md, a.text());
        md.update(ByteBuffer.allocate(4 * 7 + 1).putInt(a.page()).putFloat(a.fontSize()).putInt(a.textColor())
                .putInt(a.backgroundColor() != null ? a.backgroundColor() : -1)
                .putInt(a.textAlign().ordinal()).putInt(a.imagePosition().ordinal())
                .putInt(a.font() != null ? a.font().length : -1).put((byte) 0).array());
        if (a.font() != null) {
            md.update(a.font());
        }
        if (a.image() != null) {
            md.update(a.image().data());
        }
        return HexFormat.of().formatHex(md.digest());
    }

    private static void update(MessageDigest md, String s) {
        if (s == null) {
            md.update((byte) 0);
        } else {
            md.update((byte) 1);
            md.update(s.getBytes(StandardCharsets.UTF_8));
            md.update((byte) 0);
        }
    }
}
