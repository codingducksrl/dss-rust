/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.visible;

/**
 * What a visible signature shows, and where, as the caller asked for it (placeholders already filled in).
 *
 * @param field           an empty signature field of the PDF to sign, or null for a new field at
 *                        {@code page}/{@code x}/{@code y}/{@code width}/{@code height}
 * @param page            1-based; ignored with {@code field}
 * @param x               points from the left edge of the page as displayed (its {@code /Rotate} applied)
 * @param y               points from the top edge of the page as displayed
 * @param text            null for an image alone; lines separated by {@code \n}
 * @param font            a TrueType font, or null for the default (DSS's PT Serif)
 * @param fontSize        the largest size: the text shrinks and wraps to fit
 * @param textColor       0xRRGGBB
 * @param backgroundColor 0xRRGGBB, or null for none
 * @param image           null for text alone
 */
public record Appearance(String field, int page, float x, float y, float width, float height, String text,
                         byte[] font, float fontSize, int textColor, TextAlign textAlign, Integer backgroundColor,
                         SignatureImage image, ImagePosition imagePosition) {

    public enum TextAlign { LEFT, CENTER, RIGHT }

    /** Where the image goes relative to the text; {@code BEHIND} puts the text over it. */
    public enum ImagePosition { LEFT, RIGHT, TOP, BOTTOM, BEHIND }
}
