/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.visible;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

/** {@link FontCheck}: real fonts pass, fonts that would make FontBox allocate or fail are refused with a reason. */
class FontCheckTest {

    @Test
    void realFontsPass() throws IOException {
        assertDoesNotThrow(() -> FontCheck.check(CraftedFonts.plain()));
        try (InputStream in = AwtFreeSignatureDrawer.defaultFont()) {
            byte[] ptSerif = in.readAllBytes();
            assertDoesNotThrow(() -> FontCheck.check(ptSerif));
        }
        // duplicate records within the limit are a real-world pattern (the same subtable for several platforms)
        assertDoesNotThrow(() -> FontCheck.check(CraftedFonts.duplicateCmapRecords(FontCheck.MAX_CMAP_RECORDS)));
        // what FontBox tolerates is accepted: a short left-side-bearing array (read as zeros), a cmap without
        // a space (the drawer refuses a text the font cannot show, not the font)
        assertDoesNotThrow(() -> FontCheck.check(CraftedFonts.shortLeftSideBearings()));
        assertDoesNotThrow(() -> FontCheck.check(CraftedFonts.noSpaceGlyph()));
    }

    @Test
    void outlinesThatWouldMakeTheSubsetterAllocateAreRefused() {
        refused(CraftedFonts.oversizedLoca(), "ends at byte 2147483632 of a 269356-byte 'glyf' table");
        refused(CraftedFonts.reversedLoca(), "has a negative length in 'loca'");
    }

    @Test
    void characterMapsThatWouldMakeFontBoxAllocateAreRefused() {
        refused(CraftedFonts.cmapFormat13(), "format 13");
        refused(CraftedFonts.cmapFormat12Everything(), "map more than " + FontCheck.MAX_CMAP_ENTRIES);
        refused(CraftedFonts.duplicateCmapRecords(FontCheck.MAX_CMAP_RECORDS + 1),
                (FontCheck.MAX_CMAP_RECORDS + 1) + " encoding records");
    }

    @Test
    void fontsTheDrawerCouldNotEmbedAreRefusedUpFront() {
        refused(CraftedFonts.noSubsetting(), "does not permit subsetting");
        refused(CraftedFonts.noHorizontalMetrics(), "declares 0 horizontal metrics");
        refused(CraftedFonts.truncatedHorizontalMetrics(), "shorter than its 2620 horizontal metrics need");
    }

    @Test
    void sizeAndKindAreBounded() {
        refused(new byte[FontCheck.MAX_FONT_BYTES + 1], "at most 32 MB");
        refused("ttcf\0\0\0\0\0\0\0\0".getBytes(), "TrueType collections");
        refused("OTTO\0\0\0\0\0\0\0\0".getBytes(), "PostScript (CFF) outlines");
        refused(new byte[] {1, 2, 3}, "too short");
        byte[] truncated = Arrays.copyOf(CraftedFonts.plain(), 1000);
        refused(truncated, "outside the file");
    }

    private static void refused(byte[] font, String reason) {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> FontCheck.check(font));
        assertTrue(e.getMessage().contains(reason), e.getMessage());
    }
}
