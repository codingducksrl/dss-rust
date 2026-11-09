/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.visible;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

import org.apache.fontbox.ttf.CmapLookup;
import org.apache.fontbox.ttf.TTFParser;
import org.apache.fontbox.ttf.TrueTypeFont;
import org.apache.pdfbox.io.RandomAccessReadBuffer;

import it.codingduck.dssnative.testsupport.TestImages;

/**
 * Liberation Sans with one table bent the way a hostile or damaged font would be: a {@code loca} that claims a
 * gigabyte-sized glyph or a negative one, a licence that forbids subsetting, no horizontal metrics, and
 * {@code cmap} tables that make FontBox build millions of entries. FontBox does not verify table checksums,
 * so the directory entries are rewritten without them.
 */
public final class CraftedFonts {

    private CraftedFonts() {
    }

    /** The unmodified font, which every check accepts. */
    public static byte[] plain() {
        return TestImages.liberationSans();
    }

    /** The last {@code loca} entry says the last glyph ends about 2 GB into the 263 KB {@code glyf} table. */
    public static byte[] oversizedLoca() {
        byte[] f = plain();
        int loca = offset(f, "loca");
        int numGlyphs = u16(f, offset(f, "maxp") + 4);
        putInt(f, loca + numGlyphs * 4, 0x7ffffff0);
        return f;
    }

    /** A glyph whose {@code loca} end lies before its start: a negative length. */
    public static byte[] reversedLoca() {
        byte[] f = plain();
        int loca = offset(f, "loca");
        int numGlyphs = u16(f, offset(f, "maxp") + 4);
        for (int gid = 1; gid < numGlyphs; gid++) {
            long start = u32(f, loca + gid * 4);
            long end = u32(f, loca + (gid + 1) * 4);
            if (end > start && start >= 1) {
                putInt(f, loca + (gid + 1) * 4, (int) (start - 1));
                return f;
            }
        }
        throw new IllegalStateException("no glyph with outlines");
    }

    /** {@code OS/2.fsType} with bit 8 set: embedding allowed, subsetting not. */
    public static byte[] noSubsetting() {
        byte[] f = plain();
        int os2 = offset(f, "OS/2");
        int fsType = u16(f, os2 + 8) | 0x0100;
        f[os2 + 8] = (byte) (fsType >> 8);
        f[os2 + 9] = (byte) fsType;
        return f;
    }

    /** {@code hmtx} cut short of the horizontal metrics {@code hhea} announces: FontBox reads past its end. */
    public static byte[] truncatedHorizontalMetrics() {
        byte[] f = plain();
        int numberOfHMetrics = u16(f, offset(f, "hhea") + 34);
        putInt(f, entry(f, "hmtx") + 12, 4 * numberOfHMetrics - 2);
        return f;
    }

    /** {@code hhea.numberOfHMetrics} zero, so FontBox reads past the end of {@code hmtx}. */
    public static byte[] noHorizontalMetrics() {
        byte[] f = plain();
        int hhea = offset(f, "hhea");
        f[hhea + 34] = 0;
        f[hhea + 35] = 0;
        return f;
    }

    /**
     * {@code hhea.numberOfHMetrics} cut to 128 and {@code hmtx} to those 128 metrics: the other glyphs share
     * the last advance and have no left side bearing at all, which FontBox takes as zero.
     */
    public static byte[] shortLeftSideBearings() {
        byte[] f = plain();
        int hhea = offset(f, "hhea");
        f[hhea + 34] = 0;
        f[hhea + 35] = (byte) 128;
        putInt(f, entry(f, "hmtx") + 12, 4 * 128);
        return f;
    }

    /**
     * A {@code cmap} of one format-12 subtable that maps U+0021..U+007E to the glyphs the font maps them to,
     * and nothing else: no glyph for the space, as in a symbol or icon font.
     */
    public static byte[] noSpaceGlyph() {
        byte[] f = plain();
        int first = 0x21;
        int last = 0x7e;
        int[] gids = new int[last - first + 1];
        try (TrueTypeFont ttf = new TTFParser().parse(new RandomAccessReadBuffer(f))) {
            CmapLookup cmap = ttf.getUnicodeCmapLookup();
            for (int cp = first; cp <= last; cp++) {
                gids[cp - first] = cmap.getGlyphId(cp);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(new byte[] {0, 0, 0, 1}); // version, one record
        out.writeBytes(new byte[] {0, 3, 0, 10}); // Windows, full Unicode
        out.writeBytes(int4(12)); // the subtable follows the record
        out.writeBytes(new byte[] {0, 12, 0, 0}); // format 12, reserved
        out.writeBytes(int4(16 + 12 * gids.length)); // length
        out.writeBytes(int4(0)); // language
        out.writeBytes(int4(gids.length)); // nGroups: one code point each
        for (int cp = first; cp <= last; cp++) {
            out.writeBytes(int4(cp));
            out.writeBytes(int4(cp));
            out.writeBytes(int4(gids[cp - first]));
        }
        return replaceTable(f, "cmap", out.toByteArray());
    }

    /** The font's {@code cmap} with its first encoding record repeated {@code n} times. */
    public static byte[] duplicateCmapRecords(int n) {
        byte[] f = plain();
        int cmap = offset(f, "cmap");
        int cmapLength = length(f, "cmap");
        int records = u16(f, cmap + 2);
        int bodyStart = 4 + 8 * records;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0);
        out.write(0);
        out.write(n >> 8);
        out.write(n);
        long shift = 8L * (n - records);
        for (int i = 0; i < n; i++) {
            out.write(f, cmap + 4, 4); // platform and encoding of record 0
            long offset = u32(f, cmap + 8) + shift;
            out.writeBytes(int4((int) offset));
        }
        out.write(f, cmap + bodyStart, cmapLength - bodyStart);
        return replaceTable(f, "cmap", out.toByteArray());
    }

    /** One format-13 subtable mapping every Unicode code point to glyph 0, as a "last resort" font does. */
    public static byte[] cmapFormat13() {
        return replaceTable(plain(), "cmap", cmapWithGroup(13, 0x10ffff));
    }

    /** One format-12 subtable whose single group covers all of Unicode: 1.1 million entries. */
    public static byte[] cmapFormat12Everything() {
        return replaceTable(plain(), "cmap", cmapWithGroup(12, 0x10ffff));
    }

    /** A {@code cmap} with one (3,10) record pointing at a format-12 or -13 subtable of one group 0..{@code last}. */
    private static byte[] cmapWithGroup(int format, int last) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(new byte[] {0, 0, 0, 1}); // version, one record
        out.writeBytes(new byte[] {0, 3, 0, 10}); // Windows, full Unicode
        out.writeBytes(int4(12)); // the subtable follows the record
        out.writeBytes(new byte[] {(byte) 0, (byte) format, 0, 0}); // format, reserved
        out.writeBytes(int4(16 + 12)); // length
        out.writeBytes(int4(0)); // language
        out.writeBytes(int4(1)); // nGroups
        out.writeBytes(int4(0));
        out.writeBytes(int4(last));
        out.writeBytes(int4(0)); // start glyph
        return out.toByteArray();
    }

    /** The font with the table {@code tag} replaced by {@code data}, appended at the end. */
    private static byte[] replaceTable(byte[] f, String tag, byte[] data) {
        int entry = entry(f, tag);
        int padded = (f.length + 3) & ~3;
        byte[] out = new byte[padded + data.length];
        System.arraycopy(f, 0, out, 0, f.length);
        System.arraycopy(data, 0, out, padded, data.length);
        putInt(out, entry + 8, padded);
        putInt(out, entry + 12, data.length);
        return out;
    }

    private static int entry(byte[] f, String tag) {
        int n = u16(f, 4);
        for (int i = 0; i < n; i++) {
            int at = 12 + 16 * i;
            if (new String(f, at, 4, StandardCharsets.ISO_8859_1).equals(tag)) {
                return at;
            }
        }
        throw new IllegalStateException("no table " + tag);
    }

    private static int offset(byte[] f, String tag) {
        return (int) u32(f, entry(f, tag) + 8);
    }

    private static int length(byte[] f, String tag) {
        return (int) u32(f, entry(f, tag) + 12);
    }

    private static int u16(byte[] b, int i) {
        return ((b[i] & 0xff) << 8) | (b[i + 1] & 0xff);
    }

    private static long u32(byte[] b, int i) {
        return ((long) u16(b, i) << 16) | u16(b, i + 2);
    }

    private static byte[] int4(int v) {
        byte[] b = new byte[4];
        putInt(b, 0, v);
        return b;
    }

    private static void putInt(byte[] b, int i, int v) {
        b[i] = (byte) (v >>> 24);
        b[i + 1] = (byte) (v >>> 16);
        b[i + 2] = (byte) (v >>> 8);
        b[i + 3] = (byte) v;
    }
}
