/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.visible;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Checks the table structure of a caller-supplied TrueType font before FontBox parses it. FontBox trusts the
 * table lengths and offsets a font declares: a {@code loca} entry claiming a 1.9 GB glyph makes the subsetter
 * allocate that much, a {@code cmap} with many records or a format-13 group spanning Unicode costs gigabytes
 * of hash-map entries, and a reversed {@code loca} or a short {@code hmtx} surfaces as an array exception while
 * the signature is being built. Everything checked here is bounded by the font's own size, so a bad font is
 * refused with a clear message in milliseconds. It is not a validator: a font that passes may still be refused
 * by FontBox.
 */
public final class FontCheck {

    /** Caller fonts larger than this are refused: CJK TrueType fonts with full coverage are around 20 MB. */
    static final int MAX_FONT_BYTES = 32 << 20;
    /** At most this many {@code cmap} encoding records (real fonts have up to about eight). */
    static final int MAX_CMAP_RECORDS = 16;
    /**
     * At most this many character-to-glyph entries over all {@code cmap} subtables together, duplicates
     * counted: FontBox builds a boxed hash-map entry for each. A font mapping every CJK character in both a
     * BMP and a full-Unicode subtable for two platforms needs about a quarter of this.
     */
    static final long MAX_CMAP_ENTRIES = 1_000_000;

    private record Table(int offset, int length) {
    }

    private final byte[] b;
    private final Map<String, Table> tables = new HashMap<>();

    private FontCheck(byte[] b) {
        this.b = b;
    }

    /**
     * @throws IllegalArgumentException with the reason, for the caller, when the font cannot be used
     */
    public static void check(byte[] font) {
        if (font.length > MAX_FONT_BYTES) {
            throw new IllegalArgumentException("the font is " + (font.length >> 20) + " MB; at most "
                    + (MAX_FONT_BYTES >> 20) + " MB are supported");
        }
        new FontCheck(font).run();
    }

    private void run() {
        if (b.length < 12) {
            throw bad("it is too short to be a font");
        }
        String tag = new String(b, 0, 4, StandardCharsets.ISO_8859_1);
        if (tag.equals("ttcf")) {
            throw bad("TrueType collections (.ttc) are not supported; extract one font");
        }
        if (tag.equals("OTTO")) {
            throw bad("it has PostScript (CFF) outlines; only TrueType outlines are supported");
        }
        if (u32(0) != 0x00010000L && !tag.equals("true")) {
            throw bad("it does not start with a TrueType header");
        }
        int numTables = u16(4);
        if (numTables == 0 || 12 + 16L * numTables > b.length) {
            throw bad("its table directory is truncated");
        }
        for (int i = 0; i < numTables; i++) {
            int at = 12 + 16 * i;
            String name = new String(b, at, 4, StandardCharsets.ISO_8859_1);
            long offset = u32(at + 8);
            long length = u32(at + 12);
            if (offset > b.length || length > b.length - offset) {
                throw bad("table '" + name + "' lies outside the file");
            }
            tables.put(name, new Table((int) offset, (int) length));
        }
        for (String required : new String[] {"head", "hhea", "maxp", "hmtx", "cmap"}) {
            if (!tables.containsKey(required)) {
                throw bad("the '" + required + "' table is missing");
            }
        }
        Table maxp = tables.get("maxp");
        if (maxp.length < 6) {
            throw bad("the 'maxp' table is truncated");
        }
        int numGlyphs = u16(maxp.offset + 4);
        if (numGlyphs == 0) {
            throw bad("it has no glyphs");
        }
        checkMetrics(numGlyphs);
        checkOutlines(numGlyphs);
        checkCmap();
        checkPermissions();
    }

    /**
     * {@code hmtx} must hold the horizontal metrics {@code hhea} announces, or FontBox fails on the first glyph.
     * The left side bearings of the remaining glyphs may be missing: FontBox reads what is there and takes the
     * rest as zero, so a font with a short bearing array is embedded like any other.
     */
    private void checkMetrics(int numGlyphs) {
        Table hhea = tables.get("hhea");
        if (hhea.length < 36) {
            throw bad("the 'hhea' table is truncated");
        }
        int numberOfHMetrics = u16(hhea.offset + 34);
        if (numberOfHMetrics < 1 || numberOfHMetrics > numGlyphs) {
            throw bad("'hhea' declares " + numberOfHMetrics + " horizontal metrics for " + numGlyphs + " glyphs");
        }
        if (tables.get("hmtx").length < 4L * numberOfHMetrics) {
            throw bad("the 'hmtx' table is shorter than its " + numberOfHMetrics + " horizontal metrics need");
        }
    }

    /** Every glyph's {@code loca} range must lie within {@code glyf}, in order: the subsetter allocates it. */
    private void checkOutlines(int numGlyphs) {
        Table head = tables.get("head");
        Table loca = tables.get("loca");
        Table glyf = tables.get("glyf");
        if (loca == null || glyf == null) {
            throw bad("the 'loca' or 'glyf' table is missing; only TrueType outlines are supported");
        }
        if (head.length < 54) {
            throw bad("the 'head' table is truncated");
        }
        int format = u16(head.offset + 50);
        if (format != 0 && format != 1) {
            throw bad("'head' has an unknown loca format " + format);
        }
        int entry = format == 0 ? 2 : 4;
        if ((long) (numGlyphs + 1) * entry > loca.length) {
            throw bad("the 'loca' table is shorter than its " + numGlyphs + " glyphs need");
        }
        long previous = 0;
        for (int gid = 0; gid <= numGlyphs; gid++) {
            long offset = format == 0 ? u16(loca.offset + gid * 2) * 2L : u32(loca.offset + gid * 4);
            if (offset < previous) {
                throw bad("glyph " + (gid - 1) + " has a negative length in 'loca'");
            }
            if (offset > glyf.length + 3L) { // a few bytes of padding past the table are tolerated
                throw bad("glyph " + Math.max(0, gid - 1) + " ends at byte " + offset + " of a " + glyf.length
                        + "-byte 'glyf' table");
            }
            previous = offset;
        }
    }

    /** Bounds what FontBox builds from the {@code cmap} table: one hash-map entry per mapped character. */
    private void checkCmap() {
        Table cmap = tables.get("cmap");
        if (cmap.length < 4) {
            throw bad("the 'cmap' table is truncated");
        }
        int records = u16(cmap.offset + 2);
        if (records > MAX_CMAP_RECORDS) {
            throw bad("'cmap' has " + records + " encoding records; at most " + MAX_CMAP_RECORDS
                    + " are supported");
        }
        if (4 + 8L * records > cmap.length) {
            throw bad("the 'cmap' table is truncated");
        }
        long entries = 0;
        for (int i = 0; i < records; i++) {
            long subtable = u32(cmap.offset + 4 + 8 * i + 4); // after the record's platform and encoding ids
            if (subtable + 4 > cmap.length) {
                throw bad("a 'cmap' subtable lies outside the table");
            }
            entries += cmapEntries(cmap.offset + (int) subtable, cmap.offset + cmap.length);
            if (entries > MAX_CMAP_ENTRIES) {
                throw bad("its 'cmap' subtables map more than " + MAX_CMAP_ENTRIES + " characters in all");
            }
        }
    }

    /** How many character codes FontBox will map for the subtable at {@code at}, reading no further than it. */
    private long cmapEntries(int at, int end) {
        int format = u16(at);
        switch (format) {
            case 0 -> {
                return 256;
            }
            case 2 -> {
                return 65536;
            }
            case 4 -> {
                need(at + 14, end);
                int segCount = u16(at + 6) / 2;
                int endCodes = at + 14;
                int startCodes = endCodes + segCount * 2 + 2;
                need(startCodes + segCount * 2, end);
                long n = 0;
                for (int s = 0; s < segCount; s++) {
                    int start = u16(startCodes + s * 2);
                    int last = u16(endCodes + s * 2);
                    if (start != 0xffff && last != 0xffff && last >= start) {
                        n += last - start + 1;
                    }
                }
                return n;
            }
            case 6 -> {
                need(at + 6, end);
                return u16(at + 4);
            }
            case 8 -> {
                need(at + 12 + 8192 + 4, end);
                return groups(at + 12 + 8192, end);
            }
            case 10 -> {
                need(at + 20, end);
                return u32(at + 16);
            }
            case 12 -> {
                need(at + 16, end);
                return groups(at + 12, end);
            }
            case 13 -> throw bad("'cmap' has a format 13 (many-to-one) subtable, which is not supported");
            default -> {
                return 0; // 14 (variation sequences) is ignored by FontBox; others fail there with its message
            }
        }
    }

    /** The characters covered by sequential map groups ({@code nGroups} at {@code at}, then 12 bytes each). */
    private long groups(int at, int end) {
        long nGroups = u32(at);
        if (nGroups > (end - at - 4) / 12) {
            throw bad("a 'cmap' subtable declares more groups than it holds");
        }
        long n = 0;
        for (int g = 0; g < nGroups; g++) {
            int group = at + 4 + g * 12;
            long start = u32(group);
            long last = u32(group + 4);
            if (last >= start) {
                n += last - start + 1;
            }
            if (n > MAX_CMAP_ENTRIES) {
                break;
            }
        }
        return n;
    }

    /** A font whose licence forbids subsetting cannot be embedded the way the drawer does. */
    private void checkPermissions() {
        Table os2 = tables.get("OS/2");
        if (os2 == null || os2.length < 10) {
            return; // FontBox reports a missing OS/2 table itself
        }
        int fsType = u16(os2.offset + 8);
        if ((fsType & 0x0100) != 0) {
            throw bad("its licence does not permit subsetting (OS/2 fsType bit 8), and fonts are embedded as "
                    + "subsets");
        }
    }

    private void need(long upTo, int end) {
        if (upTo > end) {
            throw bad("a 'cmap' subtable is truncated");
        }
    }

    private int u16(int i) {
        if (i < 0 || i + 2 > b.length) {
            throw bad("it is truncated");
        }
        return ((b[i] & 0xff) << 8) | (b[i + 1] & 0xff);
    }

    private long u32(int i) {
        if (i < 0 || i + 4 > b.length) {
            throw bad("it is truncated");
        }
        return ((long) (b[i] & 0xff) << 24) | ((b[i + 1] & 0xff) << 16) | ((b[i + 2] & 0xff) << 8) | (b[i + 3] & 0xff);
    }

    private static IllegalArgumentException bad(String why) {
        return new IllegalArgumentException(why);
    }
}
