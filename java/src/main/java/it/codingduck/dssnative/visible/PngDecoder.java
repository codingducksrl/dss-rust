/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.visible;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.CRC32;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * Decodes a non-interlaced PNG of any colour type and bit depth to 8-bit samples: Gray or RGB, plus alpha when
 * the image has transparency (an alpha channel or a {@code tRNS} chunk). 16-bit samples keep their high byte.
 * Ancillary chunks, colour profiles included, are ignored. Plain Java, so it needs neither ImageIO nor AWT.
 *
 * <p>The image is decoded row by row: the compressed data is inflated into one row at a time, unfiltered
 * against the previous row and handed to a {@link RowSink}, so the memory needed is a few rows, whatever the
 * image size. A small file can declare a large image (a 200 KB PNG can hold 25 megapixels of one colour), and
 * before this the decoder held the whole inflated image, its unfiltered copy and the samples at once.
 */
final class PngDecoder {

    private static final byte[] SIGNATURE = {(byte) 0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};

    /** @param alpha null when every pixel is opaque */
    record Decoded(int width, int height, boolean gray, byte[] samples, byte[] alpha) {
    }

    /** What the header says, known before any pixel is decoded. */
    record Info(int width, int height, boolean gray) {
    }

    /**
     * Receives the image one row at a time, top to bottom. The arrays are reused between rows: a sink must
     * copy or consume them before returning.
     */
    interface RowSink {
        /**
         * @param samples     the row's 8-bit samples: {@code width} bytes (gray) or {@code 3 * width} (RGB)
         * @param alpha       the row's 8-bit alpha, {@code width} bytes; all 255 when the row is opaque
         * @param transparent whether any pixel of this row is not fully opaque
         */
        void row(byte[] samples, byte[] alpha, boolean transparent);
    }

    /** One IDAT chunk's data, by position in the file. */
    private record Range(int offset, int length) {
    }

    private PngDecoder() {
    }

    static boolean isPng(byte[] b) {
        if (b.length < SIGNATURE.length) {
            return false;
        }
        for (int i = 0; i < SIGNATURE.length; i++) {
            if (b[i] != SIGNATURE[i]) {
                return false;
            }
        }
        return true;
    }

    /** Decodes the whole image into memory; for images known to be small (tests). */
    static Decoded decode(byte[] b) {
        Info info = header(b);
        int channels = info.gray ? 1 : 3;
        byte[] samples = new byte[info.width * info.height * channels];
        byte[] alpha = new byte[info.width * info.height];
        boolean[] transparent = {false};
        int[] y = {0};
        decode(b, (s, a, t) -> {
            System.arraycopy(s, 0, samples, y[0] * info.width * channels, info.width * channels);
            System.arraycopy(a, 0, alpha, y[0] * info.width, info.width);
            transparent[0] |= t;
            y[0]++;
        });
        return new Decoded(info.width, info.height, info.gray, samples, transparent[0] ? alpha : null);
    }

    /** The image's size and kind, from its header, with the whole file's chunk structure checked. */
    static Info header(byte[] b) {
        Chunks c = chunks(b);
        return new Info(c.width, c.height, c.colorType == 0 || c.colorType == 4);
    }

    /** Decodes the image into {@code sink}, row by row. */
    static void decode(byte[] b, RowSink sink) {
        Chunks c = chunks(b);
        int channels = switch (c.colorType) {
            case 0, 3 -> 1;
            case 2 -> 3;
            case 4 -> 2;
            default -> 4; // 6
        };
        int bitsPerPixel = channels * c.depth;
        int stride = (int) (((long) c.width * bitsPerPixel + 7) / 8);
        int bpp = Math.max(1, bitsPerPixel / 8);
        boolean gray = c.colorType == 0 || c.colorType == 4;
        byte[] filtered = new byte[stride + 1];
        byte[] row = new byte[stride];
        byte[] previous = new byte[stride];
        byte[] samples = new byte[c.width * (gray ? 1 : 3)];
        byte[] alpha = new byte[c.width];
        Converter converter = new Converter(c);
        Inflater inflater = new Inflater();
        try {
            int chunk = 0;
            for (int y = 0; y < c.height; y++) {
                int filled = 0;
                while (filled < filtered.length) {
                    int n = inflater.inflate(filtered, filled, filtered.length - filled);
                    if (n > 0) {
                        filled += n;
                        continue;
                    }
                    if (inflater.finished() || inflater.needsDictionary()) {
                        throw corrupt("the image data is shorter than its size says");
                    }
                    if (inflater.needsInput()) {
                        if (chunk >= c.idat.size()) {
                            throw corrupt("the image data is shorter than its size says");
                        }
                        Range r = c.idat.get(chunk++);
                        inflater.setInput(b, r.offset, r.length);
                    }
                }
                unfilter(filtered, row, previous, stride, bpp, y > 0);
                boolean transparent = converter.convert(row, samples, alpha);
                sink.row(samples, alpha, transparent);
                byte[] swap = previous;
                previous = row;
                row = swap;
            }
        } catch (DataFormatException e) {
            throw corrupt("bad image data: " + e.getMessage());
        } finally {
            inflater.end();
        }
    }

    // ------------------------------------------------------------------ chunks

    private static final class Chunks {
        int width;
        int height;
        int depth;
        int colorType = -1;
        byte[] palette;
        byte[] trns;
        final List<Range> idat = new ArrayList<>();
    }

    /** Walks and checks every chunk (lengths, CRCs, the header), without touching the image data. */
    private static Chunks chunks(byte[] b) {
        Chunks c = new Chunks();
        int i = SIGNATURE.length;
        boolean end = false;
        while (!end) {
            if (i + 12 > b.length) {
                throw corrupt("it ends before IEND");
            }
            long length = readInt(b, i) & 0xffffffffL;
            if (length > b.length - i - 12) {
                throw corrupt("a chunk is longer than the file");
            }
            int len = (int) length;
            String type = new String(b, i + 4, 4, StandardCharsets.US_ASCII);
            CRC32 crc = new CRC32();
            crc.update(b, i + 4, 4 + len);
            if ((int) crc.getValue() != readInt(b, i + 8 + len)) {
                throw corrupt("bad CRC in chunk " + type);
            }
            int data = i + 8;
            switch (type) {
                case "IHDR" -> {
                    if (len != 13) {
                        throw corrupt("bad IHDR");
                    }
                    c.width = readInt(b, data);
                    c.height = readInt(b, data + 4);
                    c.depth = b[data + 8] & 0xff;
                    c.colorType = b[data + 9] & 0xff;
                    if (b[data + 10] != 0 || b[data + 11] != 0) {
                        throw corrupt("unknown compression or filter method");
                    }
                    if (b[data + 12] != 0) {
                        throw new IllegalArgumentException("interlaced PNGs are not supported; save it without "
                                + "interlacing");
                    }
                    checkHeader(c.width, c.height, c.depth, c.colorType);
                }
                case "PLTE" -> c.palette = copy(b, data, len);
                case "tRNS" -> c.trns = copy(b, data, len);
                case "IDAT" -> c.idat.add(new Range(data, len));
                case "IEND" -> end = true;
                default -> {
                    // ancillary chunks (gAMA, iCCP, sRGB, pHYs, text, …) are ignored
                }
            }
            i += 12 + len;
        }
        if (c.colorType < 0) {
            throw corrupt("no IHDR");
        }
        if (c.colorType == 3 && c.palette == null) {
            throw corrupt("an indexed image without PLTE");
        }
        return c;
    }

    private static void checkHeader(int width, int height, int depth, int colorType) {
        SignatureImage.checkSize(width, height);
        boolean ok = switch (colorType) {
            case 0 -> depth == 1 || depth == 2 || depth == 4 || depth == 8 || depth == 16;
            case 3 -> depth == 1 || depth == 2 || depth == 4 || depth == 8;
            case 2, 4, 6 -> depth == 8 || depth == 16;
            default -> false;
        };
        if (!ok) {
            throw corrupt("colour type " + colorType + " with bit depth " + depth);
        }
    }

    // ------------------------------------------------------------------ rows

    /** Reverses one row's filter (PNG spec, section 9): {@code in} is the filter byte and the row. */
    private static void unfilter(byte[] in, byte[] out, byte[] previous, int stride, int bpp, boolean hasPrevious) {
        int filter = in[0] & 0xff;
        if (filter > 4) {
            throw corrupt("unknown row filter " + filter);
        }
        for (int x = 0; x < stride; x++) {
            int raw = in[1 + x] & 0xff;
            int a = x >= bpp ? out[x - bpp] & 0xff : 0;
            int up = hasPrevious ? previous[x] & 0xff : 0;
            int c = x >= bpp && hasPrevious ? previous[x - bpp] & 0xff : 0;
            int v = switch (filter) {
                case 0 -> raw;
                case 1 -> raw + a;
                case 2 -> raw + up;
                case 3 -> raw + ((a + up) >> 1);
                default -> raw + paeth(a, up, c);
            };
            out[x] = (byte) v;
        }
    }

    private static int paeth(int a, int b, int c) {
        int p = a + b - c;
        int pa = Math.abs(p - a);
        int pb = Math.abs(p - b);
        int pc = Math.abs(p - c);
        if (pa <= pb && pa <= pc) {
            return a;
        }
        return pb <= pc ? b : c;
    }

    /** Turns one unfiltered row into 8-bit samples and alpha. */
    private static final class Converter {
        private final int width;
        private final int depth;
        private final int colorType;
        private final byte[] palette;
        private final byte[] trns;
        private final int maxValue;
        // tRNS for gray and RGB: the one colour, at the image's bit depth, that is fully transparent
        private final int keyGray;
        private final int keyR;
        private final int keyG;
        private final int keyB;

        Converter(Chunks c) {
            this.width = c.width;
            this.depth = c.depth;
            this.colorType = c.colorType;
            this.palette = c.palette;
            this.trns = c.trns;
            this.maxValue = (1 << depth) - 1;
            this.keyGray = colorType == 0 && trns != null && trns.length >= 2 ? readShort(trns, 0) : -1;
            boolean rgbKey = colorType == 2 && trns != null && trns.length >= 6;
            this.keyR = rgbKey ? readShort(trns, 0) : -1;
            this.keyG = rgbKey ? readShort(trns, 2) : -1;
            this.keyB = rgbKey ? readShort(trns, 4) : -1;
        }

        /** @return whether any pixel of the row is not fully opaque */
        boolean convert(byte[] raw, byte[] samples, byte[] alpha) {
            boolean transparent = false;
            for (int x = 0; x < width; x++) {
                int a = 255;
                switch (colorType) {
                    case 0 -> {
                        int v = sample(raw, x);
                        samples[x] = (byte) (depth == 16 ? v >> 8 : v * 255 / maxValue);
                        if (v == keyGray) {
                            a = 0;
                        }
                    }
                    case 3 -> {
                        int index = sample(raw, x);
                        if (index * 3 + 2 >= palette.length) {
                            throw corrupt("a palette index is out of range");
                        }
                        samples[x * 3] = palette[index * 3];
                        samples[x * 3 + 1] = palette[index * 3 + 1];
                        samples[x * 3 + 2] = palette[index * 3 + 2];
                        if (trns != null && index < trns.length) {
                            a = trns[index] & 0xff;
                        }
                    }
                    case 2 -> {
                        int r = sample(raw, x * 3);
                        int g = sample(raw, x * 3 + 1);
                        int bl = sample(raw, x * 3 + 2);
                        samples[x * 3] = (byte) (depth == 16 ? r >> 8 : r);
                        samples[x * 3 + 1] = (byte) (depth == 16 ? g >> 8 : g);
                        samples[x * 3 + 2] = (byte) (depth == 16 ? bl >> 8 : bl);
                        if (r == keyR && g == keyG && bl == keyB) {
                            a = 0;
                        }
                    }
                    case 4 -> {
                        int v = sample(raw, x * 2);
                        int al = sample(raw, x * 2 + 1);
                        samples[x] = (byte) (depth == 16 ? v >> 8 : v);
                        a = depth == 16 ? al >> 8 : al;
                    }
                    default -> { // 6
                        for (int ch = 0; ch < 3; ch++) {
                            int v = sample(raw, x * 4 + ch);
                            samples[x * 3 + ch] = (byte) (depth == 16 ? v >> 8 : v);
                        }
                        int al = sample(raw, x * 4 + 3);
                        a = depth == 16 ? al >> 8 : al;
                    }
                }
                alpha[x] = (byte) a;
                transparent |= a != 255;
            }
            return transparent;
        }

        /** Sample number {@code n} of the row, at the image's bit depth (1, 2, 4, 8 or 16). */
        private int sample(byte[] raw, int n) {
            return switch (depth) {
                case 8 -> raw[n] & 0xff;
                case 16 -> readShort(raw, n * 2);
                default -> {
                    int bit = n * depth;
                    int shift = 8 - depth - (bit & 7);
                    yield ((raw[bit >> 3] & 0xff) >> shift) & maxValue;
                }
            };
        }
    }

    // ------------------------------------------------------------------ bytes

    private static int readInt(byte[] b, int i) {
        return ((b[i] & 0xff) << 24) | ((b[i + 1] & 0xff) << 16) | ((b[i + 2] & 0xff) << 8) | (b[i + 3] & 0xff);
    }

    private static int readShort(byte[] b, int i) {
        return ((b[i] & 0xff) << 8) | (b[i + 1] & 0xff);
    }

    private static byte[] copy(byte[] b, int from, int len) {
        byte[] out = new byte[len];
        System.arraycopy(b, from, out, 0, len);
        return out;
    }

    private static IllegalArgumentException corrupt(String why) {
        return new IllegalArgumentException("the PNG is corrupt or unsupported: " + why);
    }
}
