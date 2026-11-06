/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.visible;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.CRC32;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * Decodes a non-interlaced PNG of any colour type and bit depth to 8-bit samples: Gray or RGB, plus alpha when
 * the image has transparency (an alpha channel or a {@code tRNS} chunk). 16-bit samples keep their high byte.
 * Ancillary chunks, colour profiles included, are ignored. Plain Java, so it needs neither ImageIO nor AWT.
 */
final class PngDecoder {

    private static final byte[] SIGNATURE = {(byte) 0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};

    /** @param alpha null when every pixel is opaque */
    record Decoded(int width, int height, boolean gray, byte[] samples, byte[] alpha) {
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

    static Decoded decode(byte[] b) {
        int width = 0;
        int height = 0;
        int depth = 0;
        int colorType = -1;
        byte[] palette = null;
        byte[] trns = null;
        ByteArrayOutputStream idat = new ByteArrayOutputStream();
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
                    width = readInt(b, data);
                    height = readInt(b, data + 4);
                    depth = b[data + 8] & 0xff;
                    colorType = b[data + 9] & 0xff;
                    if (b[data + 10] != 0 || b[data + 11] != 0) {
                        throw corrupt("unknown compression or filter method");
                    }
                    if (b[data + 12] != 0) {
                        throw new IllegalArgumentException("interlaced PNGs are not supported; save it without "
                                + "interlacing");
                    }
                    checkHeader(width, height, depth, colorType);
                }
                case "PLTE" -> palette = copy(b, data, len);
                case "tRNS" -> trns = copy(b, data, len);
                case "IDAT" -> idat.write(b, data, len);
                case "IEND" -> end = true;
                default -> {
                    // ancillary chunks (gAMA, iCCP, sRGB, pHYs, text, …) are ignored
                }
            }
            i += 12 + len;
        }
        if (colorType < 0) {
            throw corrupt("no IHDR");
        }
        if (colorType == 3 && palette == null) {
            throw corrupt("an indexed image without PLTE");
        }
        int channels = switch (colorType) {
            case 0, 3 -> 1;
            case 2 -> 3;
            case 4 -> 2;
            default -> 4; // 6
        };
        int bitsPerPixel = channels * depth;
        int stride = (int) (((long) width * bitsPerPixel + 7) / 8);
        byte[] raw = unfilter(inflate(idat.toByteArray(), (long) (stride + 1) * height), width, height, stride,
                Math.max(1, bitsPerPixel / 8));
        return toSamples(raw, width, height, depth, colorType, stride, palette, trns);
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

    private static byte[] inflate(byte[] compressed, long expected) {
        if (expected > Integer.MAX_VALUE - 8) {
            throw new IllegalArgumentException("the PNG is too large");
        }
        Inflater inflater = new Inflater();
        try {
            inflater.setInput(compressed);
            byte[] out = new byte[(int) expected];
            int n = 0;
            while (n < out.length && !inflater.finished()) {
                int r = inflater.inflate(out, n, out.length - n);
                if (r == 0 && (inflater.needsInput() || inflater.needsDictionary())) {
                    break;
                }
                n += r;
            }
            if (n != out.length) {
                throw corrupt("the image data is shorter than its size says");
            }
            return out;
        } catch (DataFormatException e) {
            throw corrupt("bad image data: " + e.getMessage());
        } finally {
            inflater.end();
        }
    }

    /** Reverses the per-row filters (PNG spec, section 9); returns the rows without their filter bytes. */
    private static byte[] unfilter(byte[] in, int width, int height, int stride, int bpp) {
        byte[] out = new byte[stride * height];
        for (int y = 0; y < height; y++) {
            int filter = in[y * (stride + 1)] & 0xff;
            int src = y * (stride + 1) + 1;
            int row = y * stride;
            int prev = row - stride;
            for (int x = 0; x < stride; x++) {
                int raw = in[src + x] & 0xff;
                int a = x >= bpp ? out[row + x - bpp] & 0xff : 0;
                int up = y > 0 ? out[prev + x] & 0xff : 0;
                int c = x >= bpp && y > 0 ? out[prev + x - bpp] & 0xff : 0;
                int v = switch (filter) {
                    case 0 -> raw;
                    case 1 -> raw + a;
                    case 2 -> raw + up;
                    case 3 -> raw + ((a + up) >> 1);
                    case 4 -> raw + paeth(a, up, c);
                    default -> throw corrupt("unknown row filter " + filter);
                };
                out[row + x] = (byte) v;
            }
        }
        return out;
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

    private static Decoded toSamples(byte[] raw, int width, int height, int depth, int colorType, int stride,
                                     byte[] palette, byte[] trns) {
        boolean gray = colorType == 0 || colorType == 4;
        int outChannels = gray ? 1 : 3;
        byte[] samples = new byte[width * height * outChannels];
        byte[] alpha = new byte[width * height];
        boolean transparent = false;
        int maxValue = (1 << depth) - 1;
        // tRNS for gray and RGB: the one colour, at the image's bit depth, that is fully transparent
        int keyGray = colorType == 0 && trns != null && trns.length >= 2 ? readShort(trns, 0) : -1;
        int keyR = -1;
        int keyG = -1;
        int keyB = -1;
        if (colorType == 2 && trns != null && trns.length >= 6) {
            keyR = readShort(trns, 0);
            keyG = readShort(trns, 2);
            keyB = readShort(trns, 4);
        }
        for (int y = 0; y < height; y++) {
            int row = y * stride;
            for (int x = 0; x < width; x++) {
                int pixel = y * width + x;
                int a = 255;
                switch (colorType) {
                    case 0 -> {
                        int v = sample(raw, row, x, depth);
                        samples[pixel] = (byte) (depth == 16 ? v >> 8 : v * 255 / maxValue);
                        if (v == keyGray) {
                            a = 0;
                        }
                    }
                    case 3 -> {
                        int index = sample(raw, row, x, depth);
                        if (index * 3 + 2 >= palette.length) {
                            throw corrupt("a palette index is out of range");
                        }
                        samples[pixel * 3] = palette[index * 3];
                        samples[pixel * 3 + 1] = palette[index * 3 + 1];
                        samples[pixel * 3 + 2] = palette[index * 3 + 2];
                        if (trns != null && index < trns.length) {
                            a = trns[index] & 0xff;
                        }
                    }
                    case 2 -> {
                        int r = sample(raw, row, x * 3, depth);
                        int g = sample(raw, row, x * 3 + 1, depth);
                        int bl = sample(raw, row, x * 3 + 2, depth);
                        samples[pixel * 3] = (byte) (depth == 16 ? r >> 8 : r);
                        samples[pixel * 3 + 1] = (byte) (depth == 16 ? g >> 8 : g);
                        samples[pixel * 3 + 2] = (byte) (depth == 16 ? bl >> 8 : bl);
                        if (r == keyR && g == keyG && bl == keyB) {
                            a = 0;
                        }
                    }
                    case 4 -> {
                        int v = sample(raw, row, x * 2, depth);
                        int al = sample(raw, row, x * 2 + 1, depth);
                        samples[pixel] = (byte) (depth == 16 ? v >> 8 : v);
                        a = depth == 16 ? al >> 8 : al;
                    }
                    default -> { // 6
                        for (int ch = 0; ch < 3; ch++) {
                            int v = sample(raw, row, x * 4 + ch, depth);
                            samples[pixel * 3 + ch] = (byte) (depth == 16 ? v >> 8 : v);
                        }
                        int al = sample(raw, row, x * 4 + 3, depth);
                        a = depth == 16 ? al >> 8 : al;
                    }
                }
                alpha[pixel] = (byte) a;
                transparent |= a != 255;
            }
        }
        return new Decoded(width, height, gray, samples, transparent ? alpha : null);
    }

    /** Sample number {@code n} of a row, at {@code depth} bits (1, 2, 4, 8 or 16). */
    private static int sample(byte[] raw, int row, int n, int depth) {
        return switch (depth) {
            case 8 -> raw[row + n] & 0xff;
            case 16 -> readShort(raw, row + n * 2);
            default -> {
                int bit = n * depth;
                int shift = 8 - depth - (bit & 7);
                yield ((raw[row + (bit >> 3)] & 0xff) >> shift) & ((1 << depth) - 1);
            }
        };
    }

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
