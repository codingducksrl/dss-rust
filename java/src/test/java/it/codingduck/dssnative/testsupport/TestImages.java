/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.testsupport;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.zip.CRC32;
import java.util.zip.Deflater;

/**
 * Images and fonts for visible-signature tests, made without AWT so the tests also run in the native test
 * image: PNGs are encoded here; the JPEG and the PDFs with fields come from {@code testdata/fixtures/content/}
 * ({@link FixtureGenerator}); the TrueType font is Liberation Sans from the PDFBox jar (SIL Open Font License).
 */
public final class TestImages {

    private TestImages() {
    }

    /**
     * A {@code width} x {@code height} PNG of colour type {@code colorType} (0, 2, 3, 4 or 6) and bit depth
     * {@code depth}, with a gradient and, for types 4 and 6, a transparent left half. Type 3 uses a 4-entry
     * palette, the first entry transparent through {@code tRNS} when {@code trns} is set; so does a type-0 or
     * type-2 image (its value 0 is the transparent key).
     */
    public static byte[] png(int width, int height, int colorType, int depth, boolean trns) {
        int channels = switch (colorType) {
            case 0, 3 -> 1;
            case 2 -> 3;
            case 4 -> 2;
            default -> 4;
        };
        int maxValue = (1 << depth) - 1;
        int stride = (width * channels * depth + 7) / 8;
        byte[] raw = new byte[(stride + 1) * height];
        byte[] previous = new byte[stride];
        for (int y = 0; y < height; y++) {
            int row = y * (stride + 1);
            int filterType = y % 5; // every row filter, so decoding exercises each
            raw[row] = (byte) filterType;
            int[] samples = new int[width * channels];
            for (int x = 0; x < width; x++) {
                for (int c = 0; c < channels; c++) {
                    boolean alphaChannel = (colorType == 4 && c == 1) || (colorType == 6 && c == 3);
                    int v;
                    if (alphaChannel) {
                        v = x < width / 2 ? 0 : maxValue;
                    } else if (colorType == 3) {
                        v = (x + y) % 4;
                    } else {
                        v = (int) ((long) maxValue * ((x * (c + 1) + y) % (width + 1)) / width);
                    }
                    samples[x * channels + c] = v;
                }
            }
            byte[] line = pack(samples, depth);
            filter(filterType, line, previous, Math.max(1, channels * depth / 8), raw, row + 1);
            previous = line;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(new byte[] {(byte) 0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'});
        byte[] ihdr = new byte[13];
        putInt(ihdr, 0, width);
        putInt(ihdr, 4, height);
        ihdr[8] = (byte) depth;
        ihdr[9] = (byte) colorType;
        chunk(out, "IHDR", ihdr);
        if (colorType == 3) {
            chunk(out, "PLTE", new byte[] {(byte) 255, 0, 0, 0, (byte) 128, 0, 0, 0, (byte) 255, 10, 10, 10});
            if (trns) {
                chunk(out, "tRNS", new byte[] {0});
            }
        } else if (trns && colorType == 0) {
            chunk(out, "tRNS", new byte[] {0, 0});
        } else if (trns && colorType == 2) {
            chunk(out, "tRNS", new byte[] {0, 0, 0, 0, 0, 0});
        }
        chunk(out, "gAMA", new byte[] {0, 0, (byte) 0xb1, (byte) 0x8f}); // ignored ancillary chunk
        chunk(out, "IDAT", deflate(raw));
        chunk(out, "IEND", new byte[0]);
        return out.toByteArray();
    }

    /** The PDFBox jar's Liberation Sans, a font every test machine has. */
    public static byte[] liberationSans() {
        try (InputStream in = TestImages.class.getResourceAsStream(
                "/org/apache/pdfbox/resources/ttf/LiberationSans-Regular.ttf")) {
            return in.readAllBytes();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static byte[] pack(int[] samples, int depth) {
        if (depth == 8) {
            byte[] b = new byte[samples.length];
            for (int i = 0; i < samples.length; i++) {
                b[i] = (byte) samples[i];
            }
            return b;
        }
        if (depth == 16) {
            byte[] b = new byte[samples.length * 2];
            for (int i = 0; i < samples.length; i++) {
                b[i * 2] = (byte) (samples[i] >> 8);
                b[i * 2 + 1] = (byte) samples[i];
            }
            return b;
        }
        byte[] b = new byte[(samples.length * depth + 7) / 8];
        for (int i = 0; i < samples.length; i++) {
            int bit = i * depth;
            b[bit >> 3] |= (byte) (samples[i] << (8 - depth - (bit & 7)));
        }
        return b;
    }

    /** Writes {@code line} filtered with {@code type} into {@code out} at {@code at}. */
    private static void filter(int type, byte[] line, byte[] previous, int bpp, byte[] out, int at) {
        for (int x = 0; x < line.length; x++) {
            int raw = line[x] & 0xff;
            int a = x >= bpp ? line[x - bpp] & 0xff : 0;
            int b = previous[x] & 0xff;
            int c = x >= bpp ? previous[x - bpp] & 0xff : 0;
            int predictor = switch (type) {
                case 1 -> a;
                case 2 -> b;
                case 3 -> (a + b) >> 1;
                case 4 -> paeth(a, b, c);
                default -> 0;
            };
            out[at + x] = (byte) (raw - predictor);
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

    private static void chunk(ByteArrayOutputStream out, String type, byte[] data) {
        byte[] len = new byte[4];
        putInt(len, 0, data.length);
        out.writeBytes(len);
        byte[] t = type.getBytes(StandardCharsets.US_ASCII);
        out.writeBytes(t);
        out.writeBytes(data);
        CRC32 crc = new CRC32();
        crc.update(t);
        crc.update(data);
        byte[] c = new byte[4];
        putInt(c, 0, (int) crc.getValue());
        out.writeBytes(c);
    }

    private static byte[] deflate(byte[] raw) {
        Deflater d = new Deflater();
        d.setInput(raw);
        d.finish();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        while (!d.finished()) {
            out.write(buffer, 0, d.deflate(buffer));
        }
        d.end();
        return out.toByteArray();
    }

    private static void putInt(byte[] b, int i, int v) {
        b[i] = (byte) (v >>> 24);
        b[i + 1] = (byte) (v >>> 16);
        b[i + 2] = (byte) (v >>> 8);
        b[i + 3] = (byte) v;
    }
}
