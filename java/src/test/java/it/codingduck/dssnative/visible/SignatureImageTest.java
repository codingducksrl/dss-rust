/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.visible;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.zip.CRC32;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import javax.imageio.ImageIO;

import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledInNativeImage;

import it.codingduck.dssnative.testsupport.Fixtures;
import it.codingduck.dssnative.testsupport.TestImages;

/** {@link SignatureImage} and {@link PngDecoder}: every PNG colour type and bit depth, JPEG headers, refusals. */
class SignatureImageTest {

    /** colour type, bit depth, tRNS. */
    private static final List<int[]> PNG_VARIANTS = List.of(
            new int[] {0, 1, 0}, new int[] {0, 2, 0}, new int[] {0, 4, 0}, new int[] {0, 8, 0}, new int[] {0, 16, 0},
            new int[] {0, 8, 1}, new int[] {2, 8, 0}, new int[] {2, 16, 0}, new int[] {2, 8, 1},
            new int[] {3, 1, 0}, new int[] {3, 2, 0}, new int[] {3, 4, 0}, new int[] {3, 8, 0}, new int[] {3, 8, 1},
            new int[] {4, 8, 0}, new int[] {4, 16, 0}, new int[] {6, 8, 0}, new int[] {6, 16, 0});

    @Test
    void everyPngColourTypeAndBitDepth() {
        for (int[] v : PNG_VARIANTS) {
            String what = "colour type " + v[0] + ", depth " + v[1] + (v[2] == 1 ? ", tRNS" : "");
            SignatureImage image = SignatureImage.parse(TestImages.png(37, 11, v[0], v[1], v[2] == 1));
            assertEquals(37, image.width(), what);
            assertEquals(11, image.height(), what);
            assertEquals(v[0] == 0 || v[0] == 4, image.isGray(), what);
            assertEquals(v[0] == 4 || v[0] == 6 || v[2] == 1, image.hasAlpha(), what);
        }
    }

    /** Our decoder against the JDK's, sample by sample (ImageIO needs AWT, so JVM only). */
    @Test
    @DisabledInNativeImage
    void pngSamplesMatchImageIo() throws IOException {
        for (int[] v : PNG_VARIANTS) {
            String what = "colour type " + v[0] + ", depth " + v[1] + (v[2] == 1 ? ", tRNS" : "");
            byte[] png = TestImages.png(37, 11, v[0], v[1], v[2] == 1);
            PngDecoder.Decoded ours = PngDecoder.decode(png);
            BufferedImage reference = ImageIO.read(new ByteArrayInputStream(png));
            for (int y = 0; y < 11; y++) {
                for (int x = 0; x < 37; x++) {
                    int pixel = y * 37 + x;
                    int[] expected = reference.getRaster().getPixel(x, y, (int[]) null);
                    int bands = reference.getRaster().getNumBands();
                    int shift = v[1] == 16 ? 8 : 0; // 16-bit samples keep their high byte
                    if (v[0] == 3) { // indexed: compare through the colour model
                        int argb = reference.getRGB(x, y);
                        assertEquals((argb >> 16) & 0xff, ours.samples()[pixel * 3] & 0xff, what);
                        assertEquals(argb & 0xff, ours.samples()[pixel * 3 + 2] & 0xff, what);
                        if (ours.alpha() != null) {
                            assertEquals(argb >>> 24, ours.alpha()[pixel] & 0xff, what);
                        }
                        continue;
                    }
                    int colorBands = ours.gray() ? 1 : 3;
                    for (int c = 0; c < colorBands; c++) {
                        int want = v[1] < 8 ? expected[c] * 255 / ((1 << v[1]) - 1) : expected[c] >> shift;
                        assertEquals(want, ours.samples()[pixel * colorBands + c] & 0xff, what + " at " + x + "," + y);
                    }
                    if (bands > colorBands) {
                        assertEquals(expected[colorBands] >> shift, ours.alpha()[pixel] & 0xff, what);
                    }
                }
            }
        }
    }

    @Test
    void jpegHeaderIsReadWithoutDecoding() {
        SignatureImage jpeg = SignatureImage.parse(Fixtures.read("content/stamp.jpg"));
        assertEquals(160, jpeg.width());
        assertEquals(80, jpeg.height());
        assertFalse(jpeg.isGray());
        assertFalse(jpeg.hasAlpha());
        assertArrayEquals(Fixtures.read("content/stamp.jpg"), jpeg.data(), "a JPEG goes into the PDF unchanged");
    }

    @Test
    void unsupportedImagesAreRefusedWithAReason() {
        refused(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9}, "neither a PNG nor a JPEG");

        byte[] png = TestImages.png(8, 8, 2, 8, false);
        byte[] interlaced = png.clone();
        interlaced[8 + 8 + 12] = 1; // IHDR interlace method
        fixCrc(interlaced, 8);
        refused(interlaced, "interlaced");
        byte[] badCrc = png.clone();
        badCrc[8 + 8 + 13] ^= 1;
        refused(badCrc, "bad CRC");
        refused(Arrays.copyOf(png, png.length - 20), "corrupt");

        byte[] jpeg = Fixtures.read("content/stamp.jpg");
        int sof = sof(jpeg);
        byte[] cmyk = jpeg.clone();
        cmyk[sof + 9] = 4;
        refused(cmyk, "CMYK");
        byte[] twelveBit = jpeg.clone();
        twelveBit[sof + 4] = 12;
        refused(twelveBit, "8-bit");
        byte[] arithmetic = jpeg.clone();
        arithmetic[sof + 1] = (byte) (arithmetic[sof + 1] | 0x09); // SOF0/2 -> SOF9/11
        refused(arithmetic, "not supported");
    }

    /** The guards of an untrusted-input parser, each with the message the caller gets. */
    @Test
    void pngParserGuardsRefuseWithAReason() {
        byte[] rgb = TestImages.png(8, 8, 2, 8, false);
        refused(withHeader(rgb, 6000, 6000), "at most " + SignatureImage.MAX_PIXELS + " pixels");
        refused(withHeader(rgb, 20000, 100), "each side can be at most " + SignatureImage.MAX_SIDE);
        refused(withHeader(rgb, 0, 8), "has no pixels");
        refused(withHeader(rgb, 0x80000000, 8), "has no pixels"); // a width past 2^31 reads as negative

        byte[] indexed = TestImages.png(8, 8, 3, 2, false); // indices 0..3 over a 4-entry palette
        refused(withoutChunk(indexed, "PLTE"), "indexed image without PLTE");
        refused(withChunk(indexed, "PLTE", new byte[] {1, 2, 3, 4, 5, 6}), "palette index is out of range");

        byte[] raw = inflate(chunkData(rgb, "IDAT"), (8 * 3 + 1) * 8);
        byte[] badFilter = raw.clone();
        badFilter[0] = 7;
        refused(withChunk(rgb, "IDAT", deflate(badFilter)), "unknown row filter 7");
        refused(withChunk(rgb, "IDAT", deflate(Arrays.copyOf(raw, raw.length / 2))), "shorter than its size says");
        refused(withChunk(rgb, "IDAT", new byte[] {1, 2, 3}), "bad image data");
        refused(withChunk(rgb, "IHDR", new byte[12]), "bad IHDR");
        refused(Arrays.copyOf(rgb, 8), "ends before IEND");
    }

    /** A JPEG stored rotated (Exif orientation 2-8) would come out rotated in the PDF, so it is refused. */
    @Test
    void jpegExifOrientationIsRefusedUnlessUpright() {
        byte[] jpeg = Fixtures.read("content/stamp.jpg");
        refused(withExif(jpeg, exif(true, 6)), "Exif orientation 6");
        refused(withExif(jpeg, exif(false, 3)), "Exif orientation 3");
        assertEquals(160, SignatureImage.parse(withExif(jpeg, exif(true, 1))).width(), "orientation 1 is upright");
        byte[] truncated = Arrays.copyOf(exif(true, 6), 12);
        assertEquals(160, SignatureImage.parse(withExif(jpeg, truncated)).width(), "a malformed Exif is ignored");
        byte[] notExif = "XMP\0".getBytes(StandardCharsets.US_ASCII);
        assertEquals(160, SignatureImage.parse(withExif(jpeg, notExif)).width(), "another APP1 is ignored");
    }

    /**
     * A small PNG can declare a huge image: 5000 x 5000 RGBA16 of one colour is 194 KB and 200 MB inflated. The
     * decoder works row by row, so parsing it allocates a few MB, and the result is cached for {@code complete}.
     */
    @Test
    @DisabledInNativeImage // allocation is measured through com.sun.management
    void aLargePngIsDecodedInBoundedMemoryAndCached() {
        byte[] png = zeros(5000, 5000, 6, 16);
        assertTrue(png.length < 250_000, "the PNG is small: " + png.length);
        SignatureImage.clearCache();
        com.sun.management.ThreadMXBean mx = (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();
        long id = Thread.currentThread().threadId();
        long before = mx.getThreadAllocatedBytes(id);
        SignatureImage image = SignatureImage.parse(png);
        long allocated = mx.getThreadAllocatedBytes(id) - before;
        assertEquals(5000, image.width());
        assertEquals(5000, image.height());
        assertTrue(image.hasAlpha(), "an alpha of 0 everywhere: fully transparent");
        assertTrue(allocated < 32L << 20, "decoding allocated " + (allocated >> 20) + " MB");
        assertSame(image, SignatureImage.parse(png), "the second call (complete) finds it in the cache");
        assertEquals(1, SignatureImage.cacheSize());
    }

    /** The row-by-row compression writes the same bytes as compressing the whole image at once did. */
    @Test
    void rowByRowCompressionEqualsOneShot() {
        for (int[] v : PNG_VARIANTS) {
            byte[] png = TestImages.png(37, 11, v[0], v[1], v[2] == 1);
            PngDecoder.Decoded whole = PngDecoder.decode(png);
            SignatureImage image = SignatureImage.parse(png);
            assertArrayEquals(deflateBest(whole.samples()), image.data(), "samples of type " + v[0] + "/" + v[1]);
            if (whole.alpha() != null) {
                assertArrayEquals(deflateBest(whole.alpha()), alpha(image), "alpha of type " + v[0] + "/" + v[1]);
            }
        }
    }

    /**
     * The alpha stream is started at the first row that is not fully opaque and fed the opaque rows before
     * it, so an opaque image compresses nothing for its mask and a transparent one gets the same stream
     * wherever its transparency starts.
     */
    @Test
    void theAlphaStreamIsTheSameWhereverTransparencyStarts() {
        for (int row : new int[] {0, 5, 10}) {
            byte[] png = rgba(37, 11, row);
            PngDecoder.Decoded whole = PngDecoder.decode(png);
            SignatureImage image = SignatureImage.parse(png);
            assertTrue(image.hasAlpha(), "transparent from row " + row);
            assertArrayEquals(deflateBest(whole.alpha()), alpha(image), "alpha, transparent from row " + row);
            assertArrayEquals(deflateBest(whole.samples()), image.data(), "samples, transparent from row " + row);
        }
        assertFalse(SignatureImage.parse(rgba(37, 11, -1)).hasAlpha(), "an opaque RGBA image has no soft mask");
    }

    /** The cache's byte bound follows the heap, so a small {@code --max-heap} is not a quarter pinned by images. */
    @Test
    void theCacheIsSizedToTheHeap() {
        long max = Runtime.getRuntime().maxMemory();
        assertEquals(Math.min(SignatureImage.MAX_CACHE_BYTES, max / 16), SignatureImage.cacheBytes());
        assertTrue(SignatureImage.cacheBytes() > 0);
    }

    /**
     * A {@code w} x {@code h} opaque white RGBA PNG with one half-transparent pixel in row
     * {@code transparentRow}, or none for -1.
     */
    private static byte[] rgba(int w, int h, int transparentRow) {
        byte[] raw = new byte[(w * 4 + 1) * h];
        Arrays.fill(raw, (byte) 0xff);
        for (int y = 0; y < h; y++) {
            raw[y * (w * 4 + 1)] = 0; // filter None
        }
        if (transparentRow >= 0) {
            raw[transparentRow * (w * 4 + 1) + 1 + 3] = (byte) 0x80;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(new byte[] {(byte) 0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'});
        byte[] ihdr = new byte[13];
        putInt(ihdr, 0, w);
        putInt(ihdr, 4, h);
        ihdr[8] = 8;
        ihdr[9] = 6;
        writeChunk(out, "IHDR", ihdr);
        writeChunk(out, "IDAT", deflate(raw));
        writeChunk(out, "IEND", new byte[0]);
        return out.toByteArray();
    }

    private static byte[] alpha(SignatureImage image) {
        try (PDDocument doc = new PDDocument()) {
            PDImageXObject x = image.toXObject(doc);
            COSStream mask = (COSStream) x.getCOSObject().getDictionaryObject(COSName.SMASK);
            try (InputStream in = mask.createRawInputStream()) {
                return in.readAllBytes();
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static void refused(byte[] image, String reason) {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> SignatureImage.parse(image));
        assertTrue(e.getMessage().contains(reason), e.getMessage());
    }

    // ------------------------------------------------------------------ crafting

    /** The PNG with another width and height in its IHDR. */
    private static byte[] withHeader(byte[] png, long width, long height) {
        byte[] out = png.clone();
        putInt(out, 16, (int) width);
        putInt(out, 20, (int) height);
        fixCrc(out, 8);
        return out;
    }

    private static byte[] withoutChunk(byte[] png, String type) {
        return rebuild(png, type, null);
    }

    private static byte[] withChunk(byte[] png, String type, byte[] data) {
        return rebuild(png, type, data);
    }

    /** The PNG with the chunk {@code type} replaced by {@code data}, or removed when {@code data} is null. */
    private static byte[] rebuild(byte[] png, String type, byte[] data) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(png, 0, 8);
        int i = 8;
        while (i + 12 <= png.length) {
            int len = readInt(png, i);
            String t = new String(png, i + 4, 4, StandardCharsets.US_ASCII);
            if (t.equals(type)) {
                if (data != null) {
                    writeChunk(out, type, data);
                }
            } else {
                out.write(png, i, 12 + len);
            }
            i += 12 + len;
        }
        return out.toByteArray();
    }

    private static byte[] chunkData(byte[] png, String type) {
        int i = 8;
        while (i + 12 <= png.length) {
            int len = readInt(png, i);
            if (new String(png, i + 4, 4, StandardCharsets.US_ASCII).equals(type)) {
                return Arrays.copyOfRange(png, i + 8, i + 8 + len);
            }
            i += 12 + len;
        }
        throw new IllegalStateException("no chunk " + type);
    }

    private static void writeChunk(ByteArrayOutputStream out, String type, byte[] data) {
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

    /** A {@code w} x {@code h} PNG of zero samples, built row by row (it would be 200 MB raw at 5000 x 5000). */
    private static byte[] zeros(int w, int h, int colorType, int depth) {
        int channels = switch (colorType) {
            case 0, 3 -> 1;
            case 2 -> 3;
            case 4 -> 2;
            default -> 4;
        };
        byte[] row = new byte[(w * channels * depth + 7) / 8 + 1];
        Deflater d = new Deflater();
        ByteArrayOutputStream idat = new ByteArrayOutputStream();
        byte[] buffer = new byte[65536];
        for (int y = 0; y < h; y++) {
            d.setInput(row);
            while (!d.needsInput()) {
                idat.write(buffer, 0, d.deflate(buffer));
            }
        }
        d.finish();
        while (!d.finished()) {
            idat.write(buffer, 0, d.deflate(buffer));
        }
        d.end();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(new byte[] {(byte) 0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'});
        byte[] ihdr = new byte[13];
        putInt(ihdr, 0, w);
        putInt(ihdr, 4, h);
        ihdr[8] = (byte) depth;
        ihdr[9] = (byte) colorType;
        writeChunk(out, "IHDR", ihdr);
        writeChunk(out, "IDAT", idat.toByteArray());
        writeChunk(out, "IEND", new byte[0]);
        return out.toByteArray();
    }

    private static byte[] inflate(byte[] compressed, int size) {
        Inflater inflater = new Inflater();
        try {
            inflater.setInput(compressed);
            byte[] out = new byte[size];
            int n = 0;
            while (n < size) {
                n += inflater.inflate(out, n, size - n);
            }
            return out;
        } catch (DataFormatException e) {
            throw new IllegalStateException(e);
        } finally {
            inflater.end();
        }
    }

    private static byte[] deflate(byte[] raw) {
        return deflate(raw, Deflater.DEFAULT_COMPRESSION);
    }

    private static byte[] deflateBest(byte[] raw) {
        return deflate(raw, Deflater.BEST_COMPRESSION);
    }

    private static byte[] deflate(byte[] raw, int level) {
        Deflater d = new Deflater(level);
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

    /** The JPEG with an APP1 segment of {@code payload} right after its SOI marker. */
    private static byte[] withExif(byte[] jpeg, byte[] payload) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(jpeg, 0, 2);
        out.write(0xff);
        out.write(0xe1);
        int length = payload.length + 2;
        out.write(length >> 8);
        out.write(length);
        out.writeBytes(payload);
        out.write(jpeg, 2, jpeg.length - 2);
        return out.toByteArray();
    }

    /** An Exif payload with one IFD0 entry: Orientation = {@code orientation}. */
    private static byte[] exif(boolean bigEndian, int orientation) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes("Exif\0\0".getBytes(StandardCharsets.US_ASCII));
        if (bigEndian) {
            out.writeBytes(new byte[] {'M', 'M', 0, 42, 0, 0, 0, 8, 0, 1, 0x01, 0x12, 0, 3, 0, 0, 0, 1,
                    (byte) (orientation >> 8), (byte) orientation, 0, 0, 0, 0, 0, 0});
        } else {
            out.writeBytes(new byte[] {'I', 'I', 42, 0, 8, 0, 0, 0, 1, 0, 0x12, 0x01, 3, 0, 1, 0, 0, 0,
                    (byte) orientation, (byte) (orientation >> 8), 0, 0, 0, 0, 0, 0});
        }
        return out.toByteArray();
    }

    private static int readInt(byte[] b, int i) {
        return ((b[i] & 0xff) << 24) | ((b[i + 1] & 0xff) << 16) | ((b[i + 2] & 0xff) << 8) | (b[i + 3] & 0xff);
    }

    private static void putInt(byte[] b, int i, int v) {
        b[i] = (byte) (v >>> 24);
        b[i + 1] = (byte) (v >>> 16);
        b[i + 2] = (byte) (v >>> 8);
        b[i + 3] = (byte) v;
    }

    /** Offset of the frame header marker (FF C0..C2) of a JPEG. */
    private static int sof(byte[] jpeg) {
        for (int i = 2; i + 1 < jpeg.length; i++) {
            int m = jpeg[i + 1] & 0xff;
            if ((jpeg[i] & 0xff) == 0xff && m >= 0xc0 && m <= 0xc2) {
                return i;
            }
        }
        throw new IllegalStateException("no SOF");
    }

    /** Recomputes the CRC of the chunk starting at {@code at}. */
    private static void fixCrc(byte[] png, int at) {
        int len = ((png[at] & 0xff) << 24) | ((png[at + 1] & 0xff) << 16) | ((png[at + 2] & 0xff) << 8)
                | (png[at + 3] & 0xff);
        CRC32 crc = new CRC32();
        crc.update(png, at + 4, 4 + len);
        int v = (int) crc.getValue();
        int c = at + 8 + len;
        png[c] = (byte) (v >>> 24);
        png[c + 1] = (byte) (v >>> 16);
        png[c + 2] = (byte) (v >>> 8);
        png[c + 3] = (byte) v;
    }
}
