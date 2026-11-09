/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.visible;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.Deflater;

import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.graphics.color.PDColorSpace;
import org.apache.pdfbox.pdmodel.graphics.color.PDDeviceGray;
import org.apache.pdfbox.pdmodel.graphics.color.PDDeviceRGB;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;

/**
 * A PNG or JPEG for a visible signature, ready to become an image XObject without ImageIO or AWT: the shipped
 * library has neither libawt nor the JPEG and colour-management libraries they need (DECISIONS.md, "Visible
 * signatures"). A JPEG goes into the PDF as it is ({@code DCTDecode}); a PNG is decoded here and stored as
 * 8-bit Gray or RGB samples, with its transparency as a soft mask. Colour profiles in the image are ignored.
 *
 * <p>A PNG is decoded row by row straight into the Flate streams, so the memory a decode needs is a few rows
 * plus the compressed output (about the size of the PNG itself), whatever the image declares. Decoded PNGs are
 * kept in a small cache keyed by their bytes, so that {@code complete} does not decode again what
 * {@code prepare} just did.
 */
public final class SignatureImage {

    /** Larger images are refused: they would only be scaled down into a signature box. */
    static final int MAX_PIXELS = 25_000_000;
    /** No side longer than this: it bounds the row buffers of the PNG decoder (a row is at most 8 bytes a pixel). */
    static final int MAX_SIDE = 16_384;
    /** The decoded-PNG cache: at most this many images, and {@link #cacheBytes()} bytes of samples in all. */
    static final int CACHE_ENTRIES = 16;
    static final long MAX_CACHE_BYTES = 64L << 20;

    /**
     * The cache's byte bound follows the heap (a sixteenth of it, at most 64 MB), so a library run under a
     * small {@code --max-heap} does not pin a quarter of it for images: 16 MB at 256 MB, 64 MB from 1 GB up.
     * Read when needed rather than at class initialisation, which native-image may run at build time.
     */
    static long cacheBytes() {
        return Math.min(MAX_CACHE_BYTES, Runtime.getRuntime().maxMemory() / 16);
    }

    private static final Map<String, SignatureImage> CACHE = new LinkedHashMap<>(32, 0.75f, true);
    private static long cacheBytes;

    private final int width;
    private final int height;
    private final boolean gray;
    /** JPEG: the file. PNG: Flate-compressed samples. */
    private final byte[] data;
    private final boolean jpeg;
    /** Flate-compressed 8-bit alpha, or null when the image is opaque. */
    private final byte[] alpha;

    private SignatureImage(int width, int height, boolean gray, byte[] data, boolean jpeg, byte[] alpha) {
        this.width = width;
        this.height = height;
        this.gray = gray;
        this.data = data;
        this.jpeg = jpeg;
        this.alpha = alpha;
    }

    /**
     * Reads a PNG or a JPEG.
     *
     * @throws IllegalArgumentException with a message for the caller when the image is not one this supports
     */
    public static SignatureImage parse(byte[] bytes) {
        if (Jpeg.isJpeg(bytes)) {
            Jpeg.Header h = Jpeg.header(bytes);
            return new SignatureImage(h.width(), h.height(), h.components() == 1, bytes, true, null);
        }
        if (PngDecoder.isPng(bytes)) {
            String key = sha256(bytes);
            SignatureImage cached = cached(key);
            if (cached != null) {
                return cached;
            }
            SignatureImage image = decodePng(bytes);
            cache(key, image);
            return image;
        }
        throw new IllegalArgumentException("the image is neither a PNG nor a JPEG");
    }

    private static SignatureImage decodePng(byte[] bytes) {
        PngDecoder.Info info = PngDecoder.header(bytes);
        RowDeflater samples = new RowDeflater();
        // The alpha stream is started at the first row that is not fully opaque, fed the opaque rows before it
        // then: an opaque image (the common case) never compresses its width x height bytes of 255 for nothing,
        // and a transparent one gets the same stream it would from compressing every row as it came.
        RowDeflater[] alpha = {null};
        int[] rows = {0};
        try {
            PngDecoder.decode(bytes, (s, a, t) -> {
                samples.row(s);
                if (alpha[0] == null && t) {
                    alpha[0] = new RowDeflater();
                    byte[] opaque = new byte[a.length];
                    Arrays.fill(opaque, (byte) 0xff);
                    for (int i = 0; i < rows[0]; i++) {
                        alpha[0].row(opaque);
                    }
                }
                if (alpha[0] != null) {
                    alpha[0].row(a);
                }
                rows[0]++;
            });
            return new SignatureImage(info.width(), info.height(), info.gray(), samples.finish(), false,
                    alpha[0] != null ? alpha[0].finish() : null);
        } finally {
            samples.close();
            if (alpha[0] != null) {
                alpha[0].close();
            }
        }
    }

    public int width() {
        return width;
    }

    public int height() {
        return height;
    }

    public boolean isGray() {
        return gray;
    }

    boolean hasAlpha() {
        return alpha != null;
    }

    /** The bytes that identify this image in the signature's deterministic seed. */
    byte[] data() {
        return data;
    }

    PDImageXObject toXObject(PDDocument document) throws IOException {
        PDColorSpace colorSpace = gray ? PDDeviceGray.INSTANCE : PDDeviceRGB.INSTANCE;
        PDImageXObject image = new PDImageXObject(document, new ByteArrayInputStream(data),
                jpeg ? COSName.DCT_DECODE : COSName.FLATE_DECODE, width, height, 8, colorSpace);
        if (alpha != null) {
            PDImageXObject mask = new PDImageXObject(document, new ByteArrayInputStream(alpha), COSName.FLATE_DECODE,
                    width, height, 8, PDDeviceGray.INSTANCE);
            image.getCOSObject().setItem(COSName.SMASK, mask);
        }
        return image;
    }

    // ------------------------------------------------------------------ compression

    /**
     * Flate-compresses rows as they come, at a fixed level, so that prepare and complete compress the same
     * samples to the same bytes. Feeding the rows one by one gives the same output as compressing them at once.
     */
    private static final class RowDeflater {
        private final Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION);
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();
        private final byte[] buffer = new byte[16384];

        void row(byte[] row) {
            deflater.setInput(row);
            while (!deflater.needsInput()) {
                out.write(buffer, 0, deflater.deflate(buffer));
            }
        }

        byte[] finish() {
            deflater.finish();
            while (!deflater.finished()) {
                out.write(buffer, 0, deflater.deflate(buffer));
            }
            return out.toByteArray();
        }

        void close() {
            deflater.end();
        }
    }

    // ------------------------------------------------------------------ cache

    private static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static SignatureImage cached(String key) {
        synchronized (CACHE) {
            return CACHE.get(key);
        }
    }

    private static void cache(String key, SignatureImage image) {
        long size = image.data.length + (image.alpha != null ? image.alpha.length : 0);
        long limit = cacheBytes();
        if (size > limit) {
            return;
        }
        synchronized (CACHE) {
            if (CACHE.put(key, image) == null) {
                cacheBytes += size;
            }
            Iterator<SignatureImage> oldest = CACHE.values().iterator();
            while ((CACHE.size() > CACHE_ENTRIES || cacheBytes > limit) && oldest.hasNext()) {
                SignatureImage evicted = oldest.next();
                if (evicted == image) {
                    continue;
                }
                oldest.remove();
                cacheBytes -= evicted.data.length + (evicted.alpha != null ? evicted.alpha.length : 0);
            }
        }
    }

    /** For tests: how many decoded PNGs are cached. */
    static int cacheSize() {
        synchronized (CACHE) {
            return CACHE.size();
        }
    }

    /** For tests. */
    static void clearCache() {
        synchronized (CACHE) {
            CACHE.clear();
            cacheBytes = 0;
        }
    }

    // ------------------------------------------------------------------ JPEG

    /** What a JPEG declares in its frame header, read without decoding it. */
    static final class Jpeg {

        record Header(int width, int height, int components) {
        }

        private Jpeg() {
        }

        static boolean isJpeg(byte[] b) {
            return b.length > 3 && (b[0] & 0xff) == 0xff && (b[1] & 0xff) == 0xd8 && (b[2] & 0xff) == 0xff;
        }

        static Header header(byte[] b) {
            int i = 2;
            while (i + 4 <= b.length) {
                if ((b[i] & 0xff) != 0xff) {
                    throw new IllegalArgumentException("the JPEG is corrupt (no marker at byte " + i + ")");
                }
                int marker = b[i + 1] & 0xff;
                if (marker == 0xff) { // fill byte
                    i++;
                    continue;
                }
                if (marker == 0xd9 || marker == 0xda) { // EOI or SOS before any frame header
                    break;
                }
                int length = ((b[i + 2] & 0xff) << 8) | (b[i + 3] & 0xff);
                if (length < 2 || i + 2 + length > b.length) {
                    throw new IllegalArgumentException("the JPEG is corrupt (segment length)");
                }
                if (marker == 0xe1) { // APP1: Exif, whose orientation tag viewers of the PDF would not apply
                    int orientation = exifOrientation(b, i + 4, length - 2);
                    if (orientation > 1) {
                        throw new IllegalArgumentException("the JPEG has Exif orientation " + orientation
                                + " (it is stored rotated or mirrored); PDF viewers ignore it, so save the image "
                                + "with the rotation applied (orientation 1) first");
                    }
                }
                if (isFrameHeader(marker)) {
                    if (length < 8) {
                        throw new IllegalArgumentException("the JPEG is corrupt (frame header)");
                    }
                    int precision = b[i + 4] & 0xff;
                    int height = ((b[i + 5] & 0xff) << 8) | (b[i + 6] & 0xff);
                    int width = ((b[i + 7] & 0xff) << 8) | (b[i + 8] & 0xff);
                    int components = b[i + 9] & 0xff;
                    if (marker > 0xc2) { // only SOF0-2: baseline, extended sequential, progressive (Huffman)
                        throw new IllegalArgumentException("lossless, hierarchical and arithmetic-coded JPEGs are "
                                + "not supported; save it as a baseline or progressive JPEG");
                    }
                    if (precision != 8) {
                        throw new IllegalArgumentException("only 8-bit JPEGs are supported, this one is "
                                + precision + "-bit");
                    }
                    if (components == 4) {
                        throw new IllegalArgumentException("CMYK JPEGs are not supported; save it as RGB or as a "
                                + "PNG");
                    }
                    if (components != 1 && components != 3) {
                        throw new IllegalArgumentException("the JPEG has " + components + " components; only gray "
                                + "and RGB are supported");
                    }
                    checkSize(width, height);
                    return new Header(width, height, components);
                }
                i += 2 + length;
            }
            throw new IllegalArgumentException("the JPEG has no frame header");
        }

        /** SOF0–SOF15, except DHT (C4), JPG (C8) and DAC (CC). */
        private static boolean isFrameHeader(int marker) {
            return marker >= 0xc0 && marker <= 0xcf && marker != 0xc4 && marker != 0xc8 && marker != 0xcc;
        }

        /**
         * The Exif {@code Orientation} (tag 0x0112) of an APP1 segment's payload, 1-8; 0 when the segment is
         * not Exif, has no orientation, or is malformed (then it is ignored, as viewers do).
         */
        static int exifOrientation(byte[] b, int at, int len) {
            if (len < 14 || b[at] != 'E' || b[at + 1] != 'x' || b[at + 2] != 'i' || b[at + 3] != 'f'
                    || b[at + 4] != 0 || b[at + 5] != 0) {
                return 0;
            }
            int tiff = at + 6;
            int end = at + len;
            boolean little;
            if (b[tiff] == 'I' && b[tiff + 1] == 'I') {
                little = true;
            } else if (b[tiff] == 'M' && b[tiff + 1] == 'M') {
                little = false;
            } else {
                return 0;
            }
            if (u16(b, tiff + 2, little) != 42) {
                return 0;
            }
            long ifd = u32(b, tiff + 4, little);
            if (ifd < 8 || tiff + ifd + 2 > end) {
                return 0;
            }
            int entries = u16(b, (int) (tiff + ifd), little);
            int entry = (int) (tiff + ifd + 2);
            for (int n = 0; n < entries; n++, entry += 12) {
                if (entry + 12 > end) {
                    return 0;
                }
                if (u16(b, entry, little) == 0x0112) {
                    int type = u16(b, entry + 2, little);
                    long count = u32(b, entry + 4, little);
                    if (type != 3 || count != 1) {
                        return 0;
                    }
                    int value = u16(b, entry + 8, little);
                    return value >= 1 && value <= 8 ? value : 0;
                }
            }
            return 0;
        }

        private static int u16(byte[] b, int i, boolean little) {
            return little ? (b[i] & 0xff) | ((b[i + 1] & 0xff) << 8) : ((b[i] & 0xff) << 8) | (b[i + 1] & 0xff);
        }

        private static long u32(byte[] b, int i, boolean little) {
            return little ? (u16(b, i, true) | ((long) u16(b, i + 2, true) << 16))
                    : (((long) u16(b, i, false) << 16) | u16(b, i + 2, false));
        }
    }

    static void checkSize(int width, int height) {
        if (width < 1 || height < 1) {
            throw new IllegalArgumentException("the image has no pixels (" + width + "x" + height + ")");
        }
        if (width > MAX_SIDE || height > MAX_SIDE) {
            throw new IllegalArgumentException("the image is " + width + "x" + height + " pixels; each side can "
                    + "be at most " + MAX_SIDE + " pixels, scale it down");
        }
        if ((long) width * height > MAX_PIXELS) {
            throw new IllegalArgumentException("the image is " + width + "x" + height + " pixels; at most "
                    + MAX_PIXELS + " pixels are supported, scale it down");
        }
    }
}
