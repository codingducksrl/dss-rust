/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.visible;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
 */
public final class SignatureImage {

    /** Larger images are refused: they would only be scaled down into a signature box. */
    static final int MAX_PIXELS = 25_000_000;

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
            PngDecoder.Decoded d = PngDecoder.decode(bytes);
            return new SignatureImage(d.width(), d.height(), d.gray(), deflate(d.samples()), false,
                    d.alpha() != null ? deflate(d.alpha()) : null);
        }
        throw new IllegalArgumentException("the image is neither a PNG nor a JPEG");
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

    /** A fixed level, so that prepare and complete compress the same samples to the same bytes. */
    private static byte[] deflate(byte[] raw) {
        Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION);
        try {
            deflater.setInput(raw);
            deflater.finish();
            ByteArrayOutputStream out = new ByteArrayOutputStream(raw.length / 2 + 64);
            byte[] buffer = new byte[16384];
            while (!deflater.finished()) {
                out.write(buffer, 0, deflater.deflate(buffer));
            }
            return out.toByteArray();
        } finally {
            deflater.end();
        }
    }

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
    }

    static void checkSize(int width, int height) {
        if (width < 1 || height < 1) {
            throw new IllegalArgumentException("the image has no pixels (" + width + "x" + height + ")");
        }
        if ((long) width * height > MAX_PIXELS) {
            throw new IllegalArgumentException("the image is " + width + "x" + height + " pixels; at most "
                    + MAX_PIXELS + " pixels are supported, scale it down");
        }
    }
}
