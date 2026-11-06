/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.visible;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.zip.CRC32;

import javax.imageio.ImageIO;

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

    private static void refused(byte[] image, String reason) {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> SignatureImage.parse(image));
        assertTrue(e.getMessage().contains(reason), e.getMessage());
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
