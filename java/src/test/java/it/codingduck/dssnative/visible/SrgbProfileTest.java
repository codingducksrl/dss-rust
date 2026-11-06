/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.visible;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.awt.color.ColorSpace;
import java.awt.color.ICC_ColorSpace;
import java.awt.color.ICC_Profile;
import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledInNativeImage;

/** The sRGB profile we build for the output intent. */
class SrgbProfileTest {

    @Test
    void theSameBytesEveryTime() {
        assertArrayEquals(SrgbProfile.bytes(), SrgbProfile.bytes());
        byte[] b = SrgbProfile.bytes();
        int size = ((b[0] & 0xff) << 24) | ((b[1] & 0xff) << 16) | ((b[2] & 0xff) << 8) | (b[3] & 0xff);
        assertEquals(b.length, size, "the header gives the profile's size");
    }

    /**
     * The JDK's colour management (LittleCMS) reads it, and maps colours to the same XYZ as the JDK's own sRGB
     * profile. JVM only: the shipped library has no LittleCMS, which is why the profile is built.
     */
    @Test
    @DisabledInNativeImage
    void littleCmsReadsItAsSrgb() {
        ICC_Profile ours = ICC_Profile.getInstance(SrgbProfile.bytes());
        assertEquals(ICC_Profile.CLASS_DISPLAY, ours.getProfileClass());
        assertEquals(ColorSpace.TYPE_RGB, ours.getColorSpaceType());
        ICC_ColorSpace space = new ICC_ColorSpace(ours);
        ColorSpace reference = ColorSpace.getInstance(ColorSpace.CS_sRGB);
        float[][] colours = {{1, 0, 0}, {0, 1, 0}, {0, 0, 1}, {1, 1, 1}, {0.5f, 0.5f, 0.5f}, {0.2f, 0.7f, 0.4f}};
        for (float[] c : colours) {
            float[] want = reference.toCIEXYZ(c);
            float[] got = space.toCIEXYZ(c);
            for (int i = 0; i < 3; i++) {
                assertEquals(want[i], got[i], 0.01, "XYZ[" + i + "] of " + Arrays.toString(c));
            }
        }
    }
}
