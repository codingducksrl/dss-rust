/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.visible;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * An ICC v2 sRGB display profile, built here byte by byte. DSS embeds the JDK's own sRGB profile, read through
 * {@code java.awt.color.ICC_Profile}, which needs the native colour-management library the shipped library does
 * not have. Built rather than bundled, so no third-party file and licence come along. The same bytes on every
 * run, so prepare and complete embed the same profile.
 *
 * <p>Contents: the sRGB primaries adapted to D50 (Bradford), the D65 media white point, and the sRGB transfer
 * function (IEC 61966-2-1) as a 1024-entry curve shared by the three channels.
 */
final class SrgbProfile {

    private static final byte[] BYTES = build();

    private SrgbProfile() {
    }

    static byte[] bytes() {
        return BYTES.clone();
    }

    private static byte[] build() {
        byte[] desc = desc("sRGB IEC61966-2.1 (dss-native)");
        byte[] cprt = text("No copyright, use freely");
        byte[] wtpt = xyz(0.9505, 1.0, 1.0891);
        byte[] rXyz = xyz(0.4361, 0.2225, 0.0139);
        byte[] gXyz = xyz(0.3851, 0.7169, 0.0971);
        byte[] bXyz = xyz(0.1431, 0.0606, 0.7141);
        byte[] trc = curve();

        String[] signatures = {"desc", "cprt", "wtpt", "rXYZ", "gXYZ", "bXYZ", "rTRC", "gTRC", "bTRC"};
        byte[][] data = {desc, cprt, wtpt, rXyz, gXyz, bXyz, trc, null, null}; // g/bTRC share rTRC's data

        int tableSize = 4 + 12 * signatures.length;
        int[] offsets = new int[signatures.length];
        int[] sizes = new int[signatures.length];
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        int offset = 128 + tableSize;
        for (int i = 0; i < signatures.length; i++) {
            if (data[i] == null) {
                offsets[i] = offsets[i - 1];
                sizes[i] = sizes[i - 1];
                continue;
            }
            offsets[i] = offset;
            sizes[i] = data[i].length;
            body.writeBytes(data[i]);
            offset += data[i].length;
            while (offset % 4 != 0) { // tag data starts on 4-byte boundaries
                body.write(0);
                offset++;
            }
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream(offset);
        // header (ICC.1:2001-04, section 6.1)
        writeInt(out, offset);                 // profile size
        writeInt(out, 0);                      // preferred CMM
        writeInt(out, 0x02100000);             // version 2.1
        writeAscii(out, "mntr");               // device class: display
        writeAscii(out, "RGB ");               // colour space
        writeAscii(out, "XYZ ");               // profile connection space
        for (int v : new int[] {2026, 1, 1, 0, 0, 0}) { // creation date, fixed
            out.write(v >> 8);
            out.write(v);
        }
        writeAscii(out, "acsp");
        writeInt(out, 0);                      // platform
        writeInt(out, 0);                      // flags
        writeInt(out, 0);                      // device manufacturer
        writeInt(out, 0);                      // device model
        out.writeBytes(new byte[8]);           // device attributes
        writeInt(out, 0);                      // rendering intent: perceptual
        writeS15(out, 0.9642);                 // PCS illuminant: D50
        writeS15(out, 1.0);
        writeS15(out, 0.8249);
        writeInt(out, 0);                      // creator
        out.writeBytes(new byte[44]);          // reserved (profile ID in v4)
        // tag table
        writeInt(out, signatures.length);
        for (int i = 0; i < signatures.length; i++) {
            writeAscii(out, signatures[i]);
            writeInt(out, offsets[i]);
            writeInt(out, sizes[i]);
        }
        out.writeBytes(body.toByteArray());
        return out.toByteArray();
    }

    private static byte[] xyz(double x, double y, double z) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeAscii(out, "XYZ ");
        writeInt(out, 0);
        writeS15(out, x);
        writeS15(out, y);
        writeS15(out, z);
        return out.toByteArray();
    }

    /** The sRGB transfer function, linear below 0.04045. */
    private static byte[] curve() {
        int n = 1024;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeAscii(out, "curv");
        writeInt(out, 0);
        writeInt(out, n);
        for (int i = 0; i < n; i++) {
            double v = i / (double) (n - 1);
            // StrictMath: the same result on the JVM and in the native image, on every platform
            double linear = v <= 0.04045 ? v / 12.92 : StrictMath.pow((v + 0.055) / 1.055, 2.4);
            int u16 = (int) Math.round(linear * 65535);
            out.write(u16 >> 8);
            out.write(u16);
        }
        return out.toByteArray();
    }

    /** textDescriptionType: ASCII, then empty Unicode and ScriptCode descriptions. */
    private static byte[] desc(String s) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeAscii(out, "desc");
        writeInt(out, 0);
        writeInt(out, s.length() + 1);
        writeAscii(out, s);
        out.write(0);
        writeInt(out, 0);                      // Unicode language code
        writeInt(out, 0);                      // Unicode count
        out.write(0);                          // ScriptCode code
        out.write(0);
        out.write(0);                          // ScriptCode count
        out.writeBytes(new byte[67]);          // ScriptCode description
        return out.toByteArray();
    }

    private static byte[] text(String s) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeAscii(out, "text");
        writeInt(out, 0);
        writeAscii(out, s);
        out.write(0);
        return out.toByteArray();
    }

    private static void writeInt(ByteArrayOutputStream out, int v) {
        out.write(v >>> 24);
        out.write(v >>> 16);
        out.write(v >>> 8);
        out.write(v);
    }

    private static void writeS15(ByteArrayOutputStream out, double v) {
        writeInt(out, (int) Math.round(v * 65536));
    }

    private static void writeAscii(ByteArrayOutputStream out, String s) {
        out.writeBytes(s.getBytes(StandardCharsets.US_ASCII));
    }
}
