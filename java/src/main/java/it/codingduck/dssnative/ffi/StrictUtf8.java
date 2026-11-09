/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.ffi;

import java.nio.ByteBuffer;

/**
 * Strict UTF-8 validation of the C API's string arguments, without allocating. {@code String(byte[], UTF_8)} and
 * GraalVM's {@code CTypeConversion.utf8ToJavaString} replace malformed sequences with U+FFFD; a cache directory or a
 * file path inside {@code config_json} would then be used at a different path from the one the caller passed,
 * with a success result. The C API rejects such strings as {@code INVALID_ARGUMENT} instead.
 *
 * <p>Accepts exactly the well-formed sequences of RFC 3629 / Unicode table 3-7: no overlong forms, no surrogate
 * code points (U+D800..U+DFFF), nothing above U+10FFFF. Plain Java, so it is tested on the JVM.
 */
final class StrictUtf8 {

    private StrictUtf8() {
    }

    /**
     * The offset of the first malformed byte sequence in {@code bytes} (position to limit; the position is not
     * moved), or -1 if the whole buffer is well-formed UTF-8. A truncated sequence at the end is malformed.
     */
    static int firstMalformed(ByteBuffer bytes) {
        int i = bytes.position();
        int end = bytes.limit();
        while (i < end) {
            int b = bytes.get(i) & 0xFF;
            int need;
            int lo = 0x80;
            int hi = 0xBF;
            if (b < 0x80) {
                i++;
                continue;
            } else if (b >= 0xC2 && b <= 0xDF) {
                need = 1;
            } else if (b == 0xE0) {
                need = 2;
                lo = 0xA0; // not overlong
            } else if (b == 0xED) {
                need = 2;
                hi = 0x9F; // no surrogates
            } else if (b >= 0xE1 && b <= 0xEF) {
                need = 2;
            } else if (b == 0xF0) {
                need = 3;
                lo = 0x90; // not overlong
            } else if (b == 0xF4) {
                need = 3;
                hi = 0x8F; // at most U+10FFFF
            } else if (b >= 0xF1 && b <= 0xF3) {
                need = 3;
            } else {
                return i; // a continuation byte on its own, C0/C1, or F5..FF
            }
            if (i + need >= end) {
                return i; // truncated
            }
            int c = bytes.get(i + 1) & 0xFF;
            if (c < lo || c > hi) {
                return i;
            }
            for (int k = 2; k <= need; k++) {
                c = bytes.get(i + k) & 0xFF;
                if (c < 0x80 || c > 0xBF) {
                    return i;
                }
            }
            i += need + 1;
        }
        return -1;
    }
}
