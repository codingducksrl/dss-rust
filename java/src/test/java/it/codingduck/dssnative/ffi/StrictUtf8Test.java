/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.ffi;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Random;

import org.junit.jupiter.api.Test;

/**
 * The C API's strict decoder must agree with the JDK's reporting UTF-8 decoder on what is malformed, and point at
 * the offending byte, so {@code dss_init} refuses a {@code cache_dir} it could not use as given.
 */
class StrictUtf8Test {

    private static int first(int... bytes) {
        byte[] b = new byte[bytes.length];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) bytes[i];
        }
        return StrictUtf8.firstMalformed(ByteBuffer.wrap(b));
    }

    @Test
    void wellFormedTextIsAccepted() {
        assertEquals(-1, first());
        assertEquals(-1, StrictUtf8.firstMalformed(ByteBuffer.wrap("/var/lib/app/dss-cache".getBytes(StandardCharsets.UTF_8))));
        assertEquals(-1, StrictUtf8.firstMalformed(ByteBuffer.wrap(
                "{\"tl_snapshot\":\"/dati/élenchi/日本/🔒.tlsnap\"}".getBytes(StandardCharsets.UTF_8))));
        assertEquals(-1, first(0x7F, 0xC2, 0x80, 0xDF, 0xBF, 0xE0, 0xA0, 0x80, 0xED, 0x9F, 0xBF, 0xEF, 0xBF, 0xBF,
                0xF0, 0x90, 0x80, 0x80, 0xF4, 0x8F, 0xBF, 0xBF));
    }

    @Test
    void malformedSequencesAreReportedAtTheirOffset() {
        assertEquals(2, first('a', 'b', 0xC3, 0x28));        // the probe of the audit: invalid continuation
        assertEquals(0, first(0x80));                        // lone continuation byte
        assertEquals(0, first(0xC0, 0xAF));                  // overlong '/'
        assertEquals(0, first(0xC1, 0xBF));                  // overlong
        assertEquals(1, first('x', 0xE0, 0x80, 0x80));       // overlong 3-byte form
        assertEquals(0, first(0xED, 0xA0, 0x80));            // surrogate U+D800
        assertEquals(0, first(0xED, 0xBF, 0xBF));            // surrogate U+DFFF
        assertEquals(0, first(0xF0, 0x80, 0x80, 0x80));      // overlong 4-byte form
        assertEquals(0, first(0xF4, 0x90, 0x80, 0x80));      // above U+10FFFF
        assertEquals(0, first(0xF5, 0x80, 0x80, 0x80));      // never valid lead byte
        assertEquals(0, first(0xFF));
        assertEquals(3, first('a', 'b', 'c', 0xE2, 0x82));   // truncated at the end
        assertEquals(0, first(0xC3));                        // truncated: a lone lead byte
    }

    @Test
    void positionAndLimitAreHonoured() {
        ByteBuffer b = ByteBuffer.wrap(new byte[] {(byte) 0xFF, 'o', 'k', (byte) 0xFF});
        b.position(1).limit(3);
        assertEquals(-1, StrictUtf8.firstMalformed(b));
        assertEquals(1, b.position());
        b.limit(4);
        assertEquals(3, StrictUtf8.firstMalformed(b));
    }

    /** Random byte strings: well-formed exactly when the JDK's decoder, set to REPORT, accepts them. */
    @Test
    void agreesWithTheJdkDecoder() {
        Random random = new Random(20261109);
        int disagreements = 0;
        int malformed = 0;
        for (int n = 0; n < 20000; n++) {
            byte[] bytes = new byte[1 + random.nextInt(8)];
            random.nextBytes(bytes);
            // Bias towards the interesting lead bytes, or nearly every sample would fail at byte 0.
            for (int i = 0; i < bytes.length; i++) {
                if (random.nextInt(3) == 0) {
                    bytes[i] = (byte) (0x80 | random.nextInt(0x40));
                } else if (random.nextInt(2) == 0) {
                    bytes[i] = (byte) random.nextInt(0x80);
                }
            }
            boolean jdk;
            try {
                StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes));
                jdk = true;
            } catch (CharacterCodingException e) {
                jdk = false;
            }
            boolean strict = StrictUtf8.firstMalformed(ByteBuffer.wrap(bytes)) < 0;
            if (jdk != strict) {
                disagreements++;
            }
            if (!strict) {
                malformed++;
            }
        }
        assertEquals(0, disagreements);
        // The sample must have exercised both outcomes.
        assertEquals(true, malformed > 1000 && malformed < 19000, "malformed samples: " + malformed);
    }
}
