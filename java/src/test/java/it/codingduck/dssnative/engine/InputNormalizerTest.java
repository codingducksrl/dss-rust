/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Test;

import it.codingduck.dssnative.testsupport.Fixtures;

class InputNormalizerTest {

    private final byte[] der = Fixtures.read("cades/attached-der.p7m");

    @Test
    void recognisesRawFormats() {
        assertEquals(InputNormalizer.Type.CMS, InputNormalizer.normalize(der).type());
        assertEquals(InputNormalizer.Type.CMS, InputNormalizer.normalize(Fixtures.read("cades/attached-ber.p7m")).type());
        assertEquals(InputNormalizer.Type.PDF, InputNormalizer.normalize(Fixtures.read("pades/b-b.pdf")).type());
        // Junk before the header is tolerated within the first 1024 bytes.
        byte[] prefixed = ("garbage\n" + "%PDF-1.7\n").getBytes(StandardCharsets.US_ASCII);
        assertEquals(InputNormalizer.Type.PDF, InputNormalizer.normalize(prefixed).type());
    }

    @Test
    void decodesBase64Variants() {
        String b64 = Base64.getEncoder().encodeToString(der);
        for (String text : List.of(b64, Base64.getMimeEncoder().encodeToString(der), "  \n" + b64 + "\n",
                Base64.getUrlEncoder().encodeToString(der))) {
            InputNormalizer.Normalized n = InputNormalizer.normalize(text.getBytes(StandardCharsets.US_ASCII));
            assertEquals(InputNormalizer.Type.CMS, n.type());
            assertEquals(List.of("base64"), n.transformations());
            assertArrayEquals(der, n.bytes());
        }
    }

    @Test
    void decodesPemArmour() {
        String pem = "-----BEGIN PKCS7-----\n" + Base64.getMimeEncoder().encodeToString(der) + "\n-----END PKCS7-----\n";
        InputNormalizer.Normalized n = InputNormalizer.normalize(pem.getBytes(StandardCharsets.US_ASCII));
        assertEquals(InputNormalizer.Type.CMS, n.type());
        assertEquals(List.of("pem"), n.transformations());
        assertArrayEquals(der, n.bytes());
    }

    @Test
    void doubleBase64IsUnwrappedTwice() {
        byte[] once = Base64.getEncoder().encode(der);
        byte[] twice = Base64.getEncoder().encode(once);
        InputNormalizer.Normalized n = InputNormalizer.normalize(twice);
        assertEquals(List.of("base64", "base64"), n.transformations());
        assertArrayEquals(der, n.bytes());
    }

    @Test
    void unknownInputIsReportedAsSuch() {
        for (String s : List.of("hello world", "abc", "QUJD", "<xml/>")) {
            assertEquals(InputNormalizer.Type.UNKNOWN, InputNormalizer.normalize(s.getBytes(StandardCharsets.UTF_8)).type(), s);
        }
    }
}
