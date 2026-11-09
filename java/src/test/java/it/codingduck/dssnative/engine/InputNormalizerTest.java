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
    void tripleBase64IsUnwrappedToo() {
        byte[] thrice = Base64.getEncoder().encode(Base64.getEncoder().encode(Base64.getEncoder().encode(der)));
        InputNormalizer.Normalized n = InputNormalizer.normalize(thrice);
        assertEquals(InputNormalizer.Type.CMS, n.type());
        assertEquals(List.of("base64", "base64", "base64"), n.transformations());
        assertArrayEquals(der, n.bytes());
        // A fourth layer is past MAX_DECODE_ROUNDS.
        assertEquals(InputNormalizer.Type.UNKNOWN, InputNormalizer.normalize(Base64.getEncoder().encode(thrice)).type());
    }

    @Test
    void unknownInputIsReportedAsSuch() {
        for (String s : List.of("hello world", "abc", "QUJD", "<xml/>")) {
            assertEquals(InputNormalizer.Type.UNKNOWN, InputNormalizer.normalize(s.getBytes(StandardCharsets.UTF_8)).type(), s);
        }
    }

    @Test
    void textStartingWithZeroIsNotCms() {
        // Each starts with 0x30 ('0'), or is base64 that decodes to 0x30, yet none is a ContentInfo.
        for (String s : List.of("0 items in stock", "MAIL", "00", "0123456789", "0\n\n\n")) {
            assertEquals(InputNormalizer.Type.UNKNOWN, InputNormalizer.normalize(s.getBytes(StandardCharsets.UTF_8)).type(), s);
        }
        assertEquals(InputNormalizer.Type.UNKNOWN, InputNormalizer.sniff(new byte[] {0x30, (byte) 0x80, 0x01, 0x02}));
        assertEquals(InputNormalizer.Type.UNKNOWN, InputNormalizer.sniff(new byte[] {0x30, (byte) 0x85, 1, 2, 3, 4, 5, 6}),
                "five length bytes is not a length a CMS has");
    }

    @Test
    void truncatedAndIndefiniteLengthCmsStillCountAsCms() {
        byte[] ber = Fixtures.read("cades/attached-ber.p7m");
        assertEquals(InputNormalizer.Type.CMS, InputNormalizer.sniff(ber));
        assertEquals(InputNormalizer.Type.CMS, InputNormalizer.sniff(java.util.Arrays.copyOf(der, der.length / 2)),
                "truncated: DSS reports what is wrong, not 'unsupported'");
        assertEquals(InputNormalizer.Type.CMS, InputNormalizer.sniff(new byte[] {0x30, 0x03, 0x06, 0x01, 0x2a}));
    }

    @Test
    void binaryInputIsRejectedWithoutDecoding() {
        byte[] binary = new byte[] {0x50, 0x4b, 0x03, 0x04, (byte) 0xff, 0x00, 0x7f}; // a ZIP header
        assertEquals(null, InputNormalizer.decodeText(binary));
        assertEquals(InputNormalizer.Type.UNKNOWN, InputNormalizer.normalize(binary).type());
        assertArrayEquals(der, InputNormalizer.decodeText(("  " + Base64.getEncoder().encodeToString(der) + "\r\n")
                .getBytes(StandardCharsets.US_ASCII)));
    }
}
