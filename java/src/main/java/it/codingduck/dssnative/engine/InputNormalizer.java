/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Detects the container type and strips transport encodings DSS does not handle itself:
 * base64 (common for {@code .p7m} received through PEC or web forms) and PEM armour.
 */
final class InputNormalizer {

    enum Type { PDF, CMS, UNKNOWN }

    record Normalized(byte[] bytes, Type type, List<String> transformations) {
    }

    /** PDF 1.7 §7.5.2 lets readers accept the header anywhere in the first 1024 bytes. */
    private static final int PDF_HEADER_WINDOW = 1024;
    /** Encodings removed at most (base64 of base64 of base64 still works; a deeper chain is pathological). */
    static final int MAX_DECODE_ROUNDS = 3;
    /** DER/BER tag of the OBJECT IDENTIFIER that opens a CMS {@code ContentInfo} (its contentType). */
    private static final int OID_TAG = 0x06;

    private InputNormalizer() {
    }

    static Normalized normalize(byte[] input) {
        List<String> transformations = new ArrayList<>();
        byte[] bytes = input;
        for (int decoded = 0; ; decoded++) {
            Type type = sniff(bytes);
            if (type != Type.UNKNOWN) {
                return new Normalized(bytes, type, transformations);
            }
            if (decoded == MAX_DECODE_ROUNDS) {
                break;
            }
            byte[] next = decodeText(bytes);
            if (next == null) {
                break;
            }
            transformations.add(isPem(bytes) ? "pem" : "base64");
            bytes = next;
        }
        return new Normalized(input, Type.UNKNOWN, List.of());
    }

    static Type sniff(byte[] b) {
        if (looksLikeCms(b)) {
            return Type.CMS;
        }
        if (indexOf(b, "%PDF-".getBytes(StandardCharsets.US_ASCII), PDF_HEADER_WINDOW) >= 0) {
            return Type.PDF;
        }
        return Type.UNKNOWN;
    }

    /**
     * A CMS {@code ContentInfo}: a SEQUENCE (0x30) with a well-formed length (short form, long form of up to four
     * bytes, or indefinite as BER writers emit it) whose first element is an OBJECT IDENTIFIER, the contentType.
     * Text starting with '0' ({@code "0 items"}) or base64 that happens to decode to 0x30 ({@code "MAIL"}) is not.
     * The declared length is not compared with the input's: a truncated CMS is still a CMS, and DSS says so.
     */
    static boolean looksLikeCms(byte[] b) {
        if (b.length < 4 || (b[0] & 0xFF) != 0x30) {
            return false;
        }
        int first = b[1] & 0xFF;
        int headerLength;
        if (first < 0x80 || first == 0x80) {
            headerLength = 2; // short form, or indefinite length (BER)
        } else {
            int lengthBytes = first & 0x7F;
            if (lengthBytes < 1 || lengthBytes > 4) {
                return false;
            }
            headerLength = 2 + lengthBytes;
        }
        return headerLength < b.length && (b[headerLength] & 0xFF) == OID_TAG;
    }

    private static boolean isPem(byte[] b) {
        return indexOf(b, "-----BEGIN".getBytes(StandardCharsets.US_ASCII), 64) >= 0;
    }

    /**
     * Returns the decoded bytes if {@code b} is (PEM-armoured) base64 text, else null. Plain base64 is checked
     * and compacted on the bytes themselves, so binary input is rejected at its first non-text byte without a
     * copy; only PEM armour, with its header lines, goes through a string.
     */
    static byte[] decodeText(byte[] b) {
        if (isPem(b)) {
            return decodePemBody(b);
        }
        int significant = 0;
        boolean urlSafe = false;
        for (byte x : b) {
            int c = x & 0xFF;
            if (isBase64Char(c)) {
                significant++;
                urlSafe |= c == '-' || c == '_';
            } else if (!isWhitespace(c)) {
                return null;
            }
        }
        if (significant < 4) {
            return null;
        }
        byte[] compact = new byte[significant];
        int n = 0;
        for (byte x : b) {
            if (isBase64Char(x & 0xFF)) {
                compact[n++] = x;
            }
        }
        return decodeBase64(compact, urlSafe);
    }

    private static byte[] decodePemBody(byte[] b) {
        String text = new String(b, StandardCharsets.US_ASCII);
        StringBuilder body = new StringBuilder();
        for (String line : text.split("\\R")) {
            if (!line.startsWith("-----") && !line.contains(":")) {
                body.append(line.trim());
            }
        }
        boolean urlSafe = false;
        int significant = 0;
        for (int i = 0; i < body.length(); i++) {
            int c = body.charAt(i);
            if (c < 0x80 && isBase64Char(c)) {
                significant++;
                urlSafe |= c == '-' || c == '_';
            } else if (!isWhitespace(c)) {
                return null;
            }
        }
        if (significant < 4) {
            return null;
        }
        return decodeBase64(body.toString().replaceAll("\\s+", "").getBytes(StandardCharsets.US_ASCII), urlSafe);
    }

    private static byte[] decodeBase64(byte[] compact, boolean urlSafe) {
        try {
            return (urlSafe ? Base64.getUrlDecoder() : Base64.getDecoder()).decode(compact);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static boolean isBase64Char(int c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                || c == '+' || c == '/' || c == '=' || c == '-' || c == '_';
    }

    private static boolean isWhitespace(int c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == 0x0B || c == 0x0C;
    }

    private static int indexOf(byte[] haystack, byte[] needle, int window) {
        int limit = Math.min(haystack.length - needle.length, window);
        outer:
        for (int i = 0; i <= limit; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
