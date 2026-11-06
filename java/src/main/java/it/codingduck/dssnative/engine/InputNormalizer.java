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
    /** Guards against pathological base64-of-base64 chains. */
    private static final int MAX_DECODE_ROUNDS = 3;

    private InputNormalizer() {
    }

    static Normalized normalize(byte[] input) {
        List<String> transformations = new ArrayList<>();
        byte[] bytes = input;
        for (int round = 0; round < MAX_DECODE_ROUNDS; round++) {
            Type type = sniff(bytes);
            if (type != Type.UNKNOWN) {
                return new Normalized(bytes, type, transformations);
            }
            byte[] decoded = decodeText(bytes);
            if (decoded == null) {
                break;
            }
            transformations.add(isPem(bytes) ? "pem" : "base64");
            bytes = decoded;
        }
        return new Normalized(input, Type.UNKNOWN, List.of());
    }

    static Type sniff(byte[] b) {
        if (b.length >= 2 && (b[0] & 0xFF) == 0x30) {
            // SEQUENCE with definite (0x81..0x84 long form or short form) or indefinite (0x80) length.
            return Type.CMS;
        }
        if (indexOf(b, "%PDF-".getBytes(StandardCharsets.US_ASCII), PDF_HEADER_WINDOW) >= 0) {
            return Type.PDF;
        }
        return Type.UNKNOWN;
    }

    private static boolean isPem(byte[] b) {
        return indexOf(b, "-----BEGIN".getBytes(StandardCharsets.US_ASCII), 64) >= 0;
    }

    /** Returns the decoded bytes if {@code b} is (PEM-armoured) base64 text, else null. */
    static byte[] decodeText(byte[] b) {
        String text = new String(b, StandardCharsets.US_ASCII);
        if (isPem(b)) {
            StringBuilder body = new StringBuilder();
            for (String line : text.split("\\R")) {
                if (!line.startsWith("-----") && !line.contains(":")) {
                    body.append(line.trim());
                }
            }
            text = body.toString();
        }
        int significant = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            boolean base64 = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '+' || c == '/' || c == '=' || c == '-' || c == '_';
            if (base64) {
                significant++;
            } else if (!Character.isWhitespace(c)) {
                return null;
            }
        }
        if (significant < 4) {
            return null;
        }
        String compact = text.replaceAll("\\s+", "");
        try {
            if (compact.indexOf('-') >= 0 || compact.indexOf('_') >= 0) {
                return Base64.getUrlDecoder().decode(compact);
            }
            return Base64.getDecoder().decode(compact);
        } catch (IllegalArgumentException e) {
            return null;
        }
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
