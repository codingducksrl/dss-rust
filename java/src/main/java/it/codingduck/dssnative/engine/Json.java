/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal JSON reader/writer without reflection, so it needs no Native Image registration.
 *
 * <p>Parsed values map to: object → {@code LinkedHashMap<String,Object>}, array → {@code ArrayList<Object>},
 * string → {@code String}, number → {@code Long} or {@code Double}, true/false → {@code Boolean}, null → {@code null}.
 *
 * <p>Strict (RFC 8259): duplicate object keys, numbers with leading zeros or a dangling {@code .} or exponent,
 * numbers beyond a double's range, signed or non-hex {@code \\u} escapes and lone surrogates are all errors.
 * Lenient parsing here would let two parsers read one {@code config_json} differently.
 */
public final class Json {

    private Json() {
    }

    // ---------------------------------------------------------------- parsing

    /** Thrown for malformed input. */
    public static final class ParseException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        ParseException(String message, int position) {
            super(message + " at offset " + position);
        }
    }

    public static Object parse(String text) {
        Parser p = new Parser(text);
        p.skipWs();
        Object value = p.readValue(0);
        p.skipWs();
        if (p.pos != text.length()) {
            throw new ParseException("Trailing characters", p.pos);
        }
        return value;
    }

    /** Parses text that must be a JSON object; null or blank input yields an empty object. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String text) {
        if (text == null || text.isBlank()) {
            return new LinkedHashMap<>();
        }
        Object value = parse(text);
        if (!(value instanceof Map)) {
            throw new ParseException("Expected a JSON object", 0);
        }
        return (Map<String, Object>) value;
    }

    private static final class Parser {
        private static final int MAX_DEPTH = 64;
        private final String s;
        private int pos;

        Parser(String s) {
            this.s = s;
        }

        void skipWs() {
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    pos++;
                } else {
                    break;
                }
            }
        }

        Object readValue(int depth) {
            if (depth > MAX_DEPTH) {
                throw new ParseException("Nesting too deep", pos);
            }
            if (pos >= s.length()) {
                throw new ParseException("Unexpected end of input", pos);
            }
            char c = s.charAt(pos);
            switch (c) {
                case '{':
                    return readObject(depth);
                case '[':
                    return readArray(depth);
                case '"':
                    return readString();
                case 't':
                    expectWord("true");
                    return Boolean.TRUE;
                case 'f':
                    expectWord("false");
                    return Boolean.FALSE;
                case 'n':
                    expectWord("null");
                    return null;
                default:
                    if (c == '-' || (c >= '0' && c <= '9')) {
                        return readNumber();
                    }
                    throw new ParseException("Unexpected character '" + c + "'", pos);
            }
        }

        private void expectWord(String word) {
            if (!s.startsWith(word, pos)) {
                throw new ParseException("Expected '" + word + "'", pos);
            }
            pos += word.length();
        }

        private Map<String, Object> readObject(int depth) {
            Map<String, Object> map = new LinkedHashMap<>();
            pos++; // {
            skipWs();
            if (peek() == '}') {
                pos++;
                return map;
            }
            while (true) {
                skipWs();
                if (peek() != '"') {
                    throw new ParseException("Expected object key", pos);
                }
                int keyAt = pos;
                String key = readString();
                if (map.containsKey(key)) {
                    // Parsers disagree on which duplicate wins; for a security-relevant key that is a hole.
                    throw new ParseException("Duplicate key '" + key + "'", keyAt);
                }
                skipWs();
                if (peek() != ':') {
                    throw new ParseException("Expected ':'", pos);
                }
                pos++;
                skipWs();
                map.put(key, readValue(depth + 1));
                skipWs();
                char c = peek();
                pos++;
                if (c == '}') {
                    return map;
                }
                if (c != ',') {
                    throw new ParseException("Expected ',' or '}'", pos - 1);
                }
            }
        }

        private List<Object> readArray(int depth) {
            List<Object> list = new ArrayList<>();
            pos++; // [
            skipWs();
            if (peek() == ']') {
                pos++;
                return list;
            }
            while (true) {
                skipWs();
                list.add(readValue(depth + 1));
                skipWs();
                char c = peek();
                pos++;
                if (c == ']') {
                    return list;
                }
                if (c != ',') {
                    throw new ParseException("Expected ',' or ']'", pos - 1);
                }
            }
        }

        private char peek() {
            if (pos >= s.length()) {
                throw new ParseException("Unexpected end of input", pos);
            }
            return s.charAt(pos);
        }

        private String readString() {
            pos++; // opening quote
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (pos >= s.length()) {
                    throw new ParseException("Unterminated string", pos);
                }
                char c = s.charAt(pos++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c == '\\') {
                    if (pos >= s.length()) {
                        throw new ParseException("Unterminated escape", pos);
                    }
                    char e = s.charAt(pos++);
                    switch (e) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'u':
                            char u = readHex4();
                            if (Character.isHighSurrogate(u)) {
                                // Only a complete pair is a character; a lone surrogate is not valid text.
                                if (!(s.startsWith("\\u", pos) && pos + 6 <= s.length())) {
                                    throw new ParseException("Lone surrogate in unicode escape", pos - 6);
                                }
                                pos += 2;
                                char low = readHex4();
                                if (!Character.isLowSurrogate(low)) {
                                    throw new ParseException("Lone surrogate in unicode escape", pos - 12);
                                }
                                sb.append(u).append(low);
                            } else if (Character.isLowSurrogate(u)) {
                                throw new ParseException("Lone surrogate in unicode escape", pos - 6);
                            } else {
                                sb.append(u);
                            }
                            break;
                        default:
                            throw new ParseException("Bad escape '\\" + e + "'", pos - 1);
                    }
                } else if (c < 0x20) {
                    throw new ParseException("Control character in string", pos - 1);
                } else {
                    sb.append(c);
                }
            }
        }

        /** Exactly four hex digits at {@code pos} (a sign or anything else is an error), consumed. */
        private char readHex4() {
            if (pos + 4 > s.length()) {
                throw new ParseException("Bad unicode escape", pos);
            }
            int value = 0;
            for (int i = 0; i < 4; i++) {
                int digit = Character.digit(s.charAt(pos + i), 16);
                if (digit < 0) {
                    throw new ParseException("Bad unicode escape", pos);
                }
                value = (value << 4) | digit;
            }
            pos += 4;
            return (char) value;
        }

        private Object readNumber() {
            int start = pos;
            if (peek() == '-') {
                pos++;
            }
            boolean integral = true;
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if (c >= '0' && c <= '9') {
                    pos++;
                } else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
                    integral = false;
                    pos++;
                } else {
                    break;
                }
            }
            String num = s.substring(start, pos);
            // RFC 8259 §6: no leading zeros, digits on both sides of '.', digits after the exponent.
            if (!NUMBER.matcher(num).matches()) {
                throw new ParseException("Bad number '" + num + "'", start);
            }
            try {
                if (integral) {
                    return Long.parseLong(num);
                }
                double d = Double.parseDouble(num);
                if (Double.isInfinite(d) || Double.isNaN(d)) {
                    throw new ParseException("Number out of range '" + num + "'", start);
                }
                return d;
            } catch (NumberFormatException ex) {
                throw new ParseException("Bad number '" + num + "'", start);
            }
        }

        private static final java.util.regex.Pattern NUMBER =
                java.util.regex.Pattern.compile("-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?");
    }

    // ---------------------------------------------------------------- writing

    /** Serializes maps, collections, strings, numbers, booleans and null. */
    public static String write(Object value) {
        StringBuilder sb = new StringBuilder(256);
        writeValue(sb, value);
        return sb.toString();
    }

    private static void writeValue(StringBuilder sb, Object value) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof String) {
            writeString(sb, (String) value);
        } else if (value instanceof Boolean) {
            sb.append(((Boolean) value).booleanValue() ? "true" : "false");
        } else if (value instanceof Double || value instanceof Float) {
            double d = ((Number) value).doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) {
                sb.append("null");
            } else {
                sb.append(d);
            }
        } else if (value instanceof Number) {
            sb.append(((Number) value).longValue());
        } else if (value instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : ((Map<?, ?>) value).entrySet()) {
                if (e.getValue() == null) {
                    continue; // absent and null mean the same to readers; keep output small
                }
                if (!first) {
                    sb.append(',');
                }
                first = false;
                writeString(sb, String.valueOf(e.getKey()));
                sb.append(':');
                writeValue(sb, e.getValue());
            }
            sb.append('}');
        } else if (value instanceof Collection) {
            sb.append('[');
            Iterator<?> it = ((Collection<?>) value).iterator();
            while (it.hasNext()) {
                writeValue(sb, it.next());
                if (it.hasNext()) {
                    sb.append(',');
                }
            }
            sb.append(']');
        } else {
            writeString(sb, value.toString());
        }
    }

    private static void writeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                default:
                    if (c < 0x20 || c == 0x2028 || c == 0x2029) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
    }
}
