/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class JsonTest {

    @Test
    void parsesAllValueKinds() {
        Object v = Json.parse(" {\"a\":1,\"b\":-2.5e1,\"c\":\"x\\u00e8\\n\\\"\",\"d\":[true,false,null],\"e\":{}} ");
        Map<?, ?> m = (Map<?, ?>) v;
        assertEquals(1L, m.get("a"));
        assertEquals(-25.0, m.get("b"));
        assertEquals("xè\n\"", m.get("c"));
        assertEquals(Arrays.asList(true, false, null), m.get("d"));
        assertEquals(Map.of(), m.get("e"));
    }

    @Test
    void writesAndRoundTrips() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("s", "quote\" backslash\\ ctl\u0001 line\u2028");
        m.put("n", 42);
        m.put("l", List.of(1.5, "x"));
        m.put("skipped", null);
        String json = Json.write(m);
        assertEquals("{\"s\":\"quote\\\" backslash\\\\ ctl\\u0001 line\\u2028\",\"n\":42,\"l\":[1.5,\"x\"]}", json);
        Map<?, ?> back = (Map<?, ?>) Json.parse(json);
        assertEquals(m.get("s"), back.get("s"));
    }

    @Test
    void rejectsMalformedInput() {
        for (String bad : List.of("", "{", "{\"a\"}", "{\"a\":1,}", "[1 2]", "tru", "\"unterminated", "{} x",
                "\"\\x\"", "01a", "{\"a\":\"\u0001\"}")) {
            assertThrows(Json.ParseException.class, () -> Json.parse(bad), bad);
        }
    }

    @Test
    void rejectsNonConformingNumbersEscapesAndDuplicateKeys() {
        for (String bad : List.of("01", "-01", "1.", ".5", "1e", "1e+", "1e999", "-1e999", "\"\\u+123\"", "\"\\u-001\"",
                "\"\\u12G4\"", "\"\\ud800\"", "\"\\udc00\"", "\"\\ud800x\"", "{\"a\":1,\"a\":2}",
                "{\"tl_sync\":{\"accept_invalid_signature\":false,\"accept_invalid_signature\":true}}")) {
            assertThrows(Json.ParseException.class, () -> Json.parse(bad), bad);
        }
        assertEquals(0L, Json.parse("0"));
        assertEquals(-0.5, Json.parse("-0.5"));
        assertEquals(1.0e3, Json.parse("1E3"));
        assertEquals(10L, Json.parse("10"));
        assertEquals("\uD83D\uDE00", Json.parse("\"\\ud83d\\ude00\""), "a surrogate pair is one character");
        assertEquals(Map.of("a", 1L, "b", Map.of("a", 2L)), Json.parse("{\"a\":1,\"b\":{\"a\":2}}"),
                "the same key in another object is fine");
    }

    @Test
    void rejectsExcessiveNesting() {
        assertThrows(Json.ParseException.class, () -> Json.parse("[".repeat(100) + "]".repeat(100)));
    }

    @Test
    void blankObjectInputIsEmptyObject() {
        assertEquals(Map.of(), Json.parseObject(null));
        assertEquals(Map.of(), Json.parseObject("  "));
    }
}
