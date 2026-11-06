/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Typed accessors over a parsed JSON object, raising {@link DssError} with the given code on bad input. */
final class JsonFields {

    private final Map<String, Object> map;
    private final String where;
    private final DssError.Code code;

    JsonFields(Map<String, Object> map, String where, DssError.Code code) {
        this.map = map == null ? Collections.emptyMap() : map;
        this.where = where;
        this.code = code;
    }

    /** Rejects keys outside {@code allowed}: a misspelt option should fail loudly, not be ignored. */
    JsonFields allowOnly(Set<String> allowed) {
        for (String key : map.keySet()) {
            if (!allowed.contains(key)) {
                throw error("unknown key '" + key + "' (allowed: " + String.join(", ", allowed) + ")");
            }
        }
        return this;
    }

    boolean has(String key) {
        return map.get(key) != null;
    }

    String string(String key, String def) {
        Object v = map.get(key);
        if (v == null) {
            return def;
        }
        if (!(v instanceof String)) {
            throw error("'" + key + "' must be a string");
        }
        return (String) v;
    }

    String requiredString(String key) {
        String v = string(key, null);
        if (v == null || v.isBlank()) {
            throw error("'" + key + "' is required");
        }
        return v;
    }

    boolean bool(String key, boolean def) {
        Object v = map.get(key);
        if (v == null) {
            return def;
        }
        if (!(v instanceof Boolean)) {
            throw error("'" + key + "' must be a boolean");
        }
        return (Boolean) v;
    }

    long integer(String key, long def) {
        Object v = map.get(key);
        if (v == null) {
            return def;
        }
        if (!(v instanceof Long)) {
            throw error("'" + key + "' must be an integer");
        }
        return (Long) v;
    }

    /** A number, integer or not. */
    double decimal(String key, double def) {
        Object v = map.get(key);
        if (v == null) {
            return def;
        }
        if (!(v instanceof Long) && !(v instanceof Double)) {
            throw error("'" + key + "' must be a number");
        }
        return ((Number) v).doubleValue();
    }

    List<String> strings(String key, List<String> def) {
        Object v = map.get(key);
        if (v == null) {
            return def;
        }
        if (!(v instanceof List)) {
            throw error("'" + key + "' must be an array of strings");
        }
        List<String> out = new ArrayList<>();
        for (Object o : (List<?>) v) {
            if (!(o instanceof String)) {
                throw error("'" + key + "' must be an array of strings");
            }
            out.add((String) o);
        }
        return out;
    }

    List<Integer> integers(String key, List<Integer> def) {
        Object v = map.get(key);
        if (v == null) {
            return def;
        }
        if (!(v instanceof List)) {
            throw error("'" + key + "' must be an array of integers");
        }
        List<Integer> out = new ArrayList<>();
        for (Object o : (List<?>) v) {
            if (!(o instanceof Long)) {
                throw error("'" + key + "' must be an array of integers");
            }
            out.add(((Long) o).intValue());
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    JsonFields object(String key) {
        Object v = map.get(key);
        if (v != null && !(v instanceof Map)) {
            throw error("'" + key + "' must be an object");
        }
        return new JsonFields((Map<String, Object>) v, where + "." + key, code);
    }

    @SuppressWarnings("unchecked")
    List<JsonFields> objects(String key) {
        Object v = map.get(key);
        if (v == null) {
            return Collections.emptyList();
        }
        if (!(v instanceof List)) {
            throw error("'" + key + "' must be an array of objects");
        }
        List<JsonFields> out = new ArrayList<>();
        int i = 0;
        for (Object o : (List<?>) v) {
            if (!(o instanceof Map)) {
                throw error("'" + key + "' must be an array of objects");
            }
            out.add(new JsonFields((Map<String, Object>) o, where + "." + key + "[" + i++ + "]", code));
        }
        return out;
    }

    DssError error(String message) {
        return new DssError(code, where + ": " + message);
    }
}
