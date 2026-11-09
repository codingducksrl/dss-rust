/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.ffi;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import it.codingduck.dssnative.engine.DssJsonApi;
import it.codingduck.dssnative.engine.Json;
import it.codingduck.dssnative.testsupport.Fixtures;
import it.codingduck.dssnative.testsupport.TestEngines;

/**
 * {@code dss_validate_with_contents} minus the C stub: the entry point hands {@code DssJsonApi.validate(ByteBuffer,
 * String, List)} read-only views of the caller's memory (direct buffers, possibly with a position and limit), and
 * those bytes must decide the verdict exactly as a base64 {@code detached_contents} entry would, next to whatever
 * the caller's {@code options_json} already said. The engine's own test covers the same route with heap buffers
 * and the full list of refusals; this one keeps the end-to-end cases on the buffers the C API builds.
 */
class DetachedContentsTest {

    @TempDir
    Path tmp;

    @AfterEach
    void tearDown() {
        DssJsonApi.shutdown();
    }

    /** As the entry point builds them: a read-only view of memory outside the heap, not a byte[] wrapper. */
    private static ByteBuffer direct(byte[] bytes) {
        ByteBuffer b = ByteBuffer.allocateDirect(bytes.length).put(bytes);
        b.flip();
        return b.asReadOnlyBuffer();
    }

    private static DssJsonApi.DetachedContent content(String name, byte[] bytes) {
        return new DssJsonApi.DetachedContent(name, direct(bytes));
    }

    @Test
    @SuppressWarnings("unchecked")
    void detachedSignatureIsCheckedAgainstTheBinaryContent() {
        TestEngines t = new TestEngines(tmp);
        Path cache = tmp.resolve("seeded");
        t.onlineLoaded(cache, null).close();
        Map<String, Object> init = Json.parseObject(DssJsonApi.init(cache.toString(),
                t.configJson("\"revocation\":\"offline\",\"aia\":false")));
        assertEquals(Boolean.TRUE, init.get("ok"), init.toString());

        ByteBuffer signature = direct(Fixtures.read("cades/detached.txt.p7s"));
        byte[] content = Fixtures.read("content/document.txt");
        byte[] tampered = Fixtures.read("tampered/content/document.txt");

        // count 0 (NULL arrays) is dss_validate: the signed data is missing.
        assertEquals("SIGNED_DATA_NOT_FOUND",
                signatureOf(DssJsonApi.validate(signature, null, null)).get("sub_indication"));
        assertEquals("SIGNED_DATA_NOT_FOUND",
                signatureOf(DssJsonApi.validate(signature, null, List.of())).get("sub_indication"));

        // The content as a slice of a larger direct buffer: position and limit are honoured and left alone, and
        // the caller's other options are still applied (the detailed report comes back).
        ByteBuffer slice = ByteBuffer.allocateDirect(content.length + 8);
        slice.put(new byte[] {'x', 'x', 'x', 'x'}).put(content).put(new byte[] {'y', 'y', 'y', 'y'});
        slice.position(4).limit(4 + content.length);
        ByteBuffer view = slice.asReadOnlyBuffer();
        String withJson = DssJsonApi.validate(signature, "{\"reports\":[\"detailed\"]}",
                List.of(new DssJsonApi.DetachedContent("document.txt", view)));
        assertEquals(4, view.position());
        assertEquals(4 + content.length, view.limit());
        Map<String, Object> with = signatureOf(withJson);
        assertEquals("CAdES-BASELINE-B", with.get("format"));
        assertNotEquals("SIGNED_DATA_NOT_FOUND", with.get("sub_indication"));
        assertNotEquals("HASH_FAILURE", with.get("sub_indication"));
        assertTrue(Json.parseObject(withJson).containsKey("detailed_report_xml"), withJson);

        // The tampered content fails the hash check: the bytes went through, not just a name.
        Map<String, Object> bad = signatureOf(DssJsonApi.validate(signature, null,
                List.of(content("document.txt", tampered))));
        assertEquals("TOTAL_FAILED", bad.get("indication"));
        assertEquals("HASH_FAILURE", bad.get("sub_indication"));

        // A binary content next to an entry the caller's JSON already carried (the C smoke test's mixed case).
        Map<String, Object> mixed = signatureOf(DssJsonApi.validate(signature,
                "{\"detached_contents\":[{\"name\":\"other\",\"base64\":\"AQID\"}]}",
                List.of(content(null, content))));
        assertEquals("CAdES-BASELINE-B", mixed.get("format"));

        // The refusals the entry point leaves to the engine, with the messages docs/native-library.md lists.
        assertEquals("contents[1] is empty", errorMessage(DssJsonApi.validate(signature, null,
                List.of(content("a", content), content(null, new byte[0])))));
        assertEquals("contents[0] is NULL",
                errorMessage(DssJsonApi.validate(signature, null, Collections.singletonList(null))));
        assertTrue(errorMessage(DssJsonApi.validate(signature, "{bad json", List.of(content("a", content))))
                .startsWith("options_json is not valid JSON"));
        assertEquals("options: 'detached_contents' must be an array of objects", errorMessage(
                DssJsonApi.validate(signature, "{\"detached_contents\":1}", List.of(content("a", content)))));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> signatureOf(String resultJson) {
        Map<String, Object> r = Json.parseObject(resultJson);
        assertEquals(Boolean.TRUE, r.get("ok"), resultJson);
        List<Map<String, Object>> signatures = (List<Map<String, Object>>) r.get("signatures");
        assertEquals(1, signatures.size(), resultJson);
        return signatures.get(0);
    }

    @SuppressWarnings("unchecked")
    private static String errorMessage(String json) {
        Map<String, Object> m = Json.parseObject(json);
        assertEquals(Boolean.FALSE, m.get("ok"), json);
        Map<String, Object> error = (Map<String, Object>) m.get("error");
        assertEquals("INVALID_ARGUMENT", error.get("code"), json);
        return (String) error.get("message");
    }
}
