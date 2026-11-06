/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateEncodingException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;

import it.codingduck.dssnative.testsupport.ExternalSigner;
import it.codingduck.dssnative.testsupport.ExternalSigner.Cms;
import it.codingduck.dssnative.testsupport.Fixtures;
import it.codingduck.dssnative.testsupport.TestEngines;
import it.codingduck.dssnative.testsupport.TestImages;
import it.codingduck.dssnative.testsupport.TestPki.Entity;
import it.codingduck.dssnative.visible.Appearance;

/**
 * Visible signatures ({@code pades.visible}). Every appearance is signed through prepare and complete, and the
 * result validated again and opened to check the widget. Signed PDFs are also written to {@code target/visible/}
 * for a look.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class VisibleSignatureTest {

    private static final String PASSED = "TOTAL_PASSED/-";
    private static final String TIME = "\"signing_time\":\"2026-06-01T10:00:00Z\"";
    private static final String BOX = "\"page\":1,\"x\":300,\"y\":650,\"width\":240,\"height\":80";

    private TestEngines t;
    private DssEngine engine;
    /** A second engine: what prepare builds must not depend on the engine (or process) it runs in. */
    private DssEngine other;
    private ExternalSigner rsa;
    private byte[] pdf;
    private String png;

    @BeforeAll
    void setUp(@TempDir Path tmp) {
        t = new TestEngines(tmp);
        engine = t.onlineLoaded(tmp.resolve("cache"), TestEngines.tsa());
        other = t.engine(tmp.resolve("cache-other"), null);
        rsa = new ExternalSigner(t.pki, Entity.SIGNER_RSA);
        pdf = Fixtures.read("content/document.pdf");
        png = b64(TestImages.png(160, 80, 6, 8, false));
    }

    @AfterAll
    void tearDown() {
        engine.close();
        other.close();
    }

    // ------------------------------------------------------------------ helpers

    private static String b64(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }

    private String certificate() {
        try {
            return b64(t.pki.x509(Entity.SIGNER_RSA).getEncoded());
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Mode cms, level B, a fixed time, and {@code "pades":{<pades>}}. */
    private static SigningOptions options(String pades) {
        return SigningOptions.fromJson("{\"mode\":\"cms\",\"level\":\"B\"," + TIME + ",\"pades\":{" + pades + "}}");
    }

    /** prepare, sign, complete, validate again; returns the signed PDF. */
    private byte[] sign(byte[] document, SigningOptions o, String name) {
        PreparedSignature prepared = engine.prepareSignature(document, o);
        byte[] external = o.mode == SigningOptions.Mode.CMS
                ? rsa.cms(prepared.digestAlgorithm(), prepared.digest(), EnumSet.noneOf(Cms.class))
                : rsa.signatureValue(prepared.digestAlgorithm(), prepared.digest(), false);
        SigningResult r = engine.completeSignature(document, o.withSigningTime(prepared.signingTime()), external);
        ValidationResult v = engine.validate(r.document(), new ValidationOptions(null, List.of(), null, null, false));
        assertEquals(List.of(PASSED), FixtureValidationTest.verdicts(v), () -> v.reports.get(ReportKind.SIMPLE));
        keep(name, r.document());
        return r.document();
    }

    /** For a look at the result; best effort (target/ may not be writable where the native tests run). */
    private static void keep(String name, byte[] signed) {
        try {
            Path dir = Path.of("target", "visible");
            Files.createDirectories(dir);
            Files.write(dir.resolve(name + ".pdf"), signed);
        } catch (IOException | RuntimeException e) {
            // not needed for the test
        }
    }

    /** The widget of the signed field: its rectangle and that it has a normal appearance. */
    private static PDRectangle signedWidget(byte[] signed, String field) throws IOException {
        try (PDDocument doc = Loader.loadPDF(signed)) {
            PDSignatureField sig = null;
            for (PDField f : doc.getDocumentCatalog().getAcroForm().getFieldTree()) {
                if (f instanceof PDSignatureField s && s.getSignature() != null
                        && (field == null || field.equals(f.getFullyQualifiedName()))) {
                    sig = s;
                }
            }
            assertNotNull(sig, "a signed field");
            PDAnnotationWidget widget = sig.getWidgets().get(0);
            assertNotNull(widget.getAppearance().getNormalAppearance().getAppearanceStream(), "an appearance");
            assertFalse(doc.getDocumentCatalog().getOutputIntents().isEmpty(), "an output intent");
            return widget.getRectangle();
        }
    }

    private static void assertRect(PDRectangle r, float llx, float lly, float urx, float ury) {
        assertEquals(llx, r.getLowerLeftX(), 0.01, "llx");
        assertEquals(lly, r.getLowerLeftY(), 0.01, "lly");
        assertEquals(urx, r.getUpperRightX(), 0.01, "urx");
        assertEquals(ury, r.getUpperRightY(), 0.01, "ury");
    }

    private static DssError fails(DssError.Code code, Executable call) {
        DssError e = assertThrows(DssError.class, call);
        assertEquals(code, e.code(), e.getMessage());
        return e;
    }

    private static void assertMessage(DssError e, String part) {
        assertTrue(e.getMessage().contains(part), e.getMessage());
    }

    // ------------------------------------------------------------------ appearances

    @Test
    void textBesideATransparentPng() throws IOException {
        byte[] signed = sign(pdf, options("\"signer_name\":\"Mario Rossi\",\"visible\":{" + BOX + ",\"text\":"
                + "\"Firmato digitalmente da {signer_name}\\n{signing_time}\",\"image\":\"" + png + "\","
                + "\"background_color\":\"#F0F4FF\"}"), "png-left");
        // Letter page, 792 points high: y 650..730 from the top is 62..142 from the bottom.
        assertRect(signedWidget(signed, null), 300, 62, 540, 142);
    }

    @Test
    void everyImagePositionAndPngKind() {
        int[][] kinds = {{0, 8}, {2, 16}, {3, 4}, {4, 8}, {6, 16}};
        int i = 0;
        for (String position : List.of("left", "right", "top", "bottom", "behind")) {
            int[] kind = kinds[i++];
            String image = b64(TestImages.png(90, 60, kind[0], kind[1], true));
            sign(pdf, options("\"signer_name\":\"Mario Rossi\",\"visible\":{" + BOX + ",\"text\":\"{signer_name}\","
                    + "\"image\":\"" + image + "\",\"image_position\":\"" + position + "\",\"text_align\":\"center\"}"),
                    "position-" + position);
        }
    }

    @Test
    void jpegAndTheCallersFontAndColours() {
        sign(pdf, options("\"signer_name\":\"Giulia Bianchi\",\"reason\":\"Approvazione\",\"visible\":{" + BOX
                + ",\"text\":\"{signer_name} — {reason}\",\"font\":\"" + b64(TestImages.liberationSans()) + "\","
                + "\"font_size\":14,\"text_color\":\"#1A3C8C\",\"text_align\":\"right\",\"image\":\""
                + b64(Fixtures.read("content/stamp.jpg")) + "\",\"image_position\":\"top\"}"), "jpeg-font");
    }

    @Test
    void anImageAloneOrTextAlone() {
        sign(pdf, options("\"visible\":{" + BOX + ",\"image\":\"" + png + "\"}"), "image-only");
        sign(pdf, options("\"visible\":{" + BOX + ",\"text\":\"Approvato\"}"), "text-only");
    }

    @Test
    void longTextShrinksAndWraps() {
        String words = "Documento firmato digitalmente ai sensi del D.Lgs. 82/2005 e norme collegate. ".repeat(4);
        sign(pdf, options("\"visible\":{\"page\":1,\"x\":36,\"y\":400,\"width\":180,\"height\":50,\"text\":\""
                + words.trim() + "\",\"font_size\":12}"), "long-text");
    }

    @Test
    void anExistingEmptySignatureField() throws IOException {
        byte[] form = Fixtures.read("content/form.pdf");
        SigningOptions o = SigningOptions.fromJson("{\"mode\":\"signature_value\",\"level\":\"B\"," + TIME
                + ",\"signing_certificate\":\"" + certificate() + "\",\"pades\":{\"visible\":{\"field\":\"Firma1\","
                + "\"text\":\"{signer_name}\\n{signing_time}\",\"time_zone\":\"Europe/Rome\"}}}");
        byte[] signed = sign(form, o, "existing-field");
        assertRect(signedWidget(signed, "Firma1"), 350, 80, 550, 140); // the field keeps its rectangle
    }

    @Test
    void aRotatedPageGetsAnUprightBoxWhereTheCallerSeesIt() throws IOException {
        // A4 turned by /Rotate 90: 842 x 595 points as displayed. The box at (20, 20) from the displayed top-left
        // is, in user space (unrotated, origin bottom-left), 20..80 across and 20..220 up.
        byte[] signed = sign(Fixtures.read("content/rotated.pdf"), options("\"signer_name\":\"Mario Rossi\","
                + "\"visible\":{\"page\":1,\"x\":20,\"y\":20,\"width\":200,\"height\":60,\"text\":\"{signer_name}\\n"
                + "{signing_time}\",\"image\":\"" + png + "\"}"), "rotated");
        assertRect(signedWidget(signed, null), 20, 20, 80, 220);
    }

    @Test
    void anOwnerPasswordProtectedPdf() {
        byte[] protectedPdf = Fixtures.read("content/protected.pdf");
        SigningOptions o = options("\"signer_name\":\"Mario Rossi\",\"visible\":{" + BOX + ",\"text\":\"{signer_name}\","
                + "\"image\":\"" + png + "\"}");
        // The encryption of the new revision is seeded from the parameters: it must not differ between engines.
        assertArrayEquals(engine.prepareSignature(protectedPdf, o).digest(),
                other.prepareSignature(protectedPdf, o).digest());
        sign(protectedPdf, o, "protected");
    }

    // ------------------------------------------------------------------ determinism

    @Test
    void preparingIsRepeatableAndFollowsTheAppearance() {
        String base = BOX + ",\"text\":\"{signer_name}\\n{signing_time}\",\"image\":\"" + png + "\"";
        SigningOptions o = options("\"signer_name\":\"Mario Rossi\",\"visible\":{" + base + "}");
        byte[] a = engine.prepareSignature(pdf, o).digest();
        assertArrayEquals(a, other.prepareSignature(pdf, o).digest(), "same document and options, same digest");
        TimeZone host = TimeZone.getDefault();
        try {
            TimeZone.setDefault(TimeZone.getTimeZone("Pacific/Kiritimati"));
            assertArrayEquals(a, engine.prepareSignature(pdf, o).digest(), "whatever the host's time zone");
        } finally {
            TimeZone.setDefault(host);
        }
        for (String changed : List.of(BOX + ",\"text\":\"{signer_name}\",\"image\":\"" + png + "\"",
                base + ",\"text_color\":\"#FF0000\"", base + ",\"image_position\":\"right\"",
                base + ",\"font_size\":9", base.replace("\"x\":300", "\"x\":301"))) {
            SigningOptions c = options("\"signer_name\":\"Mario Rossi\",\"visible\":{" + changed + "}");
            assertFalse(Arrays.equals(a, engine.prepareSignature(pdf, c).digest()), changed);
        }
        SigningOptions invisible = options("\"signer_name\":\"Mario Rossi\"");
        assertFalse(Arrays.equals(a, engine.prepareSignature(pdf, invisible).digest()));
    }

    // ------------------------------------------------------------------ placeholders

    private static Appearance appearance(String visible, String signerName, String reason) {
        VisibleSignature v = VisibleSignature.fromJson(new JsonFields(Json.parseObject(visible), "options.pades.visible",
                DssError.Code.INVALID_ARGUMENT));
        return v.appearance(signerName, reason, null, null, Instant.parse("2026-06-01T10:00:00Z"));
    }

    @Test
    void placeholdersAreFilledIn() {
        assertEquals("Mario Rossi, 2026-06-01 10:00:00 +00:00", appearance("{" + BOX + ",\"text\":"
                + "\"{signer_name}, {signing_time}\"}", "Mario Rossi", null).text());
        assertEquals("01/06/2026 12:00 CEST", appearance("{" + BOX + ",\"text\":\"{signing_time}\",\"time_zone\":"
                + "\"Europe/Rome\",\"date_format\":\"dd/MM/yyyy HH:mm z\"}", null, null).text());
        assertEquals("{literal} Approved", appearance("{" + BOX + ",\"text\":\"{{literal}} {reason}\"}", null,
                "Approved").text());
        assertEquals("Line 1\nLine 2  tab", appearance("{" + BOX + ",\"text\":\"Line 1\\r\\nLine 2\\t tab\"}", null,
                null).text());
    }

    @Test
    void theSignerNameFallsBackToTheCertificate() {
        SigningOptions o = SigningOptions.fromJson("{\"mode\":\"cms\",\"level\":\"B\"," + TIME
                + ",\"signing_certificate\":\"" + certificate() + "\",\"pades\":{\"visible\":{" + BOX
                + ",\"text\":\"{signer_name}\"}}}");
        String cn = t.pki.token(Entity.SIGNER_RSA).getSubject().getPrincipal().getName();
        Appearance a = o.visible.appearance(null, null, null, o.signingCertificate, o.signingTime);
        assertTrue(cn.contains("CN=" + a.text()), cn + " / " + a.text());
        sign(pdf, o, "signer-from-certificate");

        DssError e = fails(DssError.Code.INVALID_ARGUMENT, () -> engine.prepareSignature(pdf,
                options("\"visible\":{" + BOX + ",\"text\":\"{signer_name}\"}")));
        assertMessage(e, "'{signer_name}' needs 'pades.signer_name'");
        e = fails(DssError.Code.INVALID_ARGUMENT, () -> engine.prepareSignature(pdf,
                options("\"visible\":{" + BOX + ",\"text\":\"{location}\"}")));
        assertMessage(e, "'{location}' needs 'pades.location'");
    }

    // ------------------------------------------------------------------ refusals

    @Test
    void badOptionsAreRefusedBeforeAnythingIsSigned() {
        Map<String, String> cases = new LinkedHashMap<>();
        cases.put("{\"field\":\"Firma1\"," + BOX + ",\"text\":\"x\"}", "either 'field'");
        cases.put("{\"text\":\"x\"}", "'page' is required");
        cases.put("{\"page\":1,\"x\":0,\"y\":0,\"width\":0,\"height\":10,\"text\":\"x\"}", "'width' and 'height'");
        cases.put("{\"page\":0,\"x\":0,\"y\":0,\"width\":10,\"height\":10,\"text\":\"x\"}", "'page' must be 1");
        cases.put("{" + BOX + "}", "give 'text', 'image' or both");
        cases.put("{" + BOX + ",\"text\":\"  \"}", "'text' is empty");
        cases.put("{" + BOX + ",\"text\":\"x\",\"text_color\":\"red\"}", "#RRGGBB");
        cases.put("{" + BOX + ",\"text\":\"x\",\"text_align\":\"justify\"}", "'text_align' must be one of");
        cases.put("{" + BOX + ",\"image\":\"" + png + "\",\"image_position\":\"under\"}", "'image_position'");
        cases.put("{" + BOX + ",\"image\":\"bm90IGFuIGltYWdl\"}", "neither a PNG nor a JPEG");
        cases.put("{" + BOX + ",\"image\":\"!!\"}", "not base64");
        cases.put("{" + BOX + ",\"text\":\"x\",\"font\":\"bm90IGEgZm9udA==\"}", "not a usable TrueType font");
        cases.put("{" + BOX + ",\"image\":\"" + png + "\",\"font\":\"bm90IGEgZm9udA==\"}", "'font' needs 'text'");
        cases.put("{" + BOX + ",\"text\":\"x\",\"font_size\":1}", "'font_size' must be between");
        cases.put("{" + BOX + ",\"text\":\"{name}\"}", "unknown placeholder '{name}'");
        cases.put("{" + BOX + ",\"text\":\"{signer_name\"}", "'{' without '}'");
        cases.put("{" + BOX + ",\"text\":\"a } b\"}", "'}' without '{'");
        cases.put("{" + BOX + ",\"text\":\"x\",\"time_zone\":\"Mars/Olympus\"}", "'time_zone'");
        cases.put("{" + BOX + ",\"text\":\"x\",\"date_format\":\"yyyy-bb\"}", "'date_format'");
        cases.put("{" + BOX + ",\"text\":\"x\",\"rotation\":90}", "unknown key 'rotation'");
        for (Map.Entry<String, String> c : cases.entrySet()) {
            DssError e = fails(DssError.Code.INVALID_ARGUMENT, () -> options("\"visible\":" + c.getKey()));
            assertMessage(e, c.getValue());
        }
        DssError e = fails(DssError.Code.INVALID_ARGUMENT, () -> SigningOptions.fromJson("{\"mode\":\"cms\","
                + "\"level\":\"B\",\"format\":\"CAdES\",\"pades\":{\"visible\":{" + BOX + ",\"text\":\"x\"}}}"));
        assertMessage(e, "'pades' applies to PAdES only");
        e = fails(DssError.Code.INVALID_ARGUMENT, () -> engine.prepareSignature(Fixtures.read("content/document.txt"),
                options("\"visible\":{" + BOX + ",\"text\":\"x\"}")));
        assertMessage(e, "'pades' applies to PAdES only");
    }

    @Test
    void placementsThatDoNotFitTheDocumentAreRefused() {
        byte[] form = Fixtures.read("content/form.pdf");
        Map<String, String> cases = new LinkedHashMap<>();
        cases.put("{\"page\":2,\"x\":0,\"y\":0,\"width\":10,\"height\":10,\"text\":\"x\"}", "page 2 does not exist");
        cases.put("{\"page\":1,\"x\":500,\"y\":700,\"width\":200,\"height\":50,\"text\":\"x\"}", "is not inside page 1");
        cases.put("{\"page\":1,\"x\":360,\"y\":660,\"width\":100,\"height\":40,\"text\":\"x\"}", "overlaps");
        cases.put("{\"field\":\"Firma9\",\"text\":\"x\"}", "no field 'Firma9' (empty signature fields: Firma1)");
        cases.put("{\"field\":\"Nome\",\"text\":\"x\"}", "'Nome' is not a signature field");
        cases.put("{\"page\":1,\"x\":36,\"y\":36,\"width\":30,\"height\":8,\"text\":\"" + "parola ".repeat(30)
                + "\"}", "does not fit in the box");
        cases.put("{\"page\":1,\"x\":36,\"y\":36,\"width\":100,\"height\":40,\"text\":\"漢字\"}",
                "the font cannot show the text");
        for (Map.Entry<String, String> c : cases.entrySet()) {
            DssError e = fails(DssError.Code.INVALID_ARGUMENT, () -> engine.prepareSignature(form,
                    options("\"visible\":" + c.getKey())));
            assertMessage(e, c.getValue());
        }
        byte[] signed = sign(form, options("\"visible\":{\"field\":\"Firma1\",\"text\":\"Primo\"}"), "field-once");
        DssError e = fails(DssError.Code.INVALID_ARGUMENT, () -> engine.prepareSignature(signed,
                options("\"visible\":{\"field\":\"Firma1\",\"text\":\"Secondo\"}")));
        assertMessage(e, "'Firma1' is already signed");
    }
}
