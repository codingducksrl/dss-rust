/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.visible;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.function.Consumer;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.encryption.AccessPermission;
import org.apache.pdfbox.pdmodel.encryption.StandardProtectionPolicy;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledInNativeImage;

import it.codingduck.dssnative.engine.DssError;
import it.codingduck.dssnative.testsupport.Fixtures;
import it.codingduck.dssnative.visible.Appearance.ImagePosition;
import it.codingduck.dssnative.visible.Appearance.TextAlign;

/**
 * {@link Placement}: the caller's box (from the top-left of the page as displayed) mapped to user space for
 * every page rotation and an offset crop box, and the checks on existing fields and pages.
 */
class PlacementTest {

    /** A box at (10, 20) of 100 x 30 points as displayed. */
    private static final float X = 10;
    private static final float Y = 20;
    private static final float W = 100;
    private static final float H = 30;

    private static Appearance newField(int page, float x, float y, float w, float h) {
        return new Appearance(null, page, x, y, w, h, "x", null, 10, 0, TextAlign.LEFT, null, null,
                ImagePosition.LEFT);
    }

    private static Appearance existingField(String name) {
        return new Appearance(name, 0, 0, 0, 0, 0, "x", null, 10, 0, TextAlign.LEFT, null, null,
                ImagePosition.LEFT);
    }

    /** An A4 page whose crop box is 400 x 600 at (50, 100) in a 595 x 842 media box, turned by {@code rotate}. */
    private static byte[] croppedPage(int rotate) throws IOException {
        try (PDDocument doc = new PDDocument()) {
            PDPage page = new PDPage(new PDRectangle(0, 0, 595, 842));
            page.setCropBox(new PDRectangle(50, 100, 400, 600));
            page.setRotation(rotate);
            doc.addPage(page);
            return save(doc);
        }
    }

    private static byte[] save(PDDocument doc) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        doc.save(out);
        return out.toByteArray();
    }

    private static void assertPlacement(Placement p, float llx, float lly, float urx, float ury, int rotation) {
        assertEquals(llx, p.llx(), 0.001, "llx");
        assertEquals(lly, p.lly(), 0.001, "lly");
        assertEquals(urx, p.urx(), 0.001, "urx");
        assertEquals(ury, p.ury(), 0.001, "ury");
        assertEquals(rotation, p.rotation(), "rotation");
    }

    private static DssError invalid(byte[] pdf, Appearance a, String message) {
        DssError e = assertThrows(DssError.class, () -> Placement.resolve(pdf, a));
        assertEquals(DssError.Code.INVALID_ARGUMENT, e.code(), e.getMessage());
        assertTrue(e.getMessage().contains(message), e.getMessage());
        return e;
    }

    // ------------------------------------------------------------------ rotation and crop

    @Test
    void everyRotationWithAnOffsetCropBox() throws IOException {
        // The crop box spans x 50..450 and y 100..700 in user space; the displayed page is 400 x 600 upright
        // (rotation 0, 180) and 600 x 400 turned (90, 270). The box's corners follow Placement.toUserSpace.
        assertPlacement(Placement.resolve(croppedPage(0), newField(1, X, Y, W, H)), 60, 650, 160, 680, 0);
        assertPlacement(Placement.resolve(croppedPage(90), newField(1, X, Y, W, H)), 70, 110, 100, 210, 90);
        assertPlacement(Placement.resolve(croppedPage(180), newField(1, X, Y, W, H)), 340, 120, 440, 150, 180);
        assertPlacement(Placement.resolve(croppedPage(270), newField(1, X, Y, W, H)), 400, 590, 430, 690, 270);
        // /Rotate is normalised: -90 is 270, 450 is 90, and anything but a multiple of 90 is rounded down
        assertPlacement(Placement.resolve(croppedPage(-90), newField(1, X, Y, W, H)), 400, 590, 430, 690, 270);
        assertPlacement(Placement.resolve(croppedPage(450), newField(1, X, Y, W, H)), 70, 110, 100, 210, 90);
        assertPlacement(Placement.resolve(croppedPage(45), newField(1, X, Y, W, H)), 60, 650, 160, 680, 0);
        // the displayed size is what the box is checked against: 600 x 400 when turned a quarter
        assertPlacement(Placement.resolve(croppedPage(90), newField(1, 500, 370, 100, 30)), 420, 600, 450, 700, 90);
        invalid(croppedPage(0), newField(1, 500, 370, 100, 30), "is not inside page 1, which is 400 x 600");
        invalid(croppedPage(90), newField(1, 0, 380, 100, 30), "is not inside page 1, which is 600 x 400");
    }

    // ------------------------------------------------------------------ existing fields

    /** {@code content/form.pdf} with its page turned by {@code rotate} and {@code change} applied to Firma1. */
    private static byte[] form(int rotate, Consumer<PDAnnotationWidget> change) throws IOException {
        try (PDDocument doc = Loader.loadPDF(Fixtures.read("content/form.pdf"))) {
            doc.getPage(0).setRotation(rotate);
            PDSignatureField field = (PDSignatureField) doc.getDocumentCatalog().getAcroForm().getField("Firma1");
            change.accept(field.getWidgets().get(0));
            return save(doc);
        }
    }

    @Test
    void aNoRotateFieldIsDrawnUprightWhateverThePageRotation() throws IOException {
        assertEquals(90, Placement.resolve(form(90, w -> { }), existingField("Firma1")).rotation());
        Placement noRotate = Placement.resolve(form(90, w -> w.setNoRotate(true)), existingField("Firma1"));
        assertEquals(0, noRotate.rotation(), "a NoRotate widget is displayed upright: nothing to undo");
        assertPlacement(noRotate, 350, 80, 550, 140, 0); // the field keeps its rectangle
    }

    @Test
    void hiddenAndNoViewFieldsAreRefused() throws IOException {
        invalid(form(0, w -> w.setHidden(true)), existingField("Firma1"), "'Firma1' is flagged Hidden");
        invalid(form(0, w -> w.setNoView(true)), existingField("Firma1"), "'Firma1' is flagged NoView");
        assertEquals(1, Placement.resolve(form(0, w -> w.setPrinted(true)), existingField("Firma1")).page());
    }

    // ------------------------------------------------------------------ pages

    @Test
    void aPageTreeCountThatOverstatesThePagesIsNotTrusted() throws IOException {
        byte[] pdf;
        try (PDDocument doc = Loader.loadPDF(Fixtures.read("content/form.pdf"))) {
            doc.getPages().getCOSObject().setInt(COSName.COUNT, 3);
            pdf = save(doc);
        }
        try (PDDocument doc = Loader.loadPDF(pdf)) {
            assertEquals(3, doc.getNumberOfPages(), "the fixture declares three pages");
        }
        invalid(pdf, newField(2, X, Y, W, H), "page 2 does not exist: the document has 1 page");
        invalid(pdf, newField(4, X, Y, W, H), "page 4 does not exist: the document has 1 page");
        assertEquals(1, Placement.resolve(pdf, newField(1, X, Y, W, H)).page());
    }

    /**
     * PDFBox reaches a page by index through the tree's {@code /Count}, and the drawer and DSS do so too: a
     * page beyond an understated count is refused for what it is, not as a page that does not exist.
     */
    @Test
    void aPageTreeCountThatUnderstatesThePagesIsReportedAsSuch() throws IOException {
        byte[] pdf;
        try (PDDocument doc = new PDDocument()) {
            for (int i = 0; i < 3; i++) {
                doc.addPage(new PDPage(PDRectangle.A4));
            }
            doc.getPages().getCOSObject().setInt(COSName.COUNT, 1);
            pdf = save(doc);
        }
        try (PDDocument doc = Loader.loadPDF(pdf)) {
            assertEquals(1, doc.getNumberOfPages(), "the document declares one page");
        }
        assertEquals(1, Placement.resolve(pdf, newField(1, X, Y, W, H)).page());
        invalid(pdf, newField(2, X, Y, W, H),
                "page 2 cannot be reached: the PDF's page tree announces 1 page but holds 3; repair the PDF");
        invalid(pdf, newField(3, X, Y, W, H), "page 3 cannot be reached");
        invalid(pdf, newField(4, X, Y, W, H), "page 4 does not exist: the document has 3 pages");
        // an existing field on such a page is refused the same way
        byte[] form;
        try (PDDocument doc = Loader.loadPDF(Fixtures.read("content/form.pdf"))) {
            doc.getPages().getCOSObject().setInt(COSName.COUNT, 0);
            form = save(doc);
        }
        invalid(form, existingField("Firma1"),
                "page 1 cannot be reached: the PDF's page tree announces 0 pages but holds 1");
    }

    @Test
    @DisabledInNativeImage // encrypting needs PDFBox's protection policy, which the native test image lacks
    void aUserPasswordIsReportedAsUnsupported() throws IOException {
        byte[] pdf;
        try (PDDocument doc = Loader.loadPDF(Fixtures.read("content/document.pdf"))) {
            doc.protect(new StandardProtectionPolicy("owner-secret", "user-secret", new AccessPermission()));
            pdf = save(doc);
        }
        DssError e = assertThrows(DssError.class, () -> Placement.resolve(pdf, newField(1, X, Y, W, H)));
        assertEquals(DssError.Code.UNSUPPORTED_DOCUMENT, e.code(), e.getMessage());
        assertTrue(e.getMessage().contains("encrypted with a user password"), e.getMessage());
    }
}
