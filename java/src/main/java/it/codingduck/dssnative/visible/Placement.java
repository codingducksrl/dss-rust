/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.visible;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.encryption.InvalidPasswordException;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;

import it.codingduck.dssnative.engine.DssError;

/**
 * Where a visible signature goes in a given PDF: its page and its rectangle in the page's user space, plus the
 * page rotation the appearance must undo to read upright. Resolved before DSS runs, so that a wrong page or
 * field fails with the caller's terms, and so that DSS gets the field's page (it otherwise assumes page 1).
 *
 * @param page     1-based
 * @param field    the existing field to fill, or null for a new one
 * @param rotation the page's {@code /Rotate}, normalised to 0, 90, 180 or 270 (0 for a {@code NoRotate} field)
 */
public record Placement(int page, String field, float llx, float lly, float urx, float ury, int rotation) {

    /** Room for rounding in the caller's coordinates before a box counts as outside the page. */
    private static final float TOLERANCE = 0.01f;

    float width() {
        return urx - llx;
    }

    float height() {
        return ury - lly;
    }

    /** Width as displayed: the user-space height when the page is turned a quarter. */
    float displayWidth() {
        return rotation == 90 || rotation == 270 ? height() : width();
    }

    float displayHeight() {
        return rotation == 90 || rotation == 270 ? width() : height();
    }

    static Placement resolve(byte[] pdf, Appearance a) {
        try (PDDocument document = Loader.loadPDF(pdf)) {
            return a.field() != null ? existingField(document, a.field()) : newField(document, a);
        } catch (InvalidPasswordException e) {
            throw new DssError(DssError.Code.UNSUPPORTED_DOCUMENT, "the PDF is encrypted with a user password, "
                    + "which is not supported: remove the password before signing it", e);
        } catch (IOException e) {
            throw new DssError(DssError.Code.UNSUPPORTED_DOCUMENT, "cannot read the PDF: " + e.getMessage(), e);
        }
    }

    private static Placement newField(PDDocument document, Appearance a) {
        PDPage page = pageOrNull(document, a.page());
        if (page == null) {
            throw missingPage(document, a.page());
        }
        int rotation = rotation(page);
        PDRectangle crop = visibleBox(page);
        boolean quarter = rotation == 90 || rotation == 270;
        float pageWidth = quarter ? crop.getHeight() : crop.getWidth();
        float pageHeight = quarter ? crop.getWidth() : crop.getHeight();
        if (a.x() < -TOLERANCE || a.y() < -TOLERANCE || a.x() + a.width() > pageWidth + TOLERANCE
                || a.y() + a.height() > pageHeight + TOLERANCE) {
            throw invalid(String.format(Locale.ROOT, "the box (x %s, y %s, width %s, height %s) is not "
                    + "inside page %d, which is %s x %s points as displayed", fmt(a.x()), fmt(a.y()),
                    fmt(a.width()), fmt(a.height()), a.page(), fmt(pageWidth), fmt(pageHeight)));
        }
        // Two corners of the box, from displayed coordinates (top-left origin, y down) to user space.
        float[] p1 = toUserSpace(crop, rotation, a.x(), a.y());
        float[] p2 = toUserSpace(crop, rotation, a.x() + a.width(), a.y() + a.height());
        return new Placement(a.page(), null, Math.min(p1[0], p2[0]), Math.min(p1[1], p2[1]),
                Math.max(p1[0], p2[0]), Math.max(p1[1], p2[1]), rotation);
    }

    private static Placement existingField(PDDocument document, String name) {
        PDAcroForm acroForm = document.getDocumentCatalog().getAcroForm(null);
        PDField field = acroForm != null ? acroForm.getField(name) : null;
        if (field == null) {
            List<String> empty = acroForm == null ? List.of() : emptySignatureFields(acroForm);
            throw invalid("the PDF has no field '" + name + "'" + (empty.isEmpty()
                    ? " (it has no empty signature field)" : " (empty signature fields: " + String.join(", ", empty)
                    + ")"));
        }
        if (!(field instanceof PDSignatureField signatureField)) {
            throw invalid("the field '" + name + "' is not a signature field");
        }
        if (signatureField.getSignature() != null) {
            throw invalid("the signature field '" + name + "' is already signed");
        }
        List<PDAnnotationWidget> widgets = signatureField.getWidgets();
        if (widgets.isEmpty() || widgets.get(0).getRectangle() == null) {
            throw invalid("the signature field '" + name + "' has no widget to draw in");
        }
        PDAnnotationWidget widget = widgets.get(0);
        Located located = locate(document, widget);
        if (located == null) {
            throw invalid("the signature field '" + name + "' is on no page");
        }
        int page = located.number();
        if (pageOrNull(document, page) == null) {
            throw missingPage(document, page); // the drawer and DSS reach the page by its index
        }
        PDRectangle r = widget.getRectangle();
        if (r.getWidth() <= 0 || r.getHeight() <= 0) {
            throw invalid("the signature field '" + name + "' has an empty rectangle: it is an invisible field");
        }
        // PDFBox keeps the widget's flags when it signs the field (it only sets Print), so an appearance drawn
        // into a Hidden or NoView widget would never be displayed.
        if (widget.isHidden() || widget.isNoView()) {
            throw invalid("the signature field '" + name + "' is flagged " + (widget.isHidden() ? "Hidden"
                    : "NoView") + ": its appearance would not be displayed");
        }
        // A NoRotate widget is displayed upright whatever the page's /Rotate, so there is nothing to undo.
        int rotation = widget.isNoRotate() ? 0 : rotation(located.page());
        return new Placement(page, name, r.getLowerLeftX(), r.getLowerLeftY(), r.getUpperRightX(),
                r.getUpperRightY(), rotation);
    }

    /**
     * The page by its index, the way PDFBox (the drawer and DSS) reaches it, or null when it cannot:
     * {@link #missingPage} says why.
     */
    private static PDPage pageOrNull(PDDocument document, int page) {
        if (page < 1 || page > document.getNumberOfPages()) {
            return null;
        }
        try {
            return document.getPage(page - 1);
        } catch (IllegalStateException | IndexOutOfBoundsException e) {
            return null;
        }
    }

    /**
     * Why {@code page} cannot be used. {@code getNumberOfPages()} is the page tree's {@code /Count}, which a
     * damaged PDF may overstate (the page does not exist) or understate (the page is there, but PDFBox does
     * not look past the count, so neither the drawer nor DSS could reach it); only walking the tree tells.
     */
    private static DssError missingPage(PDDocument document, int page) {
        int pages = countPages(document);
        if (page >= 1 && page <= pages) {
            int announced = document.getNumberOfPages();
            return invalid("page " + page + " cannot be reached: the PDF's page tree announces " + announced
                    + " page" + (announced == 1 ? "" : "s") + " but holds " + pages + "; repair the PDF before "
                    + "signing it");
        }
        return invalid("page " + page + " does not exist: the document has " + pages + " page"
                + (pages == 1 ? "" : "s"));
    }

    private static int countPages(PDDocument document) {
        int n = 0;
        for (PDPage ignored : document.getPages()) {
            n++;
        }
        return n;
    }

    private static List<String> emptySignatureFields(PDAcroForm acroForm) {
        List<String> names = new ArrayList<>();
        for (PDField f : acroForm.getFieldTree()) {
            if (f instanceof PDSignatureField s && s.getSignature() == null) {
                names.add(f.getFullyQualifiedName());
            }
        }
        return names;
    }

    /** A page found by walking the tree, with its 1-based number. */
    private record Located(int number, PDPage page) {
    }

    /**
     * The widget's page from its {@code /P} entry, else by looking for it among each page's annotations; null
     * when it is on none.
     */
    private static Located locate(PDDocument document, PDAnnotationWidget widget) {
        COSDictionary target = widget.getCOSObject();
        PDPage declared = widget.getPage();
        if (declared != null) {
            int index = document.getPages().indexOf(declared);
            if (index >= 0) {
                return new Located(index + 1, declared);
            }
        }
        int n = 1;
        for (PDPage page : document.getPages()) {
            try {
                for (PDAnnotation annotation : page.getAnnotations()) {
                    if (annotation.getCOSObject() == target) {
                        return new Located(n, page);
                    }
                }
            } catch (IOException e) {
                // an unreadable annotation array: not this page
            }
            n++;
        }
        return null;
    }

    /** What viewers show: the crop box, clipped to the media box. */
    private static PDRectangle visibleBox(PDPage page) {
        PDRectangle crop = page.getCropBox();
        PDRectangle media = page.getMediaBox();
        float llx = Math.max(crop.getLowerLeftX(), media.getLowerLeftX());
        float lly = Math.max(crop.getLowerLeftY(), media.getLowerLeftY());
        float urx = Math.min(crop.getUpperRightX(), media.getUpperRightX());
        float ury = Math.min(crop.getUpperRightY(), media.getUpperRightY());
        return new PDRectangle(llx, lly, urx - llx, ury - lly);
    }

    private static int rotation(PDPage page) {
        int r = Math.floorMod(page.getRotation(), 360);
        return r - r % 90; // viewers ignore anything but multiples of 90
    }

    /**
     * A point given from the top-left of the page as displayed, in the page's user space. The page is displayed
     * turned clockwise by {@code rotation}.
     */
    private static float[] toUserSpace(PDRectangle crop, int rotation, float dx, float dy) {
        float x0 = crop.getLowerLeftX();
        float y0 = crop.getLowerLeftY();
        float x1 = crop.getUpperRightX();
        float y1 = crop.getUpperRightY();
        return switch (rotation) {
            case 90 -> new float[] {x0 + dy, y0 + dx};
            case 180 -> new float[] {x1 - dx, y0 + dy};
            case 270 -> new float[] {x1 - dy, y1 - dx};
            default -> new float[] {x0 + dx, y1 - dy};
        };
    }

    private static String fmt(float v) {
        return v == Math.rint(v) ? Integer.toString((int) v) : Float.toString(v);
    }

    private static DssError invalid(String message) {
        return new DssError(DssError.Code.INVALID_ARGUMENT, "options: pades.visible: " + message);
    }
}
