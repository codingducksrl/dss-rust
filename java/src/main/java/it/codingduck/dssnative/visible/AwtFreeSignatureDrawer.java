/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.visible;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.common.PDStream;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDFontDescriptor;
import org.apache.pdfbox.pdmodel.font.PDType0Font;
import org.apache.pdfbox.pdmodel.graphics.color.PDColor;
import org.apache.pdfbox.pdmodel.graphics.color.PDDeviceGray;
import org.apache.pdfbox.pdmodel.graphics.color.PDDeviceRGB;
import org.apache.pdfbox.pdmodel.graphics.color.PDOutputIntent;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.apache.pdfbox.util.Matrix;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pdf.AnnotationBox;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxUtils;
import eu.europa.esig.dss.pdf.pdfbox.visible.PdfBoxSignatureDrawer;
import eu.europa.esig.dss.pdf.visible.SignatureFieldBoxBuilder;
import eu.europa.esig.dss.pdf.visible.SignatureFieldDimensionAndPosition;

import it.codingduck.dssnative.engine.DssError;
import it.codingduck.dssnative.visible.Appearance.ImagePosition;

/**
 * Draws a visible signature without AWT. DSS's {@code NativePdfBoxVisibleSignatureDrawer} reads images through
 * ImageIO and colour profiles through {@code java.awt.color.ICC_Profile}, which need native libraries the
 * shipped library does not have (DECISIONS.md, "Visible signatures"). This drawer does the same job with PDFBox
 * alone: images come from {@link SignatureImage}, the sRGB profile from {@link SrgbProfile}, text is measured
 * with the font's own metrics.
 *
 * <p>Like DSS's drawer, it builds the appearance in a one-page template document that PDFBox merges into the
 * signed PDF ({@link SignatureOptions#setVisualSignature}); DSS does the rest (field, checks, saving). Everything
 * drawn follows from the {@link Appearance} and the PDF, so prepare and complete draw the same bytes.
 *
 * <p>Layout, in the box as displayed: a {@value #PADDING}-point margin; an image beside the text takes at most
 * half the width (left/right) or height (top/bottom), keeping its aspect ratio; the text is vertically centred,
 * wrapped at spaces, and shrunk from {@code font_size} until it fits.
 */
final class AwtFreeSignatureDrawer implements PdfBoxSignatureDrawer, SignatureFieldBoxBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(AwtFreeSignatureDrawer.class);

    static final float PADDING = 3;
    /** The text never gets smaller than this; below it the box is reported as too small. */
    static final float MIN_FONT_SIZE = 3;
    private static final float SHRINK = 0.95f;
    private static final String DEFAULT_FONT = "/fonts/PTSerifRegular.ttf";

    private final Appearance appearance;
    private final Placement placement;
    private PDDocument document;
    private SignatureOptions signatureOptions;

    AwtFreeSignatureDrawer(VisibleImageParameters parameters) {
        this.appearance = parameters.appearance();
        this.placement = parameters.placement();
    }

    @Override
    public void init(SignatureImageParameters parameters, PDDocument document, SignatureOptions signatureOptions) {
        this.document = document;
        this.signatureOptions = signatureOptions;
        addOutputIntentIfMissing(document);
    }

    /** The box in DSS's terms, for its overlap check: offsets from the top-left of the media box. */
    @Override
    public SignatureFieldDimensionAndPosition buildSignatureFieldBox() {
        PDRectangle media = document.getPage(placement.page() - 1).getMediaBox();
        SignatureFieldDimensionAndPosition box = new SignatureFieldDimensionAndPosition(new AnnotationBox(
                media.getLowerLeftX(), media.getLowerLeftY(), media.getUpperRightX(), media.getUpperRightY()));
        box.setBoxX(placement.llx() - media.getLowerLeftX());
        box.setBoxY(media.getUpperRightY() - placement.ury());
        box.setBoxWidth(placement.width());
        box.setBoxHeight(placement.height());
        return box;
    }

    @Override
    public void draw() throws IOException {
        try (PDDocument template = new PDDocument()) {
            PDPage page = new PDPage(document.getPage(placement.page() - 1).getMediaBox());
            template.addPage(page);
            PDAcroForm acroForm = new PDAcroForm(template);
            template.getDocumentCatalog().setAcroForm(acroForm);
            PDSignatureField field = new PDSignatureField(acroForm);
            PDAnnotationWidget widget = field.getWidgets().get(0);
            acroForm.setSignaturesExist(true);
            acroForm.setAppendOnly(true);
            acroForm.getCOSObject().setDirect(true);
            acroForm.getFields().add(field);

            PDRectangle rectangle = new PDRectangle(placement.llx(), placement.lly(), placement.width(),
                    placement.height());
            widget.setRectangle(rectangle);
            PDAppearanceDictionary appearanceDictionary =
                    PdfBoxUtils.createSignatureAppearanceDictionary(template, rectangle);
            widget.setAppearance(appearanceDictionary);
            PDAppearanceStream stream = appearanceDictionary.getNormalAppearance().getAppearanceStream();

            // The font goes into the template, which subsets it when saved: only the glyphs drawn are embedded.
            PDFont font = appearance.text() != null ? loadFont(template) : null;
            Layout layout = layout(font);
            try (PDPageContentStream cs = new PDPageContentStream(template, stream)) {
                cs.transform(unrotate());
                if (appearance.backgroundColor() != null) {
                    cs.setNonStrokingColor(color(appearance.backgroundColor()));
                    cs.addRect(0, 0, placement.displayWidth(), placement.displayHeight());
                    cs.fill();
                }
                if (layout.image != null) {
                    cs.drawImage(appearance.image().toXObject(template), layout.image.x, layout.image.y,
                            layout.image.w, layout.image.h);
                }
                if (layout.text != null) {
                    drawText(cs, font, layout.text);
                }
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            template.save(out);
            signatureOptions.setVisualSignature(new ByteArrayInputStream(out.toByteArray()));
        }
    }

    // ------------------------------------------------------------------ layout

    private record Box(float x, float y, float w, float h) {
    }

    private record FittedText(List<String> lines, float size, float lineHeight, float firstBaseline,
                              Box area, PDFont font) {
    }

    private record Layout(Box image, FittedText text) {
    }

    /** Everything in the box's own coordinates as displayed: origin bottom-left, x right, y up. */
    private Layout layout(PDFont font) throws IOException {
        float width = placement.displayWidth();
        float height = placement.displayHeight();
        Box inner = new Box(PADDING, PADDING, width - 2 * PADDING, height - 2 * PADDING);
        if (inner.w <= 0 || inner.h <= 0) {
            throw tooSmall();
        }
        SignatureImage image = appearance.image();
        if (image == null) {
            return new Layout(null, fit(font, inner));
        }
        if (appearance.text() == null || appearance.imagePosition() == ImagePosition.BEHIND) {
            return new Layout(contain(image, inner), appearance.text() == null ? null : fit(font, inner));
        }
        float aspect = image.width() / (float) image.height();
        Box imageBox;
        Box textBox;
        switch (appearance.imagePosition()) {
            case LEFT, RIGHT -> {
                float h = inner.h;
                float w = h * aspect;
                if (w > inner.w / 2) {
                    w = inner.w / 2;
                    h = w / aspect;
                }
                float y = inner.y + (inner.h - h) / 2;
                float textWidth = inner.w - w - PADDING;
                boolean left = appearance.imagePosition() == ImagePosition.LEFT;
                imageBox = new Box(left ? inner.x : inner.x + inner.w - w, y, w, h);
                textBox = new Box(left ? inner.x + w + PADDING : inner.x, inner.y, textWidth, inner.h);
            }
            default -> { // TOP, BOTTOM
                float w = inner.w;
                float h = w / aspect;
                if (h > inner.h / 2) {
                    h = inner.h / 2;
                    w = h * aspect;
                }
                float x = inner.x + (inner.w - w) / 2;
                float textHeight = inner.h - h - PADDING;
                boolean top = appearance.imagePosition() == ImagePosition.TOP;
                imageBox = new Box(x, top ? inner.y + inner.h - h : inner.y, w, h);
                textBox = new Box(inner.x, top ? inner.y : inner.y + h + PADDING, inner.w, textHeight);
            }
        }
        if (textBox.w <= 0 || textBox.h <= 0) {
            throw tooSmall();
        }
        return new Layout(imageBox, fit(font, textBox));
    }

    /** The image scaled to fit {@code area}, keeping its aspect ratio, and centred in it. */
    private static Box contain(SignatureImage image, Box area) {
        float scale = Math.min(area.w / image.width(), area.h / image.height());
        float w = image.width() * scale;
        float h = image.height() * scale;
        return new Box(area.x + (area.w - w) / 2, area.y + (area.h - h) / 2, w, h);
    }

    /** The largest size up to {@code font_size} at which the text, wrapped at spaces, fits {@code area}. */
    private FittedText fit(PDFont font, Box area) throws IOException {
        float[] vertical = verticalMetrics(font);
        float ascent = vertical[0];
        float descent = vertical[1];
        String[] paragraphs = appearance.text().split("\n", -1);
        for (String paragraph : paragraphs) {
            checkGlyphs(font, paragraph);
        }
        for (float size = appearance.fontSize(); ; size = Math.max(MIN_FONT_SIZE, size * SHRINK)) {
            float lineHeight = (ascent - descent) / 1000 * size;
            List<String> lines = new ArrayList<>();
            boolean fits = true;
            for (String paragraph : paragraphs) {
                fits &= wrap(font, size, area.w, paragraph, lines);
            }
            if (fits && lines.size() * lineHeight <= area.h) {
                float block = lines.size() * lineHeight;
                float firstBaseline = area.y + (area.h + block) / 2 - ascent / 1000 * size;
                return new FittedText(lines, size, lineHeight, firstBaseline, area, font);
            }
            if (size == MIN_FONT_SIZE) {
                throw new DssError(DssError.Code.INVALID_ARGUMENT, "options: pades.visible: the text does not fit "
                        + "in the box even at " + (int) MIN_FONT_SIZE + " points: make the box larger or the text "
                        + "shorter");
            }
        }
    }

    /** Greedy wrapping at spaces into {@code out}; false if a single word is wider than {@code width}. */
    private static boolean wrap(PDFont font, float size, float width, String paragraph, List<String> out)
            throws IOException {
        String[] words = paragraph.split(" ", -1);
        StringBuilder line = new StringBuilder(words[0]);
        boolean fits = textWidth(font, size, words[0]) <= width;
        for (int i = 1; i < words.length; i++) {
            String candidate = line + " " + words[i];
            if (textWidth(font, size, candidate) <= width) {
                line.setLength(0);
                line.append(candidate);
            } else {
                out.add(line.toString());
                line.setLength(0);
                line.append(words[i]);
                fits &= textWidth(font, size, words[i]) <= width;
            }
        }
        out.add(line.toString());
        return fits;
    }

    private static float textWidth(PDFont font, float size, String s) throws IOException {
        return font.getStringWidth(s) / 1000 * size;
    }

    /** A clear error for a character the font cannot show, before PDFBox fails on it while drawing. */
    private static void checkGlyphs(PDFont font, String s) throws IOException {
        try {
            font.encode(s);
        } catch (IllegalArgumentException e) {
            throw new DssError(DssError.Code.INVALID_ARGUMENT, "options: pades.visible: the font cannot show the "
                    + "text: " + e.getMessage(), e);
        }
    }

    /** Ascent and (negative) descent per 1000 units, from the font descriptor, else its bounding box. */
    private static float[] verticalMetrics(PDFont font) throws IOException {
        PDFontDescriptor fd = font instanceof PDType0Font t0 ? t0.getDescendantFont().getFontDescriptor()
                : font.getFontDescriptor();
        if (fd != null && fd.getAscent() > 0) {
            return new float[] {fd.getAscent(), Math.min(0, fd.getDescent())};
        }
        PDRectangle bbox = new PDRectangle(font.getBoundingBox());
        return new float[] {bbox.getUpperRightY(), Math.min(0, bbox.getLowerLeftY())};
    }

    private void drawText(PDPageContentStream cs, PDFont font, FittedText t) throws IOException {
        cs.setNonStrokingColor(color(appearance.textColor()));
        float baseline = t.firstBaseline;
        for (String line : t.lines) {
            float x = t.area.x;
            if (appearance.textAlign() != Appearance.TextAlign.LEFT) {
                float free = t.area.w - textWidth(font, t.size, line);
                x += appearance.textAlign() == Appearance.TextAlign.CENTER ? free / 2 : free;
            }
            if (!line.isEmpty()) {
                cs.beginText();
                cs.setFont(font, t.size);
                cs.newLineAtOffset(x, baseline);
                cs.showText(line);
                cs.endText();
            }
            baseline -= t.lineHeight;
        }
    }

    /**
     * From the box as displayed to the widget's own space. Viewers turn annotations with the page, so the
     * content is drawn turned the other way to read upright.
     */
    private Matrix unrotate() {
        float w = placement.width();
        float h = placement.height();
        return switch (placement.rotation()) {
            case 90 -> new Matrix(0, 1, -1, 0, w, 0);
            case 180 -> new Matrix(-1, 0, 0, -1, w, h);
            case 270 -> new Matrix(0, -1, 1, 0, 0, h);
            default -> new Matrix();
        };
    }

    private static PDColor color(int rgb) {
        int r = (rgb >> 16) & 0xff;
        int g = (rgb >> 8) & 0xff;
        int b = rgb & 0xff;
        if (r == g && g == b) {
            return new PDColor(new float[] {r / 255f}, PDDeviceGray.INSTANCE);
        }
        return new PDColor(new float[] {r / 255f, g / 255f, b / 255f}, PDDeviceRGB.INSTANCE);
    }

    private PDFont loadFont(PDDocument template) throws IOException {
        try (InputStream in = appearance.font() != null ? new ByteArrayInputStream(appearance.font())
                : defaultFont()) {
            return PDType0Font.load(template, in, true);
        }
    }

    /** DSS's default font for visible signatures, PT Serif (SIL Open Font License), from the dss-pades jar. */
    static InputStream defaultFont() throws IOException {
        InputStream in = SignatureImageTextParameters.class.getResourceAsStream(DEFAULT_FONT);
        if (in == null) {
            throw new IOException("the default font " + DEFAULT_FONT + " is missing from the class path");
        }
        return in;
    }

    private static DssError tooSmall() {
        return new DssError(DssError.Code.INVALID_ARGUMENT, "options: pades.visible: the box is too small for its "
                + "content");
    }

    // ------------------------------------------------------------------ colour

    /**
     * As DSS does: a PDF without an output intent gets an sRGB one, so that the device colours of the appearance
     * are defined (PDF/A requires it). PDFs that have one keep it.
     */
    private static void addOutputIntentIfMissing(PDDocument document) {
        PDDocumentCatalog catalog = document.getDocumentCatalog();
        if (!catalog.getOutputIntents().isEmpty()) {
            return;
        }
        try {
            PDStream profile = new PDStream(document, new ByteArrayInputStream(SrgbProfile.bytes()),
                    COSName.FLATE_DECODE);
            profile.getCOSObject().setInt(COSName.N, 3);
            COSDictionary intent = new COSDictionary();
            intent.setItem(COSName.TYPE, COSName.OUTPUT_INTENT);
            intent.setItem(COSName.S, COSName.GTS_PDFA1);
            intent.setString(COSName.OUTPUT_CONDITION, "sRGB");
            intent.setString(COSName.OUTPUT_CONDITION_IDENTIFIER, "sRGB");
            intent.setString(COSName.INFO, "sRGB IEC61966-2.1");
            intent.setString(COSName.REGISTRY_NAME, "http://www.color.org");
            intent.setItem(COSName.DEST_OUTPUT_PROFILE, profile);
            catalog.addOutputIntent(new PDOutputIntent(intent));
        } catch (IOException e) {
            LOG.warn("Cannot add an sRGB output intent: {}", e.getMessage());
        }
    }
}
