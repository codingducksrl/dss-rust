/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.font.PDType0Font;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;

import it.codingduck.dssnative.visible.Appearance;
import it.codingduck.dssnative.visible.Appearance.ImagePosition;
import it.codingduck.dssnative.visible.Appearance.TextAlign;
import it.codingduck.dssnative.visible.SignatureImage;

/**
 * {@code pades.visible}: a visible signature appearance, parsed and checked up front (image, font, template), so
 * that a bad option fails {@code prepare} before anything is signed. The text is a template; its placeholders
 * are filled in by {@link #appearance} once the signing time is known.
 */
public final class VisibleSignature {

    static final float DEFAULT_FONT_SIZE = 10;
    static final float MIN_FONT_SIZE = 4;
    static final float MAX_FONT_SIZE = 200;
    private static final String DEFAULT_DATE_FORMAT = "yyyy-MM-dd HH:mm:ss xxx";
    private static final Set<String> PLACEHOLDERS = Set.of("signer_name", "signing_time", "reason", "location");
    private static final Set<String> KEYS = Set.of("field", "page", "x", "y", "width", "height", "text", "font",
            "font_size", "text_color", "text_align", "background_color", "image", "image_position", "time_zone",
            "date_format");

    final String field;
    final int page;
    final float x;
    final float y;
    final float width;
    final float height;
    /** The template, split into literal text and placeholder names; null without text. */
    private final List<Part> text;
    private final byte[] font;
    final float fontSize;
    private final int textColor;
    private final TextAlign textAlign;
    private final Integer backgroundColor;
    private final SignatureImage image;
    private final ImagePosition imagePosition;
    private final DateTimeFormatter dateFormat;

    /** Literal text, or a placeholder when {@code placeholder} is set. */
    private record Part(String literal, String placeholder) {
    }

    private VisibleSignature(String field, int page, float x, float y, float width, float height, List<Part> text,
                             byte[] font, float fontSize, int textColor, TextAlign textAlign, Integer backgroundColor,
                             SignatureImage image, ImagePosition imagePosition, DateTimeFormatter dateFormat) {
        this.field = field;
        this.page = page;
        this.x = x;
        this.y = y;
        this.width = width;
        this.height = height;
        this.text = text;
        this.font = font;
        this.fontSize = fontSize;
        this.textColor = textColor;
        this.textAlign = textAlign;
        this.backgroundColor = backgroundColor;
        this.image = image;
        this.imagePosition = imagePosition;
        this.dateFormat = dateFormat;
    }

    static VisibleSignature fromJson(JsonFields v) {
        v.allowOnly(KEYS);
        String field = null;
        int page = 0;
        float x = 0;
        float y = 0;
        float width = 0;
        float height = 0;
        boolean anyBox = v.has("page") || v.has("x") || v.has("y") || v.has("width") || v.has("height");
        if (v.has("field")) {
            if (anyBox) {
                throw v.error("give either 'field' (an existing signature field) or 'page', 'x', 'y', 'width' and "
                        + "'height' (a new one), not both");
            }
            field = v.requiredString("field");
        } else {
            for (String key : List.of("page", "x", "y", "width", "height")) {
                if (!v.has(key)) {
                    throw v.error("'" + key + "' is required for a new field (or give 'field' to fill an existing "
                            + "one)");
                }
            }
            long p = v.integer("page", 0);
            if (p < 1 || p > Integer.MAX_VALUE) {
                throw v.error("'page' must be 1 or more");
            }
            page = (int) p;
            x = coordinate(v, "x");
            y = coordinate(v, "y");
            width = (float) v.decimal("width", 0);
            height = (float) v.decimal("height", 0);
            if (!(width > 0) || !(height > 0) || width > 14400 || height > 14400) {
                throw v.error("'width' and 'height' must be more than 0 (points)");
            }
        }

        List<Part> text = null;
        if (v.has("text")) {
            String t = v.string("text", null).replace("\r\n", "\n").replace('\r', '\n').replace('\t', ' ');
            if (t.isBlank()) {
                throw v.error("'text' is empty; leave it out for an image alone");
            }
            text = parseTemplate(v, t);
        }
        SignatureImage image = null;
        if (v.has("image")) {
            try {
                image = SignatureImage.parse(base64(v, "image"));
            } catch (IllegalArgumentException e) {
                throw v.error("'image': " + e.getMessage());
            }
        }
        if (text == null && image == null) {
            throw v.error("give 'text', 'image' or both");
        }

        byte[] font = null;
        if (v.has("font")) {
            if (text == null) {
                throw v.error("'font' needs 'text'");
            }
            font = base64(v, "font");
            checkFont(v, font);
        }
        float fontSize = (float) v.decimal("font_size", DEFAULT_FONT_SIZE);
        if (!(fontSize >= MIN_FONT_SIZE) || fontSize > MAX_FONT_SIZE) {
            throw v.error("'font_size' must be between " + (int) MIN_FONT_SIZE + " and " + (int) MAX_FONT_SIZE);
        }
        int textColor = v.has("text_color") ? color(v, "text_color") : 0x000000;
        Integer backgroundColor = v.has("background_color") ? color(v, "background_color") : null;
        TextAlign textAlign = choice(v, "text_align", TextAlign.values(), TextAlign.LEFT);
        ImagePosition imagePosition = choice(v, "image_position", ImagePosition.values(), ImagePosition.LEFT);

        ZoneId zone = ZoneOffset.UTC;
        if (v.has("time_zone")) {
            try {
                zone = ZoneId.of(v.requiredString("time_zone"));
            } catch (DateTimeException e) {
                throw v.error("'time_zone' is not a time zone (use an IANA name like \"Europe/Rome\", or \"UTC\"): "
                        + e.getMessage());
            }
        }
        DateTimeFormatter dateFormat;
        String pattern = v.string("date_format", DEFAULT_DATE_FORMAT);
        try {
            dateFormat = DateTimeFormatter.ofPattern(pattern, Locale.US).withZone(zone);
            dateFormat.format(Instant.EPOCH);
        } catch (IllegalArgumentException | DateTimeException e) {
            throw v.error("'date_format' is not a valid pattern (java.time.format.DateTimeFormatter, e.g. "
                    + "\"dd/MM/yyyy HH:mm\"): " + e.getMessage());
        }
        return new VisibleSignature(field, page, x, y, width, height, text, font, fontSize, textColor, textAlign,
                backgroundColor, image, imagePosition, dateFormat);
    }

    /**
     * The appearance to draw, with the placeholders filled in.
     *
     * @param signerName  {@code pades.signer_name}, or null for the signing certificate's common name
     * @param certificate the signing certificate, or null when the options give none
     */
    public Appearance appearance(String signerName, String reason, String location, CertificateToken certificate,
                                 Instant signingTime) {
        String rendered = null;
        if (text != null) {
            StringBuilder sb = new StringBuilder();
            for (Part part : text) {
                if (part.placeholder == null) {
                    sb.append(part.literal);
                    continue;
                }
                sb.append(switch (part.placeholder) {
                    case "signer_name" -> signerName(signerName, certificate);
                    case "signing_time" -> dateFormat.format(signingTime);
                    case "reason" -> required(reason, "reason");
                    default -> required(location, "location");
                });
            }
            rendered = sb.toString();
        }
        return new Appearance(field, page, x, y, width, height, rendered, font, fontSize, textColor, textAlign,
                backgroundColor, image, imagePosition);
    }

    private static String signerName(String signerName, CertificateToken certificate) {
        if (signerName != null) {
            return signerName;
        }
        String cn = certificate != null ? DSSASN1Utils.getSubjectCommonName(certificate) : null;
        if (cn == null || cn.isEmpty()) {
            throw new DssError(DssError.Code.INVALID_ARGUMENT, "options: pades.visible: '{signer_name}' needs "
                    + "'pades.signer_name', or a 'signing_certificate' with a common name");
        }
        return cn;
    }

    private static String required(String value, String key) {
        if (value == null) {
            throw new DssError(DssError.Code.INVALID_ARGUMENT, "options: pades.visible: '{" + key + "}' needs "
                    + "'pades." + key + "'");
        }
        return value;
    }

    /** {@code {name}} is a placeholder, {@code {{} and {@code }}} are literal braces. */
    private static List<Part> parseTemplate(JsonFields v, String t) {
        List<Part> parts = new ArrayList<>();
        StringBuilder literal = new StringBuilder();
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (c == '{' && i + 1 < t.length() && t.charAt(i + 1) == '{') {
                literal.append('{');
                i++;
            } else if (c == '}' && i + 1 < t.length() && t.charAt(i + 1) == '}') {
                literal.append('}');
                i++;
            } else if (c == '{') {
                int close = t.indexOf('}', i);
                if (close < 0) {
                    throw v.error("'text' has a '{' without '}' (write '{{' for a literal brace)");
                }
                String name = t.substring(i + 1, close);
                if (!PLACEHOLDERS.contains(name)) {
                    throw v.error("'text' has an unknown placeholder '{" + name + "}' (known: {signer_name}, "
                            + "{signing_time}, {reason}, {location}; write '{{' for a literal brace)");
                }
                if (!literal.isEmpty()) {
                    parts.add(new Part(literal.toString(), null));
                    literal.setLength(0);
                }
                parts.add(new Part(null, name));
                i = close;
            } else if (c == '}') {
                throw v.error("'text' has a '}' without '{' (write '}}' for a literal brace)");
            } else {
                literal.append(c);
            }
        }
        if (!literal.isEmpty()) {
            parts.add(new Part(literal.toString(), null));
        }
        return List.copyOf(parts);
    }

    private static float coordinate(JsonFields v, String key) {
        double d = v.decimal(key, 0);
        if (!(d >= 0) || d > 14400) {
            throw v.error("'" + key + "' must be 0 or more (points from the " + (key.equals("x") ? "left" : "top")
                    + " edge of the page)");
        }
        return (float) d;
    }

    /** Strict base64; only line breaks and other whitespace are skipped (the MIME decoder ignores anything). */
    private static byte[] base64(JsonFields v, String key) {
        try {
            return Base64.getDecoder().decode(v.requiredString(key).replaceAll("\\s+", ""));
        } catch (IllegalArgumentException e) {
            throw v.error("'" + key + "' is not base64: " + e.getMessage());
        }
    }

    /** Loads the font the way the drawer will, so that an unusable font fails here rather than in DSS. */
    private static void checkFont(JsonFields v, byte[] font) {
        try (PDDocument scratch = new PDDocument()) {
            PDType0Font.load(scratch, new ByteArrayInputStream(font), false);
        } catch (IOException | RuntimeException e) {
            throw v.error("'font' is not a usable TrueType font (TTF, or OTF with TrueType outlines): "
                    + e.getMessage());
        }
    }

    private static int color(JsonFields v, String key) {
        String s = v.requiredString(key);
        if (!s.matches("#[0-9A-Fa-f]{6}")) {
            throw v.error("'" + key + "' must be a colour as \"#RRGGBB\"");
        }
        return Integer.parseInt(s.substring(1), 16);
    }

    private static <E extends Enum<E>> E choice(JsonFields v, String key, E[] values, E def) {
        if (!v.has(key)) {
            return def;
        }
        String s = v.requiredString(key);
        for (E e : values) {
            if (e.name().equalsIgnoreCase(s)) {
                return e;
            }
        }
        List<String> names = new ArrayList<>();
        for (E e : values) {
            names.add("\"" + e.name().toLowerCase(Locale.ROOT) + "\"");
        }
        throw v.error("'" + key + "' must be one of " + String.join(", ", names));
    }
}
