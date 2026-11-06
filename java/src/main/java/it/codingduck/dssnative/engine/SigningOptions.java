/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.x509.CertificateToken;

/**
 * Per-call options of {@link DssEngine#prepareSignature} and {@link DssEngine#completeSignature}, parsed from
 * {@code options_json}. Both calls take the same options; {@code complete} also needs the {@code signing_time}
 * that {@code prepare} returned, because the data to be signed depends on it.
 */
public final class SigningOptions {

    public enum Format { PADES, CADES }

    /** What the external signer receives and returns. */
    public enum Mode {
        /**
         * It receives the digest of the content (for PAdES: of the PDF's signed byte ranges) and returns a
         * complete detached CMS SignedData, which may already carry a signature timestamp.
         */
        CMS,
        /**
         * It receives the digest of the signed attributes DSS builds and returns only the signature value
         * (RSA PKCS#1 v1.5, or ECDSA as DER or r||s). DSS builds the CMS around it.
         */
        SIGNATURE_VALUE
    }

    public enum Level {
        B(SignatureLevel.CAdES_BASELINE_B, SignatureLevel.PAdES_BASELINE_B),
        T(SignatureLevel.CAdES_BASELINE_T, SignatureLevel.PAdES_BASELINE_T),
        LT(SignatureLevel.CAdES_BASELINE_LT, SignatureLevel.PAdES_BASELINE_LT),
        LTA(SignatureLevel.CAdES_BASELINE_LTA, SignatureLevel.PAdES_BASELINE_LTA);

        final SignatureLevel cades;
        final SignatureLevel pades;

        Level(SignatureLevel cades, SignatureLevel pades) {
            this.cades = cades;
            this.pades = pades;
        }

        SignatureLevel of(Format format) {
            return format == Format.PADES ? pades : cades;
        }
    }

    /** CAdES only: whether the content goes inside the CMS ({@code .p7m}) or stays apart ({@code .p7s}). */
    public enum Packaging { DETACHED, ENVELOPING }

    /** DSS's default {@code /Contents} size, enough when DSS builds the CMS itself. */
    static final int DEFAULT_CONTENT_SIZE = 9472;
    /** When the external signer builds the CMS its size is unknown up front: it may carry its whole chain. */
    static final int DEFAULT_EXTERNAL_CMS_CONTENT_SIZE = 32768;
    private static final int MAX_CONTENT_SIZE = 1 << 20;
    private static final Set<DigestAlgorithm> DIGESTS = Set.of(DigestAlgorithm.SHA256, DigestAlgorithm.SHA384,
            DigestAlgorithm.SHA512);

    /** Null: from the document (PAdES for a PDF, CAdES otherwise). */
    public final Format format;
    public final Mode mode;
    public final Level level;
    public final DigestAlgorithm digestAlgorithm;
    /** Null on {@code prepare} means now (whole seconds). */
    public final Instant signingTime;
    /** Required in {@link Mode#SIGNATURE_VALUE}; in {@link Mode#CMS}, the certificate the CMS must be signed with. */
    public final CertificateToken signingCertificate;
    /** Included in the CMS DSS builds; in {@link Mode#CMS}, used to build the chain when extending. */
    public final List<CertificateToken> certificateChain;
    public final Packaging packaging;
    /** Name of the document: for PAdES it enters the prepared PDF, so it must not change between the calls. */
    public final String filename;
    public final String reason;
    public final String location;
    public final String contactInfo;
    public final String signerName;
    /** Bytes reserved in the PDF for the CMS; null means the default for the mode. */
    public final Integer contentSize;
    /** A visible appearance ({@code pades.visible}); null for an invisible signature. */
    public final VisibleSignature visible;

    public SigningOptions(Format format, Mode mode, Level level, DigestAlgorithm digestAlgorithm, Instant signingTime,
                          CertificateToken signingCertificate, List<CertificateToken> certificateChain,
                          Packaging packaging, String filename, String reason, String location, String contactInfo,
                          String signerName, Integer contentSize, VisibleSignature visible) {
        this.format = format;
        this.mode = mode;
        this.level = level;
        this.digestAlgorithm = digestAlgorithm;
        this.signingTime = signingTime;
        this.signingCertificate = signingCertificate;
        this.certificateChain = certificateChain;
        this.packaging = packaging;
        this.filename = filename;
        this.reason = reason;
        this.location = location;
        this.contactInfo = contactInfo;
        this.signerName = signerName;
        this.contentSize = contentSize;
        this.visible = visible;
    }

    /** These options with {@code signingTime} set (what {@code complete} needs after {@code prepare}). */
    public SigningOptions withSigningTime(Instant time) {
        return new SigningOptions(format, mode, level, digestAlgorithm, time, signingCertificate, certificateChain,
                packaging, filename, reason, location, contactInfo, signerName, contentSize, visible);
    }

    int contentSizeOrDefault() {
        if (contentSize != null) {
            return contentSize;
        }
        return mode == Mode.CMS ? DEFAULT_EXTERNAL_CMS_CONTENT_SIZE : DEFAULT_CONTENT_SIZE;
    }

    public static SigningOptions fromJson(String json) {
        Map<String, Object> map;
        try {
            map = Json.parseObject(json);
        } catch (Json.ParseException e) {
            throw new DssError(DssError.Code.INVALID_ARGUMENT, "options_json is not valid JSON: " + e.getMessage());
        }
        JsonFields f = new JsonFields(map, "options", DssError.Code.INVALID_ARGUMENT)
                .allowOnly(Set.of("format", "mode", "level", "digest_algorithm", "signing_time", "signing_certificate",
                        "certificate_chain", "packaging", "filename", "pades"));

        Format format = null;
        if (f.has("format")) {
            String v = f.requiredString("format").toUpperCase(Locale.ROOT);
            try {
                format = Format.valueOf(v);
            } catch (IllegalArgumentException e) {
                throw f.error("'format' must be \"PAdES\" or \"CAdES\"");
            }
        }
        Mode mode;
        try {
            mode = Mode.valueOf(f.requiredString("mode").toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw f.error("'mode' must be \"cms\" or \"signature_value\"");
        }
        Level level;
        try {
            level = Level.valueOf(f.requiredString("level").toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw f.error("'level' must be \"B\", \"T\", \"LT\" or \"LTA\"");
        }

        DigestAlgorithm digest = DigestAlgorithm.SHA256;
        if (f.has("digest_algorithm")) {
            String v = f.requiredString("digest_algorithm").toUpperCase(Locale.ROOT).replace("-", "");
            digest = DIGESTS.stream().filter(d -> d.getName().equals(v)).findFirst()
                    .orElseThrow(() -> f.error("'digest_algorithm' must be \"SHA256\", \"SHA384\" or \"SHA512\""));
        }

        Instant signingTime = null;
        if (f.has("signing_time")) {
            try {
                signingTime = Instant.parse(f.requiredString("signing_time"));
            } catch (DateTimeParseException e) {
                throw f.error("'signing_time' must be ISO-8601 UTC, e.g. 2026-01-31T12:00:00Z");
            }
            if (!signingTime.equals(signingTime.truncatedTo(ChronoUnit.SECONDS))) {
                throw f.error("'signing_time' must be in whole seconds (PDF and CMS times have no fractions)");
            }
        }

        CertificateToken signingCertificate = f.has("signing_certificate")
                ? certificate(f, "signing_certificate", f.requiredString("signing_certificate"))
                : null;
        if (mode == Mode.SIGNATURE_VALUE && signingCertificate == null) {
            throw f.error("'signing_certificate' is required with mode \"signature_value\": DSS signs it into the "
                    + "signed attributes");
        }
        List<CertificateToken> chain = new ArrayList<>();
        for (String c : f.strings("certificate_chain", List.of())) {
            chain.add(certificate(f, "certificate_chain", c));
        }

        Packaging packaging = null;
        if (f.has("packaging")) {
            try {
                packaging = Packaging.valueOf(f.requiredString("packaging").toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException e) {
                throw f.error("'packaging' must be \"detached\" or \"enveloping\"");
            }
            if (format == Format.PADES) {
                throw f.error("'packaging' applies to CAdES only (a PAdES signature is always inside the PDF)");
            }
        }

        String reason = null;
        String location = null;
        String contactInfo = null;
        String signerName = null;
        Integer contentSize = null;
        VisibleSignature visible = null;
        if (f.has("pades")) {
            if (format == Format.CADES) {
                throw f.error("'pades' applies to PAdES only");
            }
            JsonFields p = f.object("pades").allowOnly(Set.of("reason", "location", "contact_info", "signer_name",
                    "content_size", "visible"));
            reason = p.string("reason", null);
            location = p.string("location", null);
            contactInfo = p.string("contact_info", null);
            signerName = p.string("signer_name", null);
            if (p.has("content_size")) {
                long size = p.integer("content_size", 0);
                if (size < 1 || size > MAX_CONTENT_SIZE) {
                    throw p.error("'content_size' must be between 1 and " + MAX_CONTENT_SIZE + " bytes");
                }
                contentSize = (int) size;
            }
            if (p.has("visible")) {
                visible = VisibleSignature.fromJson(p.object("visible"));
            }
        }

        return new SigningOptions(format, mode, level, digest, signingTime, signingCertificate, List.copyOf(chain),
                packaging, f.string("filename", null), reason, location, contactInfo, signerName, contentSize,
                visible);
    }

    /** Base64 of the DER encoding, or PEM. */
    private static CertificateToken certificate(JsonFields f, String key, String value) {
        try {
            if (value.contains("-----BEGIN CERTIFICATE-----")) {
                List<CertificateToken> certs = DssEngine.readCertificates(value.getBytes(StandardCharsets.US_ASCII));
                if (certs.size() != 1) {
                    throw f.error("'" + key + "' entries must hold one certificate each, got " + certs.size());
                }
                return certs.get(0);
            }
            return DssEngine.readCertificates(Base64.getMimeDecoder().decode(value)).get(0);
        } catch (DssError e) {
            throw e;
        } catch (RuntimeException e) {
            throw f.error("'" + key + "' is not a base64 DER or PEM certificate: " + e.getMessage());
        }
    }
}
