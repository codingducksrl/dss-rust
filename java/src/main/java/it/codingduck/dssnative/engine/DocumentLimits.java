/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import java.io.IOException;
import java.util.Set;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.encryption.InvalidPasswordException;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Cheap structural checks run on a document before DSS sees it, for every operation (validate, extend, sign).
 *
 * <ul>
 *   <li>A PDF encrypted with a user password is refused up front ({@code UNSUPPORTED_DOCUMENT}): DSS cannot open
 *       it and would say "the password is incorrect".</li>
 *   <li>Bounds on what drives DSS's super-linear costs ({@code config_json "limits"}): the number of signature
 *       revisions of a PDF (each one re-parses the growing prefix twice), its pages (the annotation-overlap scan
 *       resolves every page from the root), the annotations on one page (object modification detection compares
 *       arrays with a nested loop) and the certificates in a CMS (a token is built and checked for each). Above a
 *       bound the operation is refused with the operation's own failure code, naming the limit.</li>
 * </ul>
 *
 * <p>Counts come from one PDFBox parse of the file (what the appearance of a visible signature already does);
 * a PDF or CMS that cannot be parsed at all is let through, so that DSS reports its own, better error.
 */
public final class DocumentLimits {

    private static final Logger LOG = LoggerFactory.getLogger(DocumentLimits.class);

    public static final int DEFAULT_MAX_PDF_PAGES = 5_000;
    public static final int DEFAULT_MAX_PDF_SIGNATURES = 100;
    public static final int DEFAULT_MAX_PDF_ANNOTATIONS_PER_PAGE = 5_000;
    public static final int DEFAULT_MAX_CMS_CERTIFICATES = 500;

    /** The bounds; see the class comment. Each is at least 1. */
    public record Limits(int maxPdfPages, int maxPdfSignatures, int maxPdfAnnotationsPerPage, int maxCmsCertificates) {

        public static final Limits DEFAULT = new Limits(DEFAULT_MAX_PDF_PAGES, DEFAULT_MAX_PDF_SIGNATURES,
                DEFAULT_MAX_PDF_ANNOTATIONS_PER_PAGE, DEFAULT_MAX_CMS_CERTIFICATES);

        public Limits {
            for (int v : new int[] {maxPdfPages, maxPdfSignatures, maxPdfAnnotationsPerPage, maxCmsCertificates}) {
                if (v < 1) {
                    throw new IllegalArgumentException("every limit must be at least 1");
                }
            }
        }

        /** The {@code limits} object of {@code config_json}; absent keys take the defaults. */
        static Limits parse(JsonFields f) {
            f.allowOnly(Set.of("max_pdf_pages", "max_pdf_signatures", "max_pdf_annotations_per_page",
                    "max_cms_certificates"));
            return new Limits(bound(f, "max_pdf_pages", DEFAULT_MAX_PDF_PAGES),
                    bound(f, "max_pdf_signatures", DEFAULT_MAX_PDF_SIGNATURES),
                    bound(f, "max_pdf_annotations_per_page", DEFAULT_MAX_PDF_ANNOTATIONS_PER_PAGE),
                    bound(f, "max_cms_certificates", DEFAULT_MAX_CMS_CERTIFICATES));
        }

        private static int bound(JsonFields f, String key, int def) {
            long v = f.integer(key, def);
            if (v < 1 || v > Integer.MAX_VALUE) {
                throw f.error("'" + key + "' must be between 1 and " + Integer.MAX_VALUE);
            }
            return (int) v;
        }
    }

    private DocumentLimits() {
    }

    /**
     * Checks a PDF about to be {@code operation}-ed ("validating", "extending", "signing").
     *
     * @throws DssError {@link DssError.Code#UNSUPPORTED_DOCUMENT} for a user-password-encrypted PDF; {@code
     *                  limitCode} when a limit is exceeded
     */
    static void checkPdf(byte[] pdf, Limits limits, DssError.Code limitCode, String operation) {
        try (PDDocument document = Loader.loadPDF(pdf)) {
            int pages = 0;
            for (PDPage page : document.getPages()) {
                pages++;
                if (pages > limits.maxPdfPages) {
                    throw over(limitCode, "the PDF has more than " + limits.maxPdfPages + " pages", "max_pdf_pages",
                            limits.maxPdfPages);
                }
                COSBase annots = page.getCOSObject().getDictionaryObject(COSName.ANNOTS);
                if (annots instanceof COSArray array && array.size() > limits.maxPdfAnnotationsPerPage) {
                    throw over(limitCode, "page " + pages + " of the PDF has " + array.size() + " annotations",
                            "max_pdf_annotations_per_page", limits.maxPdfAnnotationsPerPage);
                }
            }
            int signatures = document.getSignatureDictionaries().size();
            if (signatures > limits.maxPdfSignatures) {
                throw over(limitCode, "the PDF has " + signatures + " signature revisions", "max_pdf_signatures",
                        limits.maxPdfSignatures);
            }
        } catch (InvalidPasswordException e) {
            throw new DssError(DssError.Code.UNSUPPORTED_DOCUMENT, "the PDF is encrypted with a user password, "
                    + "which is not supported: remove the password before " + operation + " it", e);
        } catch (DssError e) {
            throw e;
        } catch (IOException | RuntimeException e) {
            // Not our call: DSS opens the same bytes next and reports what is wrong with them.
            LOG.debug("PDF pre-check skipped: {}", e.toString());
        }
    }

    /**
     * Checks a CMS about to be processed.
     *
     * @throws DssError {@code limitCode} when its certificate set is larger than the limit
     */
    static void checkCms(byte[] cms, Limits limits, DssError.Code limitCode) {
        int certificates;
        try {
            ContentInfo info = ContentInfo.getInstance(ASN1Primitive.fromByteArray(cms));
            if (!CMSObjectIdentifiers.signedData.equals(info.getContentType())) {
                return;
            }
            ASN1Set set = SignedData.getInstance(info.getContent()).getCertificates();
            certificates = set == null ? 0 : set.size();
        } catch (IOException | RuntimeException e) {
            LOG.debug("CMS pre-check skipped: {}", e.toString());
            return;
        }
        if (certificates > limits.maxCmsCertificates) {
            throw over(limitCode, "the CMS carries " + certificates + " certificates", "max_cms_certificates",
                    limits.maxCmsCertificates);
        }
    }

    private static DssError over(DssError.Code code, String what, String key, int limit) {
        return new DssError(code, what + ", more than the " + limit + " this engine processes (config_json "
                + "limits." + key + ")");
    }
}
