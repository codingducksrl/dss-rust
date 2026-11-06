/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.visible;

import eu.europa.esig.dss.alert.StatusAlert;
import eu.europa.esig.dss.pdf.PdfSignatureFieldPositionChecker;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;
import eu.europa.esig.dss.pdf.pdfbox.visible.PdfBoxSignatureDrawerFactory;

import it.codingduck.dssnative.engine.DssError;

/**
 * DSS's PDFBox object factory, with {@link AwtFreeSignatureDrawer} drawing visible signatures instead of DSS's
 * native drawer, which needs AWT (see that class). A new field that overlaps another annotation fails with
 * {@code INVALID_ARGUMENT}.
 */
public class AwtFreePdfObjFactory extends PdfBoxNativeObjectFactory {

    public AwtFreePdfObjFactory() {
        PdfSignatureFieldPositionChecker checker = new PdfSignatureFieldPositionChecker();
        StatusAlert invalid = status -> {
            throw new DssError(DssError.Code.INVALID_ARGUMENT, "options: pades.visible: " + status.getMessage());
        };
        checker.setAlertOnSignatureFieldOverlap(invalid);
        checker.setAlertOnSignatureFieldOutsidePageDimensions(invalid);
        setPdfSignatureFieldPositionChecker(checker);
    }

    @Override
    protected PdfBoxSignatureDrawerFactory getSignatureDrawerFactory() {
        return parameters -> {
            if (!(parameters instanceof VisibleImageParameters visible)) {
                // Only VisibleImageParameters are ever set; DSS's own drawer would need AWT.
                throw new IllegalStateException("visible signature parameters of an unexpected type: "
                        + parameters.getClass().getName());
            }
            return new AwtFreeSignatureDrawer(visible);
        };
    }
}
