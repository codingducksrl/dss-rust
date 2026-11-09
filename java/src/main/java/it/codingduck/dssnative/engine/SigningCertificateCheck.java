/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import eu.europa.esig.dss.enumerations.ExtendedKeyUsage;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.extension.ExtendedKeyUsages;
import eu.europa.esig.dss.spi.CertificateExtensionsUtils;

/**
 * Whether a certificate can sign a document at a given time: valid then, an end-entity certificate, with a key
 * usage that covers signing and no extended key usage that limits the key to timestamping, TLS or OCSP. DSS only
 * checks the validity dates (and only on some paths); its default validation policy makes key usage a warning.
 * The checks run before any external signature is spent, and again on the certificate found in an external CMS.
 */
final class SigningCertificateCheck {

    /** Extended key usages that rule out document signing when they are the only ones present. */
    private static final Set<String> NOT_FOR_SIGNING = Set.of(ExtendedKeyUsage.TIMESTAMPING.getOid(),
            ExtendedKeyUsage.SERVER_AUTH.getOid(), ExtendedKeyUsage.OCSP_SIGNING.getOid());
    private static final String ANY_EXTENDED_KEY_USAGE = "2.5.29.37.0";

    private SigningCertificateCheck() {
    }

    /**
     * @param signingTime the time the signature claims; null when it is not known yet (CAdES in mode "cms", where
     *                    the CMS carries it), which skips the validity check
     * @throws DssError {@link DssError.Code#SIGNING_FAILED} with the reason
     */
    static void assertSuitable(CertificateToken certificate, Instant signingTime) {
        String subject = certificate.getSubject().getRFC2253();
        if (signingTime != null && !certificate.isValidOn(Date.from(signingTime))) {
            boolean expired = signingTime.isAfter(certificate.getNotAfter().toInstant());
            throw failed("the signing certificate (" + subject + ") is " + (expired ? "expired" : "not yet valid")
                    + " at the signing time " + signingTime + ": it is valid from "
                    + certificate.getNotBefore().toInstant() + " to " + certificate.getNotAfter().toInstant());
        }
        if (certificate.isCA()) {
            throw failed("the signing certificate (" + subject + ") is a CA certificate (basicConstraints cA=true): "
                    + "documents are signed with an end-entity certificate");
        }
        List<KeyUsageBit> keyUsage = certificate.getKeyUsageBits();
        if (!keyUsage.isEmpty() && !keyUsage.contains(KeyUsageBit.DIGITAL_SIGNATURE)
                && !keyUsage.contains(KeyUsageBit.NON_REPUDIATION)) {
            throw failed("the signing certificate's (" + subject + ") key usage ("
                    + keyUsage.stream().map(KeyUsageBit::getValue).collect(Collectors.joining(", "))
                    + ") allows neither digitalSignature nor nonRepudiation, which signing a document needs");
        }
        ExtendedKeyUsages extended = CertificateExtensionsUtils.getExtendedKeyUsage(certificate);
        List<String> purposes = extended != null && extended.getOids() != null ? extended.getOids() : List.of();
        if (!purposes.isEmpty() && !purposes.contains(ANY_EXTENDED_KEY_USAGE) && NOT_FOR_SIGNING.containsAll(purposes)) {
            throw failed("the signing certificate's (" + subject + ") extended key usage ("
                    + purposes.stream().map(SigningCertificateCheck::purposeName).collect(Collectors.joining(", "))
                    + ") limits its key to timestamping, TLS or OCSP: it is not a document signing certificate");
        }
    }

    private static String purposeName(String oid) {
        for (ExtendedKeyUsage u : ExtendedKeyUsage.values()) {
            if (u.getOid().equals(oid)) {
                return u.getDescription();
            }
        }
        return oid;
    }

    private static DssError failed(String message) {
        return new DssError(DssError.Code.SIGNING_FAILED, message);
    }
}
