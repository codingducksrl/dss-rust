/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import java.util.ArrayList;
import java.util.Date;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.reports.Reports;

/** Outcome of validating one document (or one nesting level of a {@code .p7m.p7m}). */
public final class ValidationResult {

    /** The fields of the simple report that callers and the differential test compare. */
    public record SignatureSummary(String id, Indication indication, SubIndication subIndication,
                                   SignatureLevel format, SignatureQualification qualification,
                                   Date signingTime, Date bestSignatureTime, String signedBy, String signerDn,
                                   List<String> errors, List<String> warnings) {

        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id);
            m.put("indication", indication == null ? null : indication.name());
            m.put("sub_indication", subIndication == null ? null : subIndication.name());
            m.put("format", format == null ? null : format.toString());
            m.put("qualification", qualification == null ? null : qualification.name());
            m.put("signing_time", TrustedListManager.iso(signingTime));
            m.put("best_signature_time", TrustedListManager.iso(bestSignatureTime));
            m.put("signed_by", signedBy);
            m.put("signer_dn", signerDn);
            m.put("errors", errors);
            m.put("warnings", warnings);
            return m;
        }
    }

    public final String containerType;
    public final List<String> transformations;
    public final List<SignatureSummary> signatures;
    public final Map<ReportKind, String> reports;
    /** Validation of the signed content when it is itself a CAdES envelope; empty otherwise. */
    public final List<ValidationResult> nested;

    ValidationResult(String containerType, List<String> transformations, List<SignatureSummary> signatures,
                     Map<ReportKind, String> reports, List<ValidationResult> nested) {
        this.containerType = containerType;
        this.transformations = transformations;
        this.signatures = signatures;
        this.reports = new EnumMap<>(reports);
        this.nested = nested;
    }

    static List<SignatureSummary> summarize(Reports reports) {
        SimpleReport report = reports.getSimpleReport();
        DiagnosticData diagnostic = reports.getDiagnosticData();
        List<SignatureSummary> out = new ArrayList<>();
        for (String id : report.getSignatureIdList()) {
            out.add(new SignatureSummary(id, report.getIndication(id), report.getSubIndication(id),
                    report.getSignatureFormat(id), report.getSignatureQualification(id),
                    report.getSigningTime(id), report.getBestSignatureTime(id), report.getSignedBy(id),
                    signerDn(diagnostic, id),
                    texts(report.getAdESValidationErrors(id), report.getQualificationErrors(id)),
                    texts(report.getAdESValidationWarnings(id), report.getQualificationWarnings(id))));
        }
        return out;
    }

    /** Subject DN (RFC 2253) of the signing certificate, if DSS identified it. */
    static String signerDn(DiagnosticData diagnostic, String signatureId) {
        SignatureWrapper signature = diagnostic.getSignatureById(signatureId);
        CertificateWrapper cert = signature == null ? null : signature.getSigningCertificate();
        return cert == null ? null : cert.getCertificateDN();
    }

    private static List<String> texts(List<Message> a, List<Message> b) {
        List<String> out = new ArrayList<>();
        for (List<Message> list : List.of(a, b)) {
            if (list != null) {
                for (Message m : list) {
                    out.add(m.getValue());
                }
            }
        }
        return out;
    }

    /** The JSON shape returned by {@code dss_validate} (minus {@code ok}). */
    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("container", containerType);
        m.put("transformations", transformations);
        List<Object> sigs = new ArrayList<>();
        for (SignatureSummary s : signatures) {
            sigs.add(s.toMap());
        }
        m.put("signatures", sigs);
        for (Map.Entry<ReportKind, String> e : reports.entrySet()) {
            m.put(e.getKey().jsonKey(), e.getValue());
        }
        if (!nested.isEmpty()) {
            List<Object> n = new ArrayList<>();
            for (ValidationResult r : nested) {
                n.add(r.toMap());
            }
            m.put("nested", n);
        }
        return m;
    }
}
