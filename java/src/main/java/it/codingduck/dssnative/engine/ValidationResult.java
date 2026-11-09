/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.PDFRevisionWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlObjectModification;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.validation.reports.Reports;

/** Outcome of validating one document (or one nesting level of a {@code .p7m.p7m} or {@code .pdf.p7m}). */
public final class ValidationResult {

    /** Where a signature's certificate chain found its trust anchor. */
    public enum TrustAnchor {
        /** A certificate of the EU trusted lists. */
        TRUSTED_LIST("trusted_list"),
        /** A certificate from {@code extra_trusted_certificates} (a private PKI; qualification is NA). */
        EXTRA_TRUSTED_CERTIFICATES("extra_trusted_certificates"),
        /** No trust anchor was reached. */
        NONE("none");

        private final String json;

        TrustAnchor(String json) {
            this.json = json;
        }

        public String json() {
            return json;
        }
    }

    /**
     * Keys of PDF objects whose addition after signing means active content or embedded files: a signed PDF
     * can be weaponised this way while every signature stays cryptographically valid.
     */
    static final Set<String> ACTIVE_CONTENT_KEYS = Set.of("OpenAction", "AA", "JS", "JavaScript", "Launch",
            "EmbeddedFiles", "EmbeddedFile", "FileAttachment", "RichMedia", "Rendition", "Movie", "Sound");

    /**
     * What changed in a PDF after a signature's revision, from DSS's object-level modification detection.
     *
     * @param extension           DSS dictionaries and document timestamps (the normal LT/LTA extension)
     * @param signatureOrFormFill later signatures and form fills
     * @param annotation          annotations added, removed or changed
     * @param undefined           anything else (page content, the catalog, …)
     * @param pagesDiffer         pages added or removed (1-based page numbers)
     * @param annotationsOverlap  pages where a later annotation covers an earlier one
     * @param activeContent       the undefined and annotation changes that add active content or embedded files
     * @param modifiedAfterSigning true when there are annotation or undefined changes, or pages differ
     */
    public record Changes(int extension, int signatureOrFormFill, int annotation, int undefined,
                          List<Long> pagesDiffer, List<Long> annotationsOverlap, List<String> activeContent,
                          boolean modifiedAfterSigning) {

        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("extension", extension);
            m.put("signature_or_form_fill", signatureOrFormFill);
            m.put("annotation", annotation);
            m.put("undefined", undefined);
            m.put("pages_differ", pagesDiffer);
            m.put("annotations_overlap", annotationsOverlap);
            m.put("active_content", activeContent);
            return m;
        }
    }

    /** A timestamp as the simple report sees it: one embedded in a signature, or a standalone document timestamp. */
    public record TimestampSummary(String id, String type, Indication indication, SubIndication subIndication,
                                   Date productionTime, String producedBy, TimestampQualification qualification,
                                   List<String> errors, List<String> warnings) {

        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id);
            m.put("type", type);
            m.put("indication", indication == null ? null : indication.name());
            m.put("sub_indication", subIndication == null ? null : subIndication.name());
            m.put("production_time", TrustedListManager.iso(productionTime));
            m.put("produced_by", producedBy);
            m.put("qualification", qualification == null ? null : qualification.name());
            m.put("errors", errors);
            m.put("warnings", warnings);
            return m;
        }
    }

    /**
     * The fields of the simple report that callers and the differential test compare.
     *
     * @param errors                AdES validation errors (what made the indication what it is)
     * @param warnings              AdES validation warnings
     * @param qualificationErrors   why the signature is not qualified (e.g. no trusted list reached); a
     *                              TOTAL_PASSED signature may have these
     * @param qualificationWarnings qualification warnings
     * @param info                  informational messages (e.g. a signature policy that was not resolved)
     * @param trustAnchor           where the chain's trust came from
     * @param policy                the signature policy the signature claims, when it claims one, and whether
     *                              DSS could identify it: {@code id}, {@code url}, {@code identified},
     *                              {@code digest_valid}
     * @param changes               PDF changes after this signature's revision; null for CMS
     * @param timestamps            the timestamps embedded in the signature (signature, archive, …)
     */
    public record SignatureSummary(String id, Indication indication, SubIndication subIndication,
                                   SignatureLevel format, SignatureQualification qualification,
                                   Date signingTime, Date bestSignatureTime, String signedBy, String signerDn,
                                   List<String> errors, List<String> warnings, List<String> qualificationErrors,
                                   List<String> qualificationWarnings, List<String> info, TrustAnchor trustAnchor,
                                   Map<String, Object> policy, Changes changes, List<TimestampSummary> timestamps) {

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
            m.put("trust_anchor", trustAnchor == null ? null : trustAnchor.json());
            m.put("errors", errors);
            m.put("warnings", warnings);
            m.put("qualification_errors", qualificationErrors);
            m.put("qualification_warnings", qualificationWarnings);
            m.put("info", info);
            m.put("policy", policy);
            if (changes != null) {
                m.put("modified_after_signing", changes.modifiedAfterSigning());
                m.put("changes_after_signing", changes.toMap());
            }
            List<Object> ts = new ArrayList<>();
            for (TimestampSummary t : timestamps) {
                ts.add(t.toMap());
            }
            m.put("timestamps", ts);
            return m;
        }
    }

    public final String containerType;
    public final List<String> transformations;
    public final List<SignatureSummary> signatures;
    /** Standalone timestamps (a PDF document timestamp with no signature under it); empty otherwise. */
    public final List<TimestampSummary> timestamps;
    public final Map<ReportKind, String> reports;
    /** Validation of the signed content when it is itself a CAdES envelope or a signed PDF; empty otherwise. */
    public final List<ValidationResult> nested;

    ValidationResult(String containerType, List<String> transformations, List<SignatureSummary> signatures,
                     List<TimestampSummary> timestamps, Map<ReportKind, String> reports,
                     List<ValidationResult> nested) {
        this.containerType = containerType;
        this.transformations = transformations;
        this.signatures = signatures;
        this.timestamps = timestamps;
        this.reports = new EnumMap<>(reports);
        this.nested = nested;
    }

    /**
     * True when there is at least one signature, at any nesting level, and every signature at every level is
     * TOTAL_PASSED. False for an unsigned document, so that a client which checks only this never accepts one.
     * Warnings and {@code modified_after_signing} do not enter into it: check them too.
     */
    public boolean allPassed() {
        List<SignatureSummary> all = new ArrayList<>();
        collect(all);
        return !all.isEmpty() && all.stream().allMatch(s -> s.indication() == Indication.TOTAL_PASSED);
    }

    private void collect(List<SignatureSummary> into) {
        into.addAll(signatures);
        for (ValidationResult n : nested) {
            n.collect(into);
        }
    }

    static List<SignatureSummary> summarize(Reports reports) {
        SimpleReport report = reports.getSimpleReport();
        DiagnosticData diagnostic = reports.getDiagnosticData();
        List<SignatureSummary> out = new ArrayList<>();
        for (String id : report.getSignatureIdList()) {
            SignatureWrapper signature = diagnostic.getSignatureById(id);
            out.add(new SignatureSummary(id, report.getIndication(id), report.getSubIndication(id),
                    report.getSignatureFormat(id), report.getSignatureQualification(id),
                    report.getSigningTime(id), report.getBestSignatureTime(id), report.getSignedBy(id),
                    signerDn(signature),
                    texts(report.getAdESValidationErrors(id)), texts(report.getAdESValidationWarnings(id)),
                    texts(report.getQualificationErrors(id)), texts(report.getQualificationWarnings(id)),
                    texts(report.getAdESValidationInfo(id), report.getQualificationInfo(id)),
                    trustAnchor(signature), policy(signature), changes(signature),
                    embeddedTimestamps(report, diagnostic, id)));
        }
        return out;
    }

    /** The standalone timestamps of the document (document timestamps covering no signature). */
    static List<TimestampSummary> summarizeTimestamps(Reports reports) {
        SimpleReport report = reports.getSimpleReport();
        DiagnosticData diagnostic = reports.getDiagnosticData();
        List<TimestampSummary> out = new ArrayList<>();
        for (String id : report.getTimestampIdList()) {
            TimestampWrapper wrapper = diagnostic.getTimestampById(id);
            out.add(new TimestampSummary(id, wrapper == null || wrapper.getType() == null ? null
                    : wrapper.getType().name(), report.getIndication(id), report.getSubIndication(id),
                    report.getProductionTime(id), report.getProducedBy(id), report.getTimestampQualification(id),
                    texts(report.getAdESValidationErrors(id), report.getQualificationErrors(id)),
                    texts(report.getAdESValidationWarnings(id), report.getQualificationWarnings(id))));
        }
        return out;
    }

    private static List<TimestampSummary> embeddedTimestamps(SimpleReport report, DiagnosticData diagnostic,
                                                             String signatureId) {
        List<TimestampSummary> out = new ArrayList<>();
        List<XmlTimestamp> timestamps = report.getSignatureTimestamps(signatureId);
        if (timestamps == null) {
            return out;
        }
        for (XmlTimestamp t : timestamps) {
            TimestampWrapper wrapper = diagnostic.getTimestampById(t.getId());
            out.add(new TimestampSummary(t.getId(), wrapper == null || wrapper.getType() == null ? null
                    : wrapper.getType().name(), t.getIndication(), t.getSubIndication(), t.getProductionTime(),
                    t.getProducedBy(), t.getTimestampLevel() == null ? null : t.getTimestampLevel().getValue(),
                    texts(report.getAdESValidationErrors(t.getId()), report.getQualificationErrors(t.getId())),
                    texts(report.getAdESValidationWarnings(t.getId()), report.getQualificationWarnings(t.getId()))));
        }
        return out;
    }

    /** Subject DN (RFC 2253) of the signing certificate, if DSS identified it. */
    static String signerDn(SignatureWrapper signature) {
        CertificateWrapper cert = signature == null ? null : signature.getSigningCertificate();
        return cert == null ? null : cert.getCertificateDN();
    }

    /** The first trusted certificate of the chain decides: one the trusted lists know, or an extra anchor. */
    static TrustAnchor trustAnchor(SignatureWrapper signature) {
        if (signature == null) {
            return TrustAnchor.NONE;
        }
        List<CertificateWrapper> chain = new ArrayList<>();
        if (signature.getSigningCertificate() != null) {
            chain.add(signature.getSigningCertificate());
        }
        if (signature.getCertificateChain() != null) {
            chain.addAll(signature.getCertificateChain());
        }
        for (CertificateWrapper cert : chain) {
            if (cert.isTrusted()) {
                return cert.isTrustedListReached() ? TrustAnchor.TRUSTED_LIST : TrustAnchor.EXTRA_TRUSTED_CERTIFICATES;
            }
        }
        return TrustAnchor.NONE;
    }

    /** The signature policy the signature claims, or null when it claims none (the usual case). */
    static Map<String, Object> policy(SignatureWrapper signature) {
        if (signature == null || !signature.isPolicyPresent()) {
            return null;
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", signature.getPolicyId());
        m.put("url", signature.getPolicyUrl());
        m.put("identified", signature.isPolicyIdentified());
        m.put("digest_valid", signature.isPolicyIdentified() ? signature.isPolicyDigestValid() : null);
        return m;
    }

    /** PDF changes after the signature's revision, or null for a signature that is not in a PDF. */
    static Changes changes(SignatureWrapper signature) {
        PDFRevisionWrapper revision = signature == null ? null : signature.getPDFRevision();
        if (revision == null) {
            return null;
        }
        List<XmlObjectModification> annotation = orEmpty(revision.getPdfAnnotationChanges());
        List<XmlObjectModification> undefined = orEmpty(revision.getPdfUndefinedChanges());
        List<Long> pagesDiffer = pages(revision.getPdfPageDifferenceConcernedPages());
        List<String> active = new ArrayList<>();
        for (List<XmlObjectModification> list : List.of(undefined, annotation)) {
            for (XmlObjectModification change : list) {
                if (isActiveContent(change.getValue())) {
                    active.add(change.getValue());
                }
            }
        }
        boolean modified = !annotation.isEmpty() || !undefined.isEmpty() || !pagesDiffer.isEmpty();
        return new Changes(orEmpty(revision.getPdfExtensionChanges()).size(),
                orEmpty(revision.getPdfSignatureOrFormFillChanges()).size(), annotation.size(), undefined.size(),
                pagesDiffer, pages(revision.getPdfAnnotationsOverlapConcernedPages()), active, modified);
    }

    /** DSS writes an object's path as {@code /Root /OpenAction} or {@code /Root /Pages 12R /Annots}. */
    static boolean isActiveContent(String objectPath) {
        if (objectPath == null) {
            return false;
        }
        for (String token : objectPath.split("\\s+")) {
            if (token.startsWith("/") && ACTIVE_CONTENT_KEYS.contains(token.substring(1))) {
                return true;
            }
        }
        return false;
    }

    private static <T> List<T> orEmpty(List<T> list) {
        return list == null ? List.of() : list;
    }

    private static List<Long> pages(List<BigInteger> pages) {
        List<Long> out = new ArrayList<>();
        if (pages != null) {
            for (BigInteger p : pages) {
                out.add(p.longValue());
            }
        }
        return out;
    }

    @SafeVarargs
    private static List<String> texts(List<Message>... lists) {
        List<String> out = new ArrayList<>();
        for (List<Message> list : lists) {
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
        m.put("all_passed", allPassed());
        List<Object> sigs = new ArrayList<>();
        for (SignatureSummary s : signatures) {
            sigs.add(s.toMap());
        }
        m.put("signatures", sigs);
        List<Object> ts = new ArrayList<>();
        for (TimestampSummary t : timestamps) {
            ts.add(t.toMap());
        }
        m.put("timestamps", ts);
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
