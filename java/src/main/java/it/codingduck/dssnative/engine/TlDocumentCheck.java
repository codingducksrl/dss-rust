/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Set;

import javax.xml.XMLConstants;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import eu.europa.esig.dss.model.DSSException;

/**
 * A cheap pre-check of a downloaded or cached trusted list, before DSS parses it, validates its signature and
 * (for a download) before it is stored: it must be XML whose root is an ETSI TS 119 612 {@code
 * TrustServiceStatusList}, and its XML signatures may only use what trusted lists use.
 *
 * <p>DSS verifies every {@code ds:Reference} of a list's signature, with secure validation off, before it
 * decides whether the signature is trusted: the transforms in a hostile list (XPath, XSLT) run on every refresh
 * and on every start from the cache, and can take seconds to minutes. Every EU list uses the enveloped-signature
 * transform followed by canonicalization, with two references and no {@code ds:Manifest}; only that is let
 * through. Streaming (StAX), so a multi-megabyte list costs one pass and no tree.
 *
 * <p>The same pass reads the list's {@code TSLSequenceNumber} and {@code ListIssueDateTime} ({@link Identity}),
 * which the rollback protection compares with the list last published for the same URL before DSS parses it.
 * They are read before the signature is checked, so a caller may act on them only in ways a forged list cannot
 * abuse: refusing a list is safe, trusting one is not.
 */
final class TlDocumentCheck {

    static final String TSL_NS = "http://uri.etsi.org/02231/v2#";
    static final String XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#";
    static final int MAX_SIGNATURES = 4;
    static final int MAX_REFERENCES_PER_SIGNATURE = 4;

    /** Enveloped-signature and the canonicalization algorithms (inclusive, exclusive, 1.1; with or without comments). */
    static final Set<String> ALLOWED_TRANSFORMS = Set.of(
            "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
            "http://www.w3.org/2006/12/xml-c14n11",
            "http://www.w3.org/2006/12/xml-c14n11#WithComments",
            "http://www.w3.org/2001/10/xml-exc-c14n#",
            "http://www.w3.org/2001/10/xml-exc-c14n#WithComments");

    private static final XMLInputFactory FACTORY = secureFactory();

    /**
     * What identifies an issue of a list: its sequence number and issue date, either null when the element is
     * absent or unreadable (DSS then flags the structure).
     */
    record Identity(Long sequenceNumber, Instant issueDate) {
        static final Identity UNKNOWN = new Identity(null, null);
    }

    private TlDocumentCheck() {
    }

    private static XMLInputFactory secureFactory() {
        XMLInputFactory f = XMLInputFactory.newDefaultFactory();
        f.setProperty(XMLInputFactory.IS_NAMESPACE_AWARE, Boolean.TRUE);
        f.setProperty(XMLInputFactory.SUPPORT_DTD, Boolean.FALSE);
        f.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.FALSE);
        f.setProperty(XMLInputFactory.IS_REPLACING_ENTITY_REFERENCES, Boolean.FALSE);
        f.setProperty(XMLInputFactory.IS_COALESCING, Boolean.FALSE);
        try {
            f.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        } catch (IllegalArgumentException ignored) {
            // not every StAX implementation knows the property; external entities are off anyway
        }
        return f;
    }

    /**
     * @param what the list's URL or path, for messages
     * @return the list's sequence number and issue date, as far as the document states them
     * @throws DSSException when the document is not an acceptable trusted list; the message says why
     */
    static Identity check(InputStream in, String what) {
        XMLStreamReader r = null;
        try {
            r = FACTORY.createXMLStreamReader(in);
            boolean rootSeen = false;
            int signatures = 0;
            int depthInSignature = 0; // > 0 while inside ds:Signature
            int references = 0;
            int depth = 0; // of the current element below the root: 1 = SchemeInformation, 2 = its children
            boolean inSchemeInformation = false;
            Long sequenceNumber = null;
            Instant issueDate = null;
            while (r.hasNext()) {
                int event = r.next();
                if (event == XMLStreamConstants.DTD) {
                    throw reject(what, "a trusted list carries no DTD");
                }
                if (event == XMLStreamConstants.START_ELEMENT) {
                    QName name = r.getName();
                    if (!rootSeen) {
                        rootSeen = true;
                        if (!TSL_NS.equals(name.getNamespaceURI()) || !"TrustServiceStatusList".equals(name.getLocalPart())) {
                            throw reject(what, "root element is " + name + ", not {" + TSL_NS + "}TrustServiceStatusList");
                        }
                        continue;
                    }
                    depth++;
                    if (depth == 1) {
                        inSchemeInformation = TSL_NS.equals(name.getNamespaceURI())
                                && "SchemeInformation".equals(name.getLocalPart());
                    } else if (depth == 2 && inSchemeInformation && depthInSignature == 0
                            && TSL_NS.equals(name.getNamespaceURI())) {
                        // getElementText consumes the END_ELEMENT of this element; the depth is kept in step below.
                        switch (name.getLocalPart()) {
                            case "TSLSequenceNumber" -> {
                                sequenceNumber = parseSequenceNumber(r.getElementText());
                                depth--;
                            }
                            case "ListIssueDateTime" -> {
                                issueDate = parseInstant(r.getElementText());
                                depth--;
                            }
                            default -> { }
                        }
                    }
                    if (depthInSignature > 0) {
                        depthInSignature++;
                        if (XMLDSIG_NS.equals(name.getNamespaceURI())) {
                            switch (name.getLocalPart()) {
                                case "Reference" -> {
                                    if (++references > MAX_REFERENCES_PER_SIGNATURE) {
                                        throw reject(what, "signature has more than " + MAX_REFERENCES_PER_SIGNATURE
                                                + " references");
                                    }
                                }
                                case "Transform" -> {
                                    String algorithm = r.getAttributeValue(null, "Algorithm");
                                    if (algorithm == null || !ALLOWED_TRANSFORMS.contains(algorithm.trim())) {
                                        throw reject(what, "signature uses transform '" + algorithm
                                                + "'; only enveloped-signature and canonicalization are allowed");
                                    }
                                }
                                case "Manifest", "RetrievalMethod" -> throw reject(what,
                                        "signature uses ds:" + name.getLocalPart() + ", which a trusted list never does");
                                default -> { }
                            }
                        }
                    } else if (XMLDSIG_NS.equals(name.getNamespaceURI()) && "Signature".equals(name.getLocalPart())) {
                        if (++signatures > MAX_SIGNATURES) {
                            throw reject(what, "more than " + MAX_SIGNATURES + " signatures");
                        }
                        depthInSignature = 1;
                        references = 0;
                    }
                } else if (event == XMLStreamConstants.END_ELEMENT) {
                    if (depth > 0) {
                        depth--;
                    }
                    if (depthInSignature > 0) {
                        depthInSignature--;
                    }
                }
            }
            if (!rootSeen) {
                throw reject(what, "empty document");
            }
            return new Identity(sequenceNumber, issueDate);
        } catch (XMLStreamException e) {
            throw reject(what, "not well-formed XML (" + firstLine(e.getMessage()) + ")");
        } finally {
            if (r != null) {
                try {
                    r.close();
                } catch (XMLStreamException ignored) {
                    // nothing left to release
                }
            }
            try {
                in.close();
            } catch (IOException ignored) {
                // the caller's stream; best effort
            }
        }
    }

    private static Long parseSequenceNumber(String text) {
        try {
            return Long.parseLong(text.trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static Instant parseInstant(String text) {
        try {
            return java.time.OffsetDateTime.parse(text.trim()).toInstant();
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    private static DSSException reject(String what, String reason) {
        return new DSSException("'" + what + "' is not an acceptable trusted list: " + reason);
    }

    private static String firstLine(String s) {
        if (s == null) {
            return "?";
        }
        int nl = s.indexOf('\n');
        return (nl < 0 ? s : s.substring(0, nl)).trim();
    }
}
