/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import eu.europa.esig.dss.model.DSSException;

import it.codingduck.dssnative.testsupport.SyntheticTrustedLists;
import it.codingduck.dssnative.testsupport.TestEngines;

/** The pre-check every downloaded or cached list goes through before DSS parses it. */
class TlDocumentCheckTest {

    @TempDir
    Path tmp;

    private static void ok(String xml) {
        TlDocumentCheck.check(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)), "test");
    }

    private static String rejected(String body) {
        DSSException e = assertThrows(DSSException.class,
                () -> TlDocumentCheck.check(new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)), "test"));
        assertTrue(e.getMessage().contains("not an acceptable trusted list"), e.getMessage());
        return e.getMessage();
    }

    private String signedLotl() {
        TestEngines t = new TestEngines(tmp);
        String xml = new String(new SyntheticTrustedLists(t.pki, 1).lotl(), StandardCharsets.UTF_8);
        assertTrue(xml.contains("xmldsig#enveloped-signature"), "the synthetic list is signed as real ones are");
        return xml;
    }

    @Test
    void realShapedListsPass() {
        String lotl = signedLotl();
        ok(lotl);
        TestEngines t = new TestEngines(tmp);
        ok(new String(new SyntheticTrustedLists(t.pki, 1).tl("IT", it.codingduck.dssnative.testsupport.TestPki.Entity.ROOT_CA,
                it.codingduck.dssnative.testsupport.TestPki.Entity.TSA), StandardCharsets.UTF_8));
        // Unsigned is structurally fine: DSS then refuses the signature, which is its decision to make.
        ok("<?xml version=\"1.0\"?><tsl:TrustServiceStatusList xmlns:tsl=\"http://uri.etsi.org/02231/v2#\"/>");
    }

    /** The rollback protection compares what the same pass reads from the list's SchemeInformation. */
    @Test
    void sequenceNumberAndIssueDateAreRead() {
        TestEngines t = new TestEngines(tmp);
        byte[] lotl = new SyntheticTrustedLists(t.pki, 42).lotl();
        TlDocumentCheck.Identity id = TlDocumentCheck.check(new ByteArrayInputStream(lotl), "test");
        assertEquals(42L, id.sequenceNumber());
        assertNotNull(id.issueDate());
        assertTrue(id.issueDate().isBefore(java.time.Instant.now()), id.toString());

        String tsl = "<tsl:TrustServiceStatusList xmlns:tsl=\"http://uri.etsi.org/02231/v2#\">";
        // Absent, unreadable, or in the wrong place: unknown, for DSS to flag.
        assertEquals(TlDocumentCheck.Identity.UNKNOWN, TlDocumentCheck.check(new ByteArrayInputStream(
                (tsl + "<tsl:SchemeInformation/></tsl:TrustServiceStatusList>").getBytes(StandardCharsets.UTF_8)), "test"));
        assertEquals(TlDocumentCheck.Identity.UNKNOWN, TlDocumentCheck.check(new ByteArrayInputStream(
                (tsl + "<tsl:SchemeInformation><tsl:TSLSequenceNumber>x</tsl:TSLSequenceNumber>"
                        + "<tsl:ListIssueDateTime>yesterday</tsl:ListIssueDateTime></tsl:SchemeInformation>"
                        + "</tsl:TrustServiceStatusList>").getBytes(StandardCharsets.UTF_8)), "test"));
        assertEquals(TlDocumentCheck.Identity.UNKNOWN, TlDocumentCheck.check(new ByteArrayInputStream(
                (tsl + "<tsl:TrustServiceProviderList><tsl:TSLSequenceNumber>7</tsl:TSLSequenceNumber>"
                        + "</tsl:TrustServiceProviderList><tsl:SchemeInformation><tsl:Nested><tsl:TSLSequenceNumber>8"
                        + "</tsl:TSLSequenceNumber></tsl:Nested></tsl:SchemeInformation></tsl:TrustServiceStatusList>")
                        .getBytes(StandardCharsets.UTF_8)), "test"));
        TlDocumentCheck.Identity plain = TlDocumentCheck.check(new ByteArrayInputStream(
                (tsl + "<tsl:SchemeInformation><tsl:TSLVersionIdentifier>6</tsl:TSLVersionIdentifier>"
                        + "<tsl:TSLSequenceNumber> 314 </tsl:TSLSequenceNumber>"
                        + "<tsl:ListIssueDateTime>2026-03-04T05:06:07Z</tsl:ListIssueDateTime></tsl:SchemeInformation>"
                        + "</tsl:TrustServiceStatusList>").getBytes(StandardCharsets.UTF_8)), "test");
        assertEquals(new TlDocumentCheck.Identity(314L, java.time.Instant.parse("2026-03-04T05:06:07Z")), plain);
    }

    @Test
    void nonXmlAndForeignRootsAreRejected() {
        assertTrue(rejected("not xml at all: 502 Bad Gateway").contains("not well-formed XML"));
        assertTrue(rejected("<html><body>captive portal</body></html>").contains("root element"));
        rejected("");
        rejected("<?xml version=\"1.0\"?><TrustServiceStatusList/>"); // right name, no namespace
        String truncated = signedLotl();
        rejected(truncated.substring(0, truncated.length() / 2));
    }

    @Test
    void dtdsAreRejected() {
        rejected("<?xml version=\"1.0\"?><!DOCTYPE tsl [<!ENTITY x \"y\">]>"
                + "<tsl:TrustServiceStatusList xmlns:tsl=\"http://uri.etsi.org/02231/v2#\"/>");
    }

    @Test
    void hostileSignatureTransformsAreRejected() {
        String lotl = signedLotl();
        String xpath = lotl.replace("http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                "http://www.w3.org/TR/1999/REC-xpath-19991116");
        assertTrue(rejected(xpath).contains("transform"));
        String xslt = lotl.replace("http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                "http://www.w3.org/TR/1999/REC-xslt-19991116");
        rejected(xslt);
        String filter2 = lotl.replace("http://www.w3.org/2001/10/xml-exc-c14n#", "http://www.w3.org/2002/06/xmldsig-filter2");
        rejected(filter2);
    }

    @Test
    void manifestsAndReferenceFloodsAreRejected() {
        String lotl = signedLotl();
        int end = lotl.indexOf("</ds:Signature>");
        assertTrue(end > 0, "ds: prefix expected in DSS's output");
        String manifest = lotl.substring(0, end) + "<ds:Object><ds:Manifest Id=\"m\"/></ds:Object>" + lotl.substring(end);
        assertTrue(rejected(manifest).contains("Manifest"));
        String retrieval = lotl.substring(0, end) + "<ds:KeyInfo><ds:RetrievalMethod URI=\"#x\"/></ds:KeyInfo>" + lotl.substring(end);
        rejected(retrieval);

        int signedInfoEnd = lotl.indexOf("</ds:SignedInfo>");
        String flood = lotl.substring(0, signedInfoEnd)
                + "<ds:Reference URI=\"\"/><ds:Reference URI=\"\"/><ds:Reference URI=\"\"/><ds:Reference URI=\"\"/>"
                + lotl.substring(signedInfoEnd);
        assertTrue(rejected(flood).contains("references"));
    }
}
