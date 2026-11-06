/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.testsupport;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.EnumSet;
import java.util.List;
import java.util.function.Function;

import javax.imageio.ImageIO;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdfwriter.compress.CompressParameters;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentInformation;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.encryption.AccessPermission;
import org.apache.pdfbox.pdmodel.encryption.StandardProtectionPolicy;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.apache.pdfbox.pdmodel.interactive.form.PDTextField;
import org.apache.pdfbox.util.Matrix;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.KeyEntityTSPSource;

import it.codingduck.dssnative.engine.DssEngine;
import it.codingduck.dssnative.engine.PreparedSignature;
import it.codingduck.dssnative.engine.SigningOptions;
import it.codingduck.dssnative.testsupport.TestPki.Entity;

/**
 * Writes the committed synthetic fixtures under {@code testdata/fixtures/}. Run via
 * {@code scripts/generate-fixtures.sh}; pass {@code --new-pki} to also replace the test PKI, or
 * {@code --signing-only} to write only {@code signing/} (from the committed content and PKI).
 *
 * <p>Every signed file has a {@code tampered/} twin in which one byte of the signed content was changed.
 * The marker string makes that byte easy to find in DER, BER (chunked) and uncompressed PDF content.
 */
public final class FixtureGenerator {

    /** Present in every signed payload; the tampered variants flip its first letter. */
    static final String MARKER = "DSS-NATIVE-SYNTHETIC-CONTENT";

    private final Path out;
    private final TestPki pki;
    private final FakeHttp http = new FakeHttp();
    private final CommonCertificateVerifier verifier = new CommonCertificateVerifier();
    private final KeyEntityTSPSource tsp;

    private FixtureGenerator(Path out, TestPki pki) {
        this.out = out;
        this.pki = pki;
        http.route(TestPki.CRL_URL, pki::freshCrl);
        CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
        trusted.addCertificate(pki.token(Entity.ROOT_CA));
        verifier.setTrustedCertSources(trusted);
        OnlineCRLSource crl = new OnlineCRLSource();
        crl.setDataLoader(http);
        verifier.setCrlSource(crl);
        verifier.setOcspSource(null);
        verifier.setAIASource(null);
        tsp = new KeyEntityTSPSource(pki.key(Entity.TSA), pki.x509(Entity.TSA),
                List.of(pki.x509(Entity.TSA), pki.x509(Entity.ROOT_CA)));
        tsp.setTsaPolicy("1.3.6.1.4.1.99999.1.1"); // arbitrary test policy OID
    }

    public static void main(String[] args) throws Exception {
        boolean newPki = List.of(args).contains("--new-pki");
        Path dir = Fixtures.dir();
        Path p12 = TestPki.defaultLocation();
        if (List.of(args).contains("--signing-only")) {
            FixtureGenerator generator = new FixtureGenerator(dir, TestPki.load(p12));
            generator.generateVisibleContent(false);
            generator.generateSigning();
            System.out.println("Signing fixtures written to " + dir.resolve("signing"));
            return;
        }
        TestPki pki = newPki || !Files.exists(p12) ? TestPki.generate(p12) : TestPki.load(p12);
        Files.writeString(dir.resolve("pki/root-ca.pem"), pki.pem(Entity.ROOT_CA));
        new FixtureGenerator(dir, pki).generateAll();
        System.out.println("Fixtures written to " + dir);
    }

    private void generateAll() throws Exception {
        byte[] text = (MARKER + "\nSynthetic document for dss-native tests. Contains no personal data.\n")
                .getBytes(StandardCharsets.US_ASCII);
        byte[] pdf = basePdf();
        write("content/document.txt", text);
        write("content/document.pdf", pdf);
        write("tampered/content/document.txt", tamper(text));
        generateVisibleContent(true);

        // --- CAdES
        byte[] der = toDer(cades(text, Entity.SIGNER_RSA, SignaturePackaging.ENVELOPING));
        write("cades/attached-der.p7m", der);
        write("tampered/cades/attached-der.p7m", tamper(der));

        byte[] ber = toIndefiniteLengthBer(der);
        write("cades/attached-ber.p7m", ber);
        write("tampered/cades/attached-ber.p7m", tamper(ber));

        write("cades/attached-base64.p7m", base64Lines(der));
        write("tampered/cades/attached-base64.p7m", base64Lines(tamper(der)));

        byte[] detached = toDer(cades(text, Entity.SIGNER_RSA, SignaturePackaging.DETACHED));
        write("cades/detached.txt.p7s", detached);

        // The EC signer wraps the RSA signer's envelope: .p7m.p7m
        // Signed over a DigestDocument: given the CMS bytes themselves, DSS would add a parallel signer instead.
        DigestDocument innerDigest = new DigestDocument(DigestAlgorithm.SHA256,
                Base64.getEncoder().encodeToString(DSSUtils.digest(DigestAlgorithm.SHA256, der)), "inner.p7m");
        byte[] nested = attachContent(toDer(cades(innerDigest, Entity.SIGNER_EC, SignaturePackaging.DETACHED)), der);
        write("cades/nested.p7m.p7m", nested);
        write("tampered/cades/nested.p7m.p7m", tamper(nested));

        // Two parallel signers over the same content (DSS adds a SignerInfo to an existing envelope).
        byte[] multi = toDer(cades(der, Entity.SIGNER_EC, SignaturePackaging.ENVELOPING));
        write("cades/multi-signer.p7m", multi);
        write("tampered/cades/multi-signer.p7m", tamper(multi));

        // --- PAdES
        byte[] bb = pades(pdf, SignatureLevel.PAdES_BASELINE_B);
        byte[] bt = pades(pdf, SignatureLevel.PAdES_BASELINE_T);
        Thread.sleep(1500); // revocation must be issued strictly after the signature timestamp
        byte[] blt = extend(bt, SignatureLevel.PAdES_BASELINE_LT);
        byte[] blta = extend(blt, SignatureLevel.PAdES_BASELINE_LTA);
        for (var e : List.of(new Object[] {"b-b", bb}, new Object[] {"b-t", bt}, new Object[] {"b-lt", blt},
                new Object[] {"b-lta", blta})) {
            write("pades/" + e[0] + ".pdf", (byte[]) e[1]);
            write("tampered/pades/" + e[0] + ".pdf", tamper((byte[]) e[1]));
        }

        generateSigning();
    }

    // ------------------------------------------------------------------ signing with an external signer

    /**
     * For the tests that cannot sign themselves (C, Rust): per case, {@code signing/<case>.json} holds the
     * {@code options_json} for {@code dss_sign_prepare}/{@code dss_sign_complete}, with a fixed signing time, and
     * {@code signing/<case>.sig} what an {@link ExternalSigner} returned for the digest prepare gave. RSA
     * PKCS#1 v1.5 and DSS's PDF preparation are deterministic, so completing with these files works as long as
     * preparing gives the same digest: they double as a check of that.
     */
    private void generateSigning() throws Exception {
        byte[] pdf = Files.readAllBytes(out.resolve("content/document.pdf"));
        byte[] text = Files.readAllBytes(out.resolve("content/document.txt"));
        String time = "\"signing_time\":\"" + Instant.now().truncatedTo(ChronoUnit.SECONDS) + "\"";
        String certificates = "\"signing_certificate\":\"" + base64(pki.x509(Entity.SIGNER_RSA).getEncoded())
                + "\",\"certificate_chain\":[\"" + base64(pki.x509(Entity.ROOT_CA).getEncoded()) + "\"]";
        ExternalSigner signer = new ExternalSigner(pki, Entity.SIGNER_RSA);
        Path work = Files.createTempDirectory("dss-native-fixtures");
        try (DssEngine engine = new TestEngines(work).engine(work.resolve("cache"), null)) {
            signingCase(engine, "pades-signature-value", pdf, "{\"mode\":\"signature_value\",\"level\":\"B\","
                    + time + "," + certificates + "}", p -> signer.signatureValue(p.digestAlgorithm(), p.digest(), false));
            signingCase(engine, "pades-cms", pdf, "{\"mode\":\"cms\",\"level\":\"B\"," + time + "}",
                    p -> signer.cms(p.digestAlgorithm(), p.digest(), EnumSet.of(ExternalSigner.Cms.TIMESTAMP,
                            ExternalSigner.Cms.BER)));
            signingCase(engine, "cades-cms", text, "{\"mode\":\"cms\",\"level\":\"B\"," + time + "}",
                    p -> signer.cms(p.digestAlgorithm(), p.digest(), EnumSet.of(ExternalSigner.Cms.SIGNING_TIME,
                            ExternalSigner.Cms.TIMESTAMP, ExternalSigner.Cms.BER)));
            signingCase(engine, "cades-signature-value", text, "{\"mode\":\"signature_value\",\"level\":\"B\","
                    + "\"packaging\":\"enveloping\"," + time + "," + certificates + "}",
                    p -> signer.signatureValue(p.digestAlgorithm(), p.digest(), false));
            // Visible signatures: completing them also checks that the native library draws the appearance
            // byte for byte like the JVM, without AWT (the Rust tests and the C smoke test run without libawt).
            String png = base64(TestImages.png(160, 80, 6, 8, false));
            signingCase(engine, "pades-visible-cms", pdf, "{\"mode\":\"cms\",\"level\":\"B\"," + time
                    + ",\"pades\":{\"signer_name\":\"Mario Rossi\",\"visible\":{\"page\":1,\"x\":300,\"y\":650,"
                    + "\"width\":240,\"height\":80,\"text\":\"Firmato digitalmente da {signer_name}\\n{signing_time}\","
                    + "\"time_zone\":\"Europe/Rome\",\"image\":\"" + png + "\",\"background_color\":\"#F0F4FF\"}}}",
                    p -> signer.cms(p.digestAlgorithm(), p.digest(), EnumSet.noneOf(ExternalSigner.Cms.class)));
            byte[] form = Files.readAllBytes(out.resolve("content/form.pdf"));
            String jpeg = base64(Files.readAllBytes(out.resolve("content/stamp.jpg")));
            signingCase(engine, "pades-visible-field-signature-value", form, "{\"mode\":\"signature_value\","
                    + "\"level\":\"B\"," + time + "," + certificates + ",\"pades\":{\"reason\":\"Approvazione\","
                    + "\"visible\":{\"field\":\"Firma1\",\"text\":\"{signer_name}\\n{reason}\",\"text_align\":"
                    + "\"center\",\"image\":\"" + jpeg + "\",\"image_position\":\"behind\"}}}",
                    p -> signer.signatureValue(p.digestAlgorithm(), p.digest(), false));
        }
    }

    private void signingCase(DssEngine engine, String name, byte[] document, String optionsJson,
                             Function<PreparedSignature, byte[]> signer) throws IOException {
        SigningOptions options = SigningOptions.fromJson(optionsJson);
        byte[] external = signer.apply(engine.prepareSignature(document, options));
        engine.completeSignature(document, options, external); // fails here rather than in the tests
        write("signing/" + name + ".json", optionsJson.getBytes(StandardCharsets.UTF_8));
        write("signing/" + name + ".sig", external);
    }

    // ------------------------------------------------------------------ visible signatures

    /**
     * Documents and an image for visible signatures: a form with an empty signature field ({@code Firma1}) and a
     * text field, a page turned by {@code /Rotate 90}, an owner-password-protected copy of the document, and a
     * JPEG (the only fixture made with ImageIO, which the native tests cannot use). With {@code overwrite} false,
     * existing files are kept: signing fixtures depend on them.
     */
    private void generateVisibleContent(boolean overwrite) throws IOException {
        if (overwrite || !Files.exists(out.resolve("content/form.pdf"))) {
            write("content/form.pdf", formPdf());
        }
        if (overwrite || !Files.exists(out.resolve("content/rotated.pdf"))) {
            write("content/rotated.pdf", rotatedPdf());
        }
        if (overwrite || !Files.exists(out.resolve("content/protected.pdf"))) {
            write("content/protected.pdf", protectedPdf(Files.readAllBytes(out.resolve("content/document.pdf"))));
        }
        if (overwrite || !Files.exists(out.resolve("content/stamp.jpg"))) {
            write("content/stamp.jpg", stampJpeg());
        }
    }

    private static byte[] formPdf() throws IOException {
        try (PDDocument doc = new PDDocument(); ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            PDPage page = new PDPage();
            doc.addPage(page);
            try (PDPageContentStream cs = new PDPageContentStream(doc, page)) {
                cs.beginText();
                cs.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
                cs.newLineAtOffset(72, 720);
                cs.showText("Synthetic form for dss-native tests. Sign in the box below.");
                cs.endText();
                cs.addRect(350, 80, 200, 60);
                cs.stroke();
            }
            PDAcroForm form = new PDAcroForm(doc);
            doc.getDocumentCatalog().setAcroForm(form);
            PDSignatureField signature = new PDSignatureField(form);
            signature.setPartialName("Firma1");
            PDAnnotationWidget widget = signature.getWidgets().get(0);
            widget.setRectangle(new PDRectangle(350, 80, 200, 60));
            widget.setPage(page);
            widget.setPrinted(true);
            page.getAnnotations().add(widget);
            form.getFields().add(signature);
            PDTextField name = new PDTextField(form);
            name.setPartialName("Nome");
            PDAnnotationWidget nameWidget = name.getWidgets().get(0);
            nameWidget.setRectangle(new PDRectangle(72, 600, 200, 20));
            nameWidget.setPage(page);
            page.getAnnotations().add(nameWidget);
            form.getFields().add(name);
            doc.save(bos);
            return bos.toByteArray();
        }
    }

    private static byte[] rotatedPdf() throws IOException {
        try (PDDocument doc = new PDDocument(); ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            PDPage page = new PDPage(PDRectangle.A4);
            page.setRotation(90);
            doc.addPage(page);
            try (PDPageContentStream cs = new PDPageContentStream(doc, page)) {
                cs.beginText();
                cs.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
                // Upright as displayed: the page turns clockwise, so the text runs up the short edge.
                cs.setTextMatrix(new Matrix(0, 1, -1, 0, 100, 72));
                cs.showText("Synthetic landscape page (/Rotate 90) for dss-native tests.");
                cs.endText();
            }
            doc.save(bos);
            return bos.toByteArray();
        }
    }

    /** Opens without a password (empty user password), so it can be signed; the owner password restricts nothing. */
    private static byte[] protectedPdf(byte[] pdf) throws IOException {
        try (PDDocument doc = Loader.loadPDF(pdf); ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            StandardProtectionPolicy policy = new StandardProtectionPolicy("owner-secret", "", new AccessPermission());
            policy.setEncryptionKeyLength(128);
            doc.protect(policy);
            doc.save(bos);
            return bos.toByteArray();
        }
    }

    private static byte[] stampJpeg() throws IOException {
        BufferedImage image = new BufferedImage(160, 80, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = image.createGraphics();
        try {
            g.setColor(new Color(0xF4, 0xE8, 0xD0));
            g.fillRect(0, 0, 160, 80);
            g.setColor(new Color(0x20, 0x40, 0x90));
            g.setStroke(new BasicStroke(3));
            g.drawOval(10, 5, 140, 70);
            g.drawString("DSS-NATIVE", 45, 45);
        } finally {
            g.dispose();
        }
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ImageIO.write(image, "jpg", bos);
        return bos.toByteArray();
    }

    private static String base64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    // ------------------------------------------------------------------ CAdES

    private DSSDocument cades(byte[] content, Entity signer, SignaturePackaging packaging) {
        return cades(new InMemoryDocument(content, "content"), signer, packaging);
    }

    private DSSDocument cades(DSSDocument doc, Entity signer, SignaturePackaging packaging) {
        CAdESSignatureParameters p = new CAdESSignatureParameters();
        p.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        p.setSignaturePackaging(packaging);
        p.setDigestAlgorithm(DigestAlgorithm.SHA256);
        p.setSigningCertificate(pki.token(signer));
        p.setCertificateChain(pki.chain(signer));
        p.bLevel().setSigningDate(new Date());
        CAdESService service = new CAdESService(verifier);
        ToBeSigned tbs = service.getDataToSign(doc, p);
        return service.signDocument(doc, p, Signing.sign(tbs, p.getDigestAlgorithm(), pki.key(signer)));
    }

    private static byte[] toDer(DSSDocument cms) throws IOException {
        return ContentInfo.getInstance(DSSUtils.toByteArray(cms)).getEncoded(ASN1Encoding.DER);
    }

    /**
     * Re-encodes the outer CMS layers with indefinite lengths and chunks the content into a constructed OCTET
     * STRING, like streaming signers (smart-card tools common in Italy) do. SignerInfos stay DER: their signed
     * attributes are what the signature covers.
     */
    static byte[] toIndefiniteLengthBer(byte[] der) throws IOException {
        ContentInfo ci = ContentInfo.getInstance(der);
        SignedData sd = SignedData.getInstance(ci.getContent());
        ContentInfo eci = sd.getEncapContentInfo();
        byte[] content = ((ASN1OctetString) eci.getContent()).getOctets();

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(sd.getVersion());
        v.add(sd.getDigestAlgorithms());
        v.add(new BERSequence(new ASN1Encodable[] {
                eci.getContentType(), new BERTaggedObject(true, 0, new BEROctetString(content, 64))}));
        if (sd.getCertificates() != null) {
            v.add(new BERTaggedObject(false, 0, new BERSet(sd.getCertificates().toArray())));
        }
        if (sd.getCRLs() != null) {
            v.add(new BERTaggedObject(false, 1, new BERSet(sd.getCRLs().toArray())));
        }
        v.add(sd.getSignerInfos());
        BERSequence outer = new BERSequence(new ASN1Encodable[] {
                ci.getContentType(), new BERTaggedObject(true, 0, new BERSequence(v))});
        byte[] ber = outer.getEncoded(ASN1Encoding.BER);
        if ((ber[1] & 0xFF) != 0x80) {
            throw new IllegalStateException("expected indefinite-length encoding");
        }
        return ber;
    }

    /** Turns a detached CMS into an attached one by putting {@code content} back into encapContentInfo. */
    static byte[] attachContent(byte[] detachedDer, byte[] content) throws IOException {
        ContentInfo ci = ContentInfo.getInstance(detachedDer);
        SignedData sd = SignedData.getInstance(ci.getContent());
        ContentInfo eci = new ContentInfo(CMSObjectIdentifiers.data, new DEROctetString(content));
        SignedData attached = new SignedData(sd.getDigestAlgorithms(), eci, sd.getCertificates(), sd.getCRLs(),
                sd.getSignerInfos());
        return new DERSequence(new ASN1Encodable[] {
                CMSObjectIdentifiers.signedData, new DERTaggedObject(true, 0, attached)}).getEncoded(ASN1Encoding.DER);
    }

    private static byte[] base64Lines(byte[] der) {
        return (Base64.getMimeEncoder(76, "\r\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der) + "\r\n")
                .getBytes(StandardCharsets.US_ASCII);
    }

    // ------------------------------------------------------------------ PAdES

    private static byte[] basePdf() throws IOException {
        try (PDDocument doc = new PDDocument(); ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            PDPage page = new PDPage();
            doc.addPage(page);
            // Uncompressed content stream so the tampering step can find the marker.
            try (PDPageContentStream cs = new PDPageContentStream(doc, page, PDPageContentStream.AppendMode.OVERWRITE,
                    false)) {
                cs.beginText();
                cs.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
                cs.newLineAtOffset(72, 720);
                cs.showText(MARKER);
                cs.newLineAtOffset(0, -18);
                cs.showText("Synthetic document for dss-native tests. Contains no personal data.");
                cs.endText();
            }
            PDDocumentInformation info = doc.getDocumentInformation();
            info.setTitle("dss-native synthetic fixture");
            doc.save(bos, CompressParameters.NO_COMPRESSION);
            return bos.toByteArray();
        }
    }

    private PAdESService padesService() {
        PAdESService service = new PAdESService(verifier);
        service.setTspSource(tsp);
        service.setPdfObjFactory(new PdfBoxNativeObjectFactory());
        return service;
    }

    private PAdESSignatureParameters padesParams(SignatureLevel level) {
        PAdESSignatureParameters p = new PAdESSignatureParameters();
        p.setSignatureLevel(level);
        p.setDigestAlgorithm(DigestAlgorithm.SHA256);
        p.setSigningCertificate(pki.token(Entity.SIGNER_RSA));
        p.setCertificateChain(pki.chain(Entity.SIGNER_RSA));
        p.bLevel().setSigningDate(new Date());
        p.setReason("dss-native fixture");
        return p;
    }

    private byte[] pades(byte[] pdf, SignatureLevel level) {
        PAdESService service = padesService();
        PAdESSignatureParameters p = padesParams(level);
        DSSDocument doc = new InMemoryDocument(pdf, "document.pdf");
        ToBeSigned tbs = service.getDataToSign(doc, p);
        return DSSUtils.toByteArray(service.signDocument(doc, p,
                Signing.sign(tbs, p.getDigestAlgorithm(), pki.key(Entity.SIGNER_RSA))));
    }

    private byte[] extend(byte[] pdf, SignatureLevel level) {
        return DSSUtils.toByteArray(padesService().extendDocument(new InMemoryDocument(pdf, "document.pdf"),
                padesParams(level)));
    }

    // ------------------------------------------------------------------ helpers

    /** Flips the first letter of the first marker occurrence ('D' → 'X'), keeping the length. */
    static byte[] tamper(byte[] signed) {
        byte[] marker = MARKER.getBytes(StandardCharsets.US_ASCII);
        byte[] copy = signed.clone();
        for (int i = 0; i + marker.length <= copy.length; i++) {
            boolean match = true;
            for (int j = 0; j < marker.length && match; j++) {
                match = copy[i + j] == marker[j];
            }
            if (match) {
                copy[i] = 'X';
                return copy;
            }
        }
        throw new IllegalStateException("marker not found; cannot tamper");
    }

    private void write(String relative, byte[] bytes) throws IOException {
        Path p = out.resolve(relative);
        Files.createDirectories(p.getParent());
        Files.write(p, bytes);
    }
}
