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
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
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
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.PDFServiceMode;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxSignatureService;
import eu.europa.esig.dss.pdf.pdfbox.visible.PdfBoxSignatureDrawerFactory;
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
 *
 * <p>Reproducible: nothing depends on the current time or on unseeded randomness. Signing times are the start of
 * a fixture clock ({@link #DEFAULT_TIME}, or {@code --time=<instant>}); each timestamp, CRL and PDF file
 * identifier takes the next minute of that clock, in the order the generator asks for them; the ECDSA signatures
 * and the encrypted PDF's IVs come from a seeded {@link TestPki#deterministicRandom}. One thing is left to the JVM:
 * DSS collects the certificates and revocation data of a PAdES DSS dictionary in hash sets whose order follows
 * enum identity hash codes, which differ from one JVM to the next; run the generator with {@link #JVM_OPTIONS}
 * (every identity hash code is then 1) and it is fixed too. So with the same PKI, the same time, those JVM options
 * and the same JDK and dependencies, a regeneration gives the same bytes. {@code --out=<dir>} writes into another
 * directory (with a copy of the committed PKI and {@code stamp.jpg}), to compare a regeneration with the committed
 * files.
 */
public final class FixtureGenerator {

    /** Present in every signed payload; the tampered variants flip its first letter. */
    static final String MARKER = "DSS-NATIVE-SYNTHETIC-CONTENT";

    /** Where the fixture clock starts unless {@code --time=} says otherwise: the signing time of every fixture. */
    static final Instant DEFAULT_TIME = Instant.parse("2026-11-01T09:00:00Z");

    /**
     * HotSpot options for the JVM that runs the generator: every identity hash code is 1, so the order of DSS's
     * hash sets (and with it the PAdES DSS dictionaries) is the same in every run. Slow for identity-keyed maps,
     * harmless for one generator run.
     */
    public static final List<String> JVM_OPTIONS = List.of("-XX:+UnlockExperimentalVMOptions", "-XX:hashCode=2");

    private final Path out;
    private final TestPki pki;
    private final Instant start;
    private final SecureRandom random;
    private int ticks;
    private final FakeHttp http = new FakeHttp();
    private final CommonCertificateVerifier verifier = new CommonCertificateVerifier();
    private final KeyEntityTSPSource tsp;

    private FixtureGenerator(Path out, TestPki pki, Instant start) {
        this.out = out;
        this.pki = pki;
        this.start = start.truncatedTo(ChronoUnit.SECONDS);
        this.random = TestPki.deterministicRandom("dss-native fixtures/" + this.start);
        http.route(TestPki.CRL_URL, () -> TestPki.crl(pki.x509(Entity.ROOT_CA), pki.key(Entity.ROOT_CA), Map.of(),
                tick()));
        CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
        trusted.addCertificate(pki.token(Entity.ROOT_CA));
        verifier.setTrustedCertSources(trusted);
        OnlineCRLSource crl = new OnlineCRLSource();
        crl.setDataLoader(http);
        verifier.setCrlSource(crl);
        verifier.setOcspSource(null);
        verifier.setAIASource(null);
        tsp = new ClockTspSource(pki);
        tsp.setTsaPolicy(TestPki.TSA_POLICY);
    }

    /**
     * Arguments: {@code --new-pki} (also replace the PKI), {@code --signing-only} (only {@code signing/}, from the
     * {@code content/} already in the output directory), {@code --out=<dir>} (default {@code testdata/fixtures};
     * a directory without a PKI gets a copy of the committed one) and {@code --time=<ISO-8601 instant>} (default
     * {@link #DEFAULT_TIME}).
     */
    public static void main(String[] args) throws Exception {
        boolean newPki = false;
        boolean signingOnly = false;
        Path dir = Fixtures.dir();
        Instant time = DEFAULT_TIME;
        for (String arg : args) {
            if (arg.equals("--new-pki")) {
                newPki = true;
            } else if (arg.equals("--signing-only")) {
                signingOnly = true;
            } else if (arg.startsWith("--out=")) {
                dir = Path.of(arg.substring("--out=".length())).toAbsolutePath();
            } else if (arg.startsWith("--time=")) {
                time = Instant.parse(arg.substring("--time=".length()));
            } else {
                throw new IllegalArgumentException("unknown argument " + arg
                        + " (expected --new-pki, --signing-only, --out=<dir>, --time=<instant>)");
            }
        }
        if (System.identityHashCode(new Object()) != 1 || System.identityHashCode(new Object()) != 1) {
            System.err.println("warning: not reproducible: the PAdES LT/LTA fixtures depend on identity hash codes;"
                    + " run the generator in a JVM started with " + String.join(" ", JVM_OPTIONS));
        }
        prepareOutput(dir, newPki);
        Path stamp = dir.resolve("content/stamp.jpg");
        if (!Files.exists(stamp)) {
            // Drawn only when there is none: AWT's text rendering differs between machines, so redrawing it would
            // make the regeneration differ too. Delete it to redraw it.
            Files.createDirectories(stamp.getParent());
            Files.write(stamp, stampJpeg());
        }
        Path p12 = dir.resolve("pki/test-pki.p12");
        if (signingOnly) {
            FixtureGenerator generator = new FixtureGenerator(dir, TestPki.load(p12), time);
            generator.generateVisibleContent(false);
            generator.generateSigning();
            System.out.println("Signing fixtures written to " + dir.resolve("signing"));
            return;
        }
        TestPki pki = newPki || !Files.exists(p12) ? TestPki.generate(p12) : TestPki.load(p12);
        generateAll(dir, pki, time);
        System.out.println("Fixtures written to " + dir);
    }

    /**
     * For an output directory other than {@code testdata/fixtures}: copies the committed PKI (unless
     * {@code newPki}) and {@code content/stamp.jpg} into it, where missing, so a regeneration there compares
     * byte for byte with the committed files.
     */
    static void prepareOutput(Path dir, boolean newPki) throws IOException {
        if (!newPki) {
            copyIfMissing(TestPki.defaultLocation(), dir.resolve("pki/test-pki.p12"));
        }
        copyIfMissing(Fixtures.path("content/stamp.jpg"), dir.resolve("content/stamp.jpg"));
    }

    private static void copyIfMissing(Path from, Path to) throws IOException {
        if (!Files.exists(to) && Files.exists(from)) {
            Files.createDirectories(to.getParent());
            Files.copy(from, to, StandardCopyOption.COPY_ATTRIBUTES);
        }
    }

    /**
     * Everything but the PKI and {@code content/stamp.jpg}, which must be there already ({@link #prepareOutput}):
     * {@code pki/root-ca.pem}, the documents and {@code signing/}.
     */
    static void generateAll(Path out, TestPki pki, Instant time) throws Exception {
        Files.createDirectories(out.resolve("pki"));
        Files.writeString(out.resolve("pki/root-ca.pem"), pki.pem(Entity.ROOT_CA));
        new FixtureGenerator(out, pki, time).generateAll();
    }

    /**
     * The fixture clock: a minute after the previous call (the first: a minute after {@link #start}), so every
     * timestamp follows the signing time and the timestamp before it, and the revocation data follows them.
     */
    private Instant tick() {
        return start.plus(++ticks, ChronoUnit.MINUTES);
    }

    /** The test TSA, answering at the fixture clock's next minute with the tick count as serial number. */
    private final class ClockTspSource extends KeyEntityTSPSource {
        ClockTspSource(TestPki pki) {
            super(pki.key(Entity.TSA), pki.x509(Entity.TSA), List.of(pki.x509(Entity.TSA), pki.x509(Entity.ROOT_CA)));
        }

        @Override
        protected Date getProductionTime() {
            return Date.from(tick());
        }

        @Override
        protected BigInteger getTimeStampSerialNumber() {
            return BigInteger.valueOf(ticks);
        }
    }

    /**
     * PDFBox derives the second half of a file identifier from the current time when the caller sets no document
     * id; DSS sets one for signatures (from the signing time), not for the DSS dictionary of an extension. This
     * factory's services fill the gap from the fixture clock.
     */
    private final class ClockPdfObjFactory extends PdfBoxNativeObjectFactory {
        @Override
        public PDFSignatureService newPAdESSignatureService() {
            return configure(new ClockPdfSignatureService(PDFServiceMode.SIGNATURE, getSignatureDrawerFactory()));
        }

        @Override
        public PDFSignatureService newContentTimestampService() {
            return configure(new ClockPdfSignatureService(PDFServiceMode.CONTENT_TIMESTAMP,
                    getSignatureDrawerFactory()));
        }

        @Override
        public PDFSignatureService newSignatureTimestampService() {
            return configure(new ClockPdfSignatureService(PDFServiceMode.SIGNATURE_TIMESTAMP,
                    getSignatureDrawerFactory()));
        }

        @Override
        public PDFSignatureService newArchiveTimestampService() {
            return configure(new ClockPdfSignatureService(PDFServiceMode.ARCHIVE_TIMESTAMP,
                    getSignatureDrawerFactory()));
        }
    }

    private final class ClockPdfSignatureService extends PdfBoxSignatureService {
        ClockPdfSignatureService(PDFServiceMode mode, PdfBoxSignatureDrawerFactory drawers) {
            super(mode, drawers);
        }

        @Override
        public void saveDocumentIncrementally(PDDocument pdDocument, OutputStream outputStream) {
            if (pdDocument.getDocumentId() == null) {
                pdDocument.setDocumentId(tick().toEpochMilli());
            }
            super.saveDocumentIncrementally(pdDocument, outputStream);
        }
    }

    /** Timestamp parameters whose date (the /M of a document timestamp, and its file identifier) is given. */
    private static final class FixedTimePAdESTimestampParameters extends PAdESTimestampParameters {
        FixedTimePAdESTimestampParameters(Instant date) {
            this.timestampDate = Date.from(date);
        }
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
        // Revocation must be issued strictly after the signature timestamp: the fixture clock sees to that.
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
        ticks = 0; // the clock restarts, so --signing-only writes what a full run writes here
        String time = "\"signing_time\":\"" + start + "\"";
        String certificates = "\"signing_certificate\":\"" + base64(pki.x509(Entity.SIGNER_RSA).getEncoded())
                + "\",\"certificate_chain\":[\"" + base64(pki.x509(Entity.ROOT_CA).getEncoded()) + "\"]";
        ExternalSigner signer = new ExternalSigner(pki, Entity.SIGNER_RSA, this::tick);
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
     * Documents for visible signatures: a form with an empty signature field ({@code Firma1}) and a text field, a
     * page turned by {@code /Rotate 90} and an owner-password-protected copy of the document. With {@code overwrite}
     * false, existing files are kept: signing fixtures depend on them. The JPEG for visible signatures
     * ({@code content/stamp.jpg}, the only fixture made with ImageIO, which the native tests cannot use) is drawn
     * by {@link #main} only when missing.
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
    }

    private byte[] formPdf() throws IOException {
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
            doc.setDocumentId(documentId());
            doc.save(bos);
            return bos.toByteArray();
        }
    }

    private byte[] rotatedPdf() throws IOException {
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
            doc.setDocumentId(documentId());
            doc.save(bos);
            return bos.toByteArray();
        }
    }

    /** Opens without a password (empty user password), so it can be signed; the owner password restricts nothing. */
    private byte[] protectedPdf(byte[] pdf) throws IOException {
        try (PDDocument doc = Loader.loadPDF(pdf); ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            StandardProtectionPolicy policy = new StandardProtectionPolicy("owner-secret", "", new AccessPermission());
            policy.setEncryptionKeyLength(128);
            doc.protect(policy);
            doc.getEncryption().getSecurityHandler().setCustomSecureRandom(random); // the AES IVs
            doc.setDocumentId(documentId());
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

    /** For PDFBox's file identifier of a new document, which it would otherwise derive from the current time. */
    private long documentId() {
        return start.toEpochMilli();
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
        p.bLevel().setSigningDate(Date.from(start));
        CAdESService service = new CAdESService(verifier);
        ToBeSigned tbs = service.getDataToSign(doc, p);
        return service.signDocument(doc, p, Signing.sign(tbs, p.getDigestAlgorithm(), pki.key(signer), random));
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

    private byte[] basePdf() throws IOException {
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
            doc.setDocumentId(documentId());
            doc.save(bos, CompressParameters.NO_COMPRESSION);
            return bos.toByteArray();
        }
    }

    private PAdESService padesService() {
        PAdESService service = new PAdESService(verifier);
        service.setTspSource(tsp);
        service.setPdfObjFactory(new ClockPdfObjFactory());
        return service;
    }

    private PAdESSignatureParameters padesParams(SignatureLevel level) {
        PAdESSignatureParameters p = new PAdESSignatureParameters();
        p.setSignatureLevel(level);
        p.setDigestAlgorithm(DigestAlgorithm.SHA256);
        p.setSigningCertificate(pki.token(Entity.SIGNER_RSA));
        p.setCertificateChain(pki.chain(Entity.SIGNER_RSA));
        p.bLevel().setSigningDate(Date.from(start));
        if (level == SignatureLevel.PAdES_BASELINE_LTA) {
            p.setArchiveTimestampParameters(new FixedTimePAdESTimestampParameters(tick()));
        }
        p.setReason("dss-native fixture");
        return p;
    }

    private byte[] pades(byte[] pdf, SignatureLevel level) {
        PAdESService service = padesService();
        PAdESSignatureParameters p = padesParams(level);
        DSSDocument doc = new InMemoryDocument(pdf, "document.pdf");
        ToBeSigned tbs = service.getDataToSign(doc, p);
        return DSSUtils.toByteArray(service.signDocument(doc, p,
                Signing.sign(tbs, p.getDigestAlgorithm(), pki.key(Entity.SIGNER_RSA), random)));
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
