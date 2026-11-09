# Reflection and resource audit

What DSS 6.5.1 and its runtime dependencies do reflectively, which of it the native image needs metadata for,
and where that metadata comes from. Written in Phase 2 (2026-10-28) and updated with each feature since: the
counts and the agent runs were last redone for trusted-list snapshots (2026-11-06), against GraalVM CE 25.4.4.1.1;
the trusted-list pre-check note under "JDK" was added after the audit of 2026-11-09 without a new agent run. The
build now pins GraalVM CE 25.5.5.0.3 (DECISIONS.md, Phase 0); the native test suite in `Exit` mode is what
confirms the metadata on it.

## Method

Three independent sources, each covering the others' blind spots (Phase 2; updated in Phase 3):

1. **Source grep** of every runtime dependency (`scripts/audit-reflection.sh`). It covers 60 source jars and 822
   call sites of `Class.forName`, `getDeclared*`/`getMethod`/`getField`/`getConstructor`, `newInstance`,
   `loadClass`, `ServiceLoader.load`, `getResource*`, `ResourceBundle.getBundle`, `Proxy.newProxyInstance`,
   `JAXBContext.newInstance`, `Security.addProvider` and `MethodHandles.lookup`. Exhaustive, but blind to
   reachability.
2. **`-H:TrackDynamicAccess=all`** while building the native test image. GraalVM lists the call sites that are
   *reachable in our image* and whose arguments it could **not** constant-fold. This is the authoritative
   "data-driven" list. Output: `java/target/dynamic-access/<jar>/{reflection,resource}-calls.json`. A one-off
   build option, passed by hand: no script or Maven profile sets it.
3. **Tracing agent** over the JVM test suite (`scripts/run-agent.sh`; `--online` adds the real-LOTL suite).
   It records what actually happened at run time, including on behalf of data-driven calls.
   `scripts/merge-metadata.py` folds it into `reachability-metadata.json`, minus what the Feature covers.

The result is checked by:
- the native test suite, built with `--exact-reachability-metadata` and run with
  `-XX:MissingRegistrationReportingMode=Exit`, and re-run by hand under foreign locales and time zones
  (it_IT/Rome, fr_FR/Paris, ja_JP/Tokyo; `scripts/run-native-tests.sh` shows how, CI does not do it);
- the C smoke test against the shared library (`scripts/smoke-test-c.sh`, offline and `--online`);
- the differential test (`scripts/diff-vs-jvm.sh`, Phase 5). It compares verdicts with plain DSS on the JVM and
  fails on native-only failures in the library's log. That catches problems the libraries catch and log
  themselves, which exact metadata alone does not surface.

### Classification

| Class | Meaning | Metadata |
|---|---|---|
| **constant** | The argument is a constant the image builder folds (`Foo.class.getResourceAsStream("/xsd/x.xsd")`, `Class.forName("a.B")`, `ServiceLoader.load(X.class)`) | None needed: registered automatically at build time |
| **automatic** | `ServiceLoader` over `META-INF/services` entries; JCA lookups served by the JDK's own providers | None: Native Image's ServiceLoader and security-services support handle these |
| **data-driven** | The class, member or resource name comes from data (XML, PDF, CMS, configuration) or from a computed value | **Must be registered**: `DssFeature` (families) or `reachability-metadata.json` |
| **unreachable** | The call site is not reachable from the library's entry points | None |

## Findings by component

### DSS 6.5.1 (35 modules, 99 call sites)

| Call sites | Class | Covered by |
|---|---|---|
| `ServiceLoader.load` × 24 (`IUtils`, `ICMSUtils`, `ICRLUtils`, `CMSGenerator`, `MimeTypeLoader`, `LoTELoader`, `ValidationPolicyFactory`, `CryptographicSuiteFactory`, `XPathQueryExecutor`, `DocumentAnalyzerFactory`, `SignaturePolicyValidator`, `SignedDocumentExtenderFactory`, …) | automatic | ServiceLoader support. The agent also records the `META-INF/services/*` lookups and the provider constructors (13 DSS types and 10 DSS `META-INF/services/*` look-ups in `reachability-metadata.json`). |
| `JAXBContext.newInstance(ObjectFactory.class, …)` × 15 (reports, policy, crypto suite, TL v5/v6/2.1.1, XAdES, XMLDSig, ETSI report, MRA) | constant call, **data-driven inside JAXB** | `DssFeature`: all 802 classes in `eu.europa.esig..jaxb..` packages, plus JAXB annotations (below) |
| `getResourceAsStream` of XSDs, `policy/constraint.xml`, `policy/tsl-constraint.xml`, `suite/dss-crypto-suite.xml` × 43 | constant (path constants) | Folded; `DssFeature` also registers them by glob (`xsd/**.xsd`, `xsd/catalog.cat`, `policy/*.xml`, `suite/*.xml`), so validators built at run time with a computed path keep working |
| `ResourceBundle.getBundle` in `I18nProvider` (bundle `dss-messages`) | data-driven (locale) | `DssFeature` registers the bundle and `dss-messages*.properties`. Locale handling: see "Locales" below |
| `ResourceLoader.getAbsoluteResourceFolder` (`dss-service`) | data-driven, but only for `classpath:` cache folders | Unreachable with our configuration (absolute `cache_dir`) |
| `Class.forName("…XAdESStructureValidator")` (`dss-xades`) | constant | Folded; also in the agent output |
| `Security.addProvider(BouncyCastleProvider)` (`DSSSecurityProvider`) | constant provider, **data-driven services** | `DssFeature`: BouncyCastle (below) |
| `DocumentBuilderFactory/TransformerFactory/SchemaFactory/XPathFactory.newInstance()` (`dss-xml-common`, `dss-xml-utils`) | automatic + JDK lookups | JDK XML implementation classes from the agent (`com.sun.org.apache.xerces…`, `…xalan…`) |
| `ServiceLoaderPdfObjFactory`, `SignedDocumentValidator.fromDocument` | automatic + negative look-ups | Not used by the engine (it instantiates `AwtFreePdfObjFactory`, a `PdfBoxNativeObjectFactory`, `PDFDocumentValidator`, `CMSDocumentValidator` directly). The plain-DSS reference of the differential test uses them, also in the native test image, so their service look-ups (`DocumentValidatorFactory`, `EvidenceRecordAnalyzerFactory`, `IPdfObjFactory`) are in the metadata |
| `AbstractCertificateValidator`, `ExternalResources*Source` | — | Unreachable |
| `DSSFileFont`'s default font (`fonts/PTSerifRegular.ttf`) | constant, but read by our visible-signature drawer | `DssFeature` resource glob, explicitly (DSS's own `DSSFileFont` and drawers stay unused) |

### JAXB (jakarta.xml.bind-api 3.0.1, glassfish jaxb-runtime/core 3.0.2)

TrackDynamicAccess reports 55 data-driven reflection sites (`ReflectionNavigator`, `ClassFactory`, `Accessor`,
`PropertyFactory`, `LocatableAnnotation`, `RuntimeInlineAnnotationReader`, `ContextFinder`). Everything JAXB
touches comes from the model classes and their annotations:

| Need | Covered by |
|---|---|
| Model classes: fields, getters/setters, constructors, `ObjectFactory` methods, `package-info`, enums, generated `Adapter*` | `DssFeature` family (`eu.europa.esig..jaxb..`, 802 classes) |
| Annotation members invoked reflectively; each annotation wrapped in a `Proxy` implementing `Locatable` | `DssFeature` family: all 32 `jakarta.xml.bind.annotation` types, members + proxy |
| Classes named *by* annotations (`W3CDomHandler`, `CollapsedStringAdapter`, `NormalizedStringAdapter`, …) | `DssFeature` family. `W3CDomHandler` was the **one** registration missing in the first native run (TL `xsd:any` content) |
| `JAXBContextFactory` lookup, property classes, `StAXExConnector`, `ReflectionNavigator` | Metadata repository (jaxb-runtime 3.0.2, exact match) and agent |
| `jaxb.properties` look-ups in every model package (they do not exist: negative look-ups) | Agent (11 resource entries) |

### BouncyCastle (bcprov/bcpkix/bcutil 1.86): not in the metadata repository

| Site | Class | Covered by |
|---|---|---|
| `BouncyCastleProvider.loadServiceClass` / `ClassUtil.loadClass`: provider constructor loads `…$Mappings` classes by name | data-driven | `DssFeature`: 130 `$Mappings` classes, public constructors |
| JCA `Provider.Service.newInstance`: algorithm name from the CMS/PDF/XML being validated | data-driven | `DssFeature`: all 1,452 classes listed by `BouncyCastleProvider.getServices()` (instantiated once in the image builder to read the list), public constructors |
| `GcmSpecUtil`, `SpecUtil`, `BaseSecretKeyFactory`, `DRBG.findSource` | data-driven | Not used by signature validation. Listed as residual risk: the DRBG path only runs if BC is asked for its own `SecureRandom` |
| `X509CertificateHolder` / `XMSSUtil` Java serialization | — | Unreachable in practice (no Java serialization in the engine) |

### Apache Santuario xmlsec 3.0.6 (repository has metadata for 4.0.4 only)

`Init.dynamicInit()` maps algorithm URIs to implementation classes. `SignatureAlgorithm`, `Canonicalizer`,
`Transform`, `KeyResolver` and `ResourceResolver` then instantiate them reflectively
(`JavaUtils.newInstanceWithEmptyConstructor`, `getConstructor(Provider.class)`). **The URI comes from the
trusted list's XML signature.**

| Need | Covered by |
|---|---|
| `algorithms`, `c14n`, `transforms`, `keys.keyresolver`, `utils.resolver` `…implementations.*` (90 classes) | `DssFeature` family. The test lists are signed RSA-SHA512, so the agent saw one algorithm. Real national TLs use RSA, RSA-PSS and ECDSA. `TrustedListTest.nationalListsSignedWithOtherSchemesAreAccepted` (ECDSA, RSASSA-PSS) guards this in the native run |
| `org/apache/xml/security/resource/xmlsecurity` bundle | Agent + metadata repository |
| `stax` package (`TransformerAlgorithmMapper`, `SecurityTokenFactory`, …) | Unreachable: DSS uses the DOM API |

### PDFBox / FontBox 3.0.8 (repository metadata for 3.0.7 covers Helvetica + glyph lists only)

| Site | Class | Covered by |
|---|---|---|
| `Standard14Fonts.loadMetrics`, `GlyphList.load`: AFM/glyph list named by the PDF's fonts | data-driven | `DssFeature` resource glob `org/apache/pdfbox/resources/**` (22 files, ~1.1 MB) |
| `CMapParser.getExternalCMap`: predefined CMap named in the PDF (e.g. CJK encodings) | data-driven | `DssFeature` resource glob `org/apache/fontbox/cmap/**` (92 files, ~3.2 MB) |
| `SecurityHandlerFactory.newSecurityHandler`: handler chosen by the PDF's encryption filter | data-driven | `DssFeature`: `StandardSecurityHandler`, `PublicKeySecurityHandler` declared constructors |
| `IOUtils.unmapper` (pdfbox-io): `sun.misc.Unsafe.invokeCleaner` via method handles | data-driven | Agent (`sun.misc.Unsafe`) |

The test PDFs use Helvetica and no encryption, so these three families are registered **proactively**. They
are not exercised by a test.

### HTTP, logging and others

| Component | Data-driven sites | Covered by |
|---|---|---|
| HttpClient 5.6.5 / HttpCore 5.4.4 (repository: 5.3 / 5.2) | `VersionInfo` loads `org/apache/hc/{client5,core5}/version.properties` by computed name; `PublicSuffixMatcherLoader` (`org/publicsuffix/list/effective_tld_names.dat`); content-decoder probing (brotli4j, commons-compress: negative look-ups); `BasicAuthCache` deserialization (auth only) | Agent: the online suite and `HttpsLoopbackTest` (client5 `version.properties`; core5's comes from the metadata repository). The client5 `version.properties` was **missing** until Phase 3: the first online run of the shared library failed every download, because no earlier test had run real HTTP |
| commons-logging 1.4.0 (PDFBox's logger) | `LogFactory` discovery: `Class.forName` of Log4j/SLF4J adapters, `commons-logging.properties` | Agent: `Slf4jLogFactory`, negative look-ups for Log4j, `WeakHashtable` |
| SLF4J 2.0.20 / slf4j-simple | `SLF4JServiceProvider` ServiceLoader, `simplelogger.properties` | Automatic + agent |
| Jakarta Activation 2.0.1 | `MailcapCommandMap` handlers | Unreachable (JAXB attachments are not used) |
| Woodstox 6.5.1 (not in repository) | `Array.newInstance` only | Needs nothing beyond the agent's `WstxInputFactory` entry |
| commons-collections4, commons-lang3, commons-io, commons-codec | Serialization, reflection utilities | Unreachable from DSS's use of them |

### JDK

| Need | Covered by |
|---|---|
| JCA services of the JDK's own providers (SHA-*, RSA, EC, PKCS12, X.509 factory) | Automatic. Platform-specific entries (`apple.security.AppleProvider`, `NativePRNG`) are filtered out of the agent output |
| `sun.security.x509.*Extension(Boolean, Object)` constructors (JDK X.509 parsing via `OIDMap`) | Agent (8 entries) |
| `http`/`https` URL stream handlers | Agent (`sun.net.www.protocol.http(s).Handler`). This replaces the deprecated `--enable-url-protocols` |
| DNS/IDN and TLS: `InetAddressResolverProvider`, ICU `uprops.icu`/`uidna.spp`, X.509 `SubjectAlternativeName`/`PrivateKeyUsage`/`NetscapeCertType` extensions, time-zone names | Agent (online suite and loopback HTTPS) |
| JDK XML (Xerces/Xalan/XPath functions, `XMLEntities`/`regex` bundles, ICU normalization data) | Agent |
| XSLTC and the XPath function classes an XML-signature transform would load (e.g. `com.sun.org.apache.xpath.internal.functions.FuncCount`) | **Deliberately absent.** Trusted-list signatures may only use the enveloped-signature and canonicalization transforms: `TlDocumentCheck` pre-checks every downloaded and cached list (XML, `TrustServiceStatusList` root, allowed transforms, at most 4 references, no `Manifest`) before DSS validates it, so an XPath or XSLT transform never reaches xmlsec on the TL path, and no EU list uses one. Documents being validated are PDF or CMS, never XML signatures |
| CLDR locale data (`FormatData`, `CalendarData`) | See "Locales" |
| Charsets: `Charset.forName("Windows-1252")` in PDFBox's `BaseParser` (and any XML/text in a non-standard encoding) | `-H:+AddAllCharsets`. Native Image includes only the standard charsets by default; PDFBox caught the `UnsupportedCharsetException` and fell back to ISO-8859-1, which only the differential test's log check revealed (Phase 5) |
| `java.awt.image.*` with JNI access, `GraphicsEnvironment.isHeadless` (JNI) | Agent, the latter **on Linux**. Only used if a libawt is found at run time: the shipped library has none, and PDFBox catches the `UnsatisfiedLinkError`. The native test executable does find one next to itself, and without the entry libawt's `JNI_OnLoad` aborted it with a fatal JNI error. See DECISIONS.md, Phase 6, "PDFBox and the JDK's libawt" |

### PAdES extension (`dss_extend`, after Phase 6)

`PAdESService` (incremental save through PDFBox, DSS dictionary, document timestamps), `OnlineTSPSource` with
`TimestampDataLoader`, BouncyCastle's TSP request/response classes, and HttpClient's Basic auth (preemptive,
for `tsa.username`) needed **no new registration**. The agent run over `ExtensionTest` and
`HttpsLoopbackTest` recorded only the test classes. The native test suite runs both with exact metadata,
including a TSA over HTTPS on 127.0.0.1. `dss_extend` takes only PDFs; CAdES signatures reach T, LT and LTA
when they are signed (below).

### Signing with an external signer (`dss_sign_prepare`, `dss_sign_complete`, after Phase 6)

Creating signatures reaches one data-driven site validation never did: DSS builds the CMS through a
`ServiceLoader<CMSGenerator>`, and the agent recorded its provider (`eu.europa.esig.dss.cms.object.CMSObjectGenerator`)
and the `META-INF/services/eu.europa.esig.dss.cms.CMSGenerator` look-up. Everything else needed **no new
registration**: `PAdESService` and `PAdESWithExternalCMSService` (PDF preparation and signing through PDFBox),
`CAdESService` signing and CAdES extension (detached and enveloping), the JCA `Signature` verification of an external
signature value (RSA, ECDSA), and BouncyCastle's ASN.1 for re-encoding and encapsulating an external CMS.
`SigningTest` runs all of it in the native test suite with exact metadata; the C smoke test and the Rust tests
complete signatures recorded on the JVM (`testdata/fixtures/signing/`) through the shared library.

### Visible signatures (`pades.visible`, after Phase 6)

Our `AwtFreeSignatureDrawer` replaces DSS's visible-signature drawer, which needs AWT, ImageIO and LittleCMS
(DECISIONS.md, "Visible signatures"). Its path is plain PDFBox and FontBox (`PDType0Font`, TrueType parsing and
subsetting, `PDImageXObject` from encoded bytes) plus our PNG decoder and sRGB profile, and needed **no new
registration** beyond the default font above. The tracing agent also recorded ImageIO and colour-management
entries (`javax.imageio.*` services, `sun.awt.image.*Raster`, `sun/java2d/cmm/profiles/*.pf`, …): they come
from the two JVM-only tests that compare our decoder and profile with the JDK's, attributed to JDK callers, and
`merge-metadata.py` drops them (`DROP_JVM_ONLY_TESTS`). `VisibleSignatureTest`, `SignatureImageTest` and
`SrgbProfileTest` run in the native test suite with exact metadata; the visible signing fixtures are completed
by the shipped library (Rust tests, CLI test, C smoke test), which has no AWT library next to it.

### Trusted-list snapshots (`dss_tl_export_snapshot`, `tl_snapshot`, after Phase 6)

The snapshot payload is Java serialization of DSS's trusted-list model (DECISIONS.md, "Trusted-list
snapshots"). Native Image needs every class written or read registered for serialization, and which classes
occur is **data-driven**: condition types, MRA, pivots and identifiers depend on the lists. So `DssFeature`
registers them as a family, from the reader's own allowlist in `TlSnapshotFile`: every `Serializable` class in its
DSS packages (`enumerations`, `model.identifier`, `model.job`, `model.timedependent`, `model.tsl`, `tsl.dto`,
`validation.job.cache.state`, `validation.job.dto`), its JDK collections and boxed types, its single classes
(`CertificateDer`, `Digest`, `DSSMessageDigest`, and `CertificateToken`, which the reader makes from each
`CertificateDer`), and the classes only ever written (`ImmutableCollections$*`, and `Token`, `FileDocument`,
`CommonDocument`, `InMemoryDocument`, which `ObjectOutputStream` looks up before `replaceObject` swaps them out). The tracing
agent records only what the synthetic test lists contain, so `merge-metadata.py` drops its serialization
records for library classes (`without_feature_serialization`); test classes keep theirs. `TlSnapshotTest` runs
in the native test suite with exact metadata, and the full EU lists were round-tripped through the shipped
library (`dss-cli tl snapshot`, `--tl-snapshot`).

## Locales

JDK date/number formatting inside DSS and JAXB loads CLDR data **for the default locale**, reflectively. The
first native run under `LANG=it_IT` failed with `MissingReflectionRegistrationError` for
`sun.text.resources.cldr.ext.FormatData_it`. There were two options:

- `-H:+IncludeAllLocales`: works for every host locale, but costs +53 MB (87 → 140 MB) and doubles the build
  time;
- **pin the locale** (chosen): only en-US data is built in (`-Duser.language=en -Duser.country=US` for the
  builder, in `native-image.properties`). The library sets `Locale.US` when its isolate starts
  (`RuntimeDefaults.apply()`; the native test suite does the same through `RuntimeDefaultsListener`). The
  isolate's heap is private, so this does not affect the host process. Output is also identical to the JVM
  baseline. `-H:DefaultLocale` is deprecated and ignored in GraalVM 25.

Verified: the native suite passes under it_IT/Europe/Rome, fr_FR/Europe/Paris and ja_JP/Asia/Tokyo, and when
built on a machine with `LANG=it_IT`.

## Where the metadata lives

| File | Contents |
|---|---|
| `java/src/main/java/.../nativeimage/DssFeature.java` | Families: JAXB models and annotations, BouncyCastle services and `$Mappings`, xmlsec implementations, PDFBox security handlers, trusted-list snapshot classes (serialization), resources by glob |
| `java/src/main/resources/META-INF/native-image/it.codingduck.dssnative/dss-native/reachability-metadata.json` | Agent leftovers for the library: 90 types, 59 resources |
| `.../dss-native/native-image.properties` | `--features=…DssFeature`, builder locale, `-H:+AddAllCharsets` |
| `java/src/test/resources/META-INF/native-image/it.codingduck.dssnative/dss-native-tests/reachability-metadata.json` | Test-only: JUnit, test classes, the JDK HTTPS server used by `HttpsLoopbackTest` (70 types, 10 resources) |
| Metadata repository (NBT 1.1.17, release 1.0.20) | jaxb, pdfbox, httpclient, slf4j, xmlsec 4.0.4, commons-* (nearest version) |

## Residual risks

Data-driven paths that are neither exercised by a test nor covered by a family. A missing registration
would not crash the host. It would surface as `INTERNAL_ERROR` in the JSON result, because `DssJsonApi`
catches `Throwable`. If it happens inside DSS's trusted-list job, it shows up as an error on that list in the
TL status.

- BouncyCastle helper reflection outside JCA services (`GcmSpecUtil`, `SpecUtil`, BC `DRBG`): not on the
  validation path.
- DSS features not enabled here (XAdES/JAdES/ASiC documents, evidence records, LoTE lists, custom validation
  policies loaded from a path): out of scope; revisit if enabled. Enabling XAdES would also make the XPath/XSLT
  transform classes reachable (see "JDK"), which the trusted-list pre-check keeps out today.
- Real-world documents beyond the synthetic fixtures. Phase 5's differential run over `testdata/private/`
  is the check.

## Regenerating

```bash
export JAVA_HOME=<GraalVM CE 25>
scripts/run-agent.sh --online                     # JVM tests (+ real-LOTL suite) under the tracing agent
python3 -I scripts/merge-metadata.py              # fold into the JSON files (union; --replace to rebuild)
scripts/build-native.sh --with-tests              # exact metadata: native JUnit run + shared library
scripts/run-native-tests.sh -XX:MissingRegistrationReportingMode=Exit
scripts/smoke-test-c.sh && scripts/smoke-test-c.sh --online
scripts/diff-vs-jvm.sh                            # verdicts vs plain DSS + native-log check
scripts/audit-reflection.sh > audit.tsv           # source grep, to review new call sites after upgrades
```

The agent records what the JVM does **on the platform it runs on**. Most entries are the same everywhere, but
native code differs: `GraphicsEnvironment.isHeadless` is only called by Linux's libawt. Keep the default union
merge, or, after `--replace`, run the agent on Linux too (in an `ubuntu:24.04` container) and merge both. The
Linux CI jobs catch a missing entry: the native tests run in `Exit` mode.

On every DSS or dependency upgrade:
1. re-run the steps above;
2. diff `audit.tsv` against the previous one;
3. check the `[DssFeature]` counts (`-Ddssnative.feature.verbose=true` in `NATIVE_IMAGE_OPTIONS`).
