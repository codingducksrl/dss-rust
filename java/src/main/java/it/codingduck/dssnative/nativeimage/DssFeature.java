/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.nativeimage;

import java.io.IOException;
import java.io.Serializable;
import java.io.UncheckedIOException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.TreeSet;
import java.util.function.Predicate;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.graalvm.nativeimage.hosted.Feature;
import org.graalvm.nativeimage.hosted.RuntimeProxyCreation;
import org.graalvm.nativeimage.hosted.RuntimeReflection;
import org.graalvm.nativeimage.hosted.RuntimeResourceAccess;
import org.graalvm.nativeimage.hosted.RuntimeSerialization;

import it.codingduck.dssnative.engine.TlSnapshotFile;

/**
 * Build-time registration of whole families of reflectively used elements, instead of one entry per use.
 * Everything else (the long tail) is in {@code reachability-metadata.json}, from the tracing agent.
 * See docs/reflection-audit.md for why each family is needed.
 *
 * <ul>
 *   <li><b>JAXB models</b>: every class in an {@code eu.europa.esig..jaxb..} package. JAXB reads and writes their
 *       fields and accessors and instantiates them and their {@code XmlAdapter}s reflectively. DSS uses JAXB for
 *       reports, policies, the crypto suite and trusted lists.</li>
 *   <li><b>JAXB annotations</b>: the runtime wraps every annotation it reads in a {@code Proxy} that also
 *       implements {@code Locatable}, and invokes the annotation members reflectively. Helper classes that
 *       annotations name ({@code W3CDomHandler}, the standard {@code XmlAdapter}s) are instantiated
 *       reflectively.</li>
 *   <li><b>BouncyCastle provider</b>: the provider constructor loads its {@code $Mappings} classes by name, and
 *       JCA instantiates every service implementation by class name.</li>
 *   <li><b>Apache Santuario (xmlsec)</b>: signature algorithms, canonicalizers, transforms and resolvers are
 *       instantiated reflectively from the algorithm URI found in the XML being verified (trusted lists, here).
 *       The test lists use one algorithm; real national lists use several (RSA, RSA-PSS, ECDSA, ...).</li>
 *   <li><b>PDFBox</b>: font metrics, glyph lists and CMaps are loaded by the names found inside the PDF, and
 *       security handlers are instantiated from the PDF's encryption filter. The test PDFs use one font and no
 *       encryption, so this is registered as a family rather than traced.</li>
 *   <li><b>Trusted-list snapshots</b>: Java serialization of DSS's trusted-list model and the JDK collections
 *       it uses, for {@code dss_tl_export_snapshot} and {@code tl_snapshot}.</li>
 *   <li><b>Resources</b>: XSDs, the default validation policy, the cryptographic suite, DSS's message
 *       bundles and the default font of visible signatures, by glob.</li>
 * </ul>
 */
public final class DssFeature implements Feature {

    private static final Pattern JAXB_CLASS = Pattern.compile("^eu/europa/esig/(.+/)?jaxb(/.+)?/[^/]+\\.class$");
    private static final Pattern BC_MAPPINGS =
            Pattern.compile("^org/bouncycastle/(jcajce|pqc/jcajce)/provider/.+\\$Mappings\\.class$");
    private static final String JAXB_ANNOTATIONS = "jakarta/xml/bind/annotation/";
    private static final String JAXB_LOCATABLE = "org.glassfish.jaxb.core.v2.model.annotation.Locatable";
    private static final String BC_PROVIDER = "org.bouncycastle.jce.provider.BouncyCastleProvider";
    private static final Pattern PDFBOX_SECURITY_HANDLER =
            Pattern.compile("^org/apache/pdfbox/pdmodel/encryption/[^/$]+SecurityHandler\\.class$");
    private static final Pattern XMLSEC_IMPLEMENTATION = Pattern.compile("^org/apache/xml/security/("
            + "algorithms|c14n|transforms|keys/keyresolver|utils/resolver)/implementations/[^/]+\\.class$");

    /** Resource globs ({@code *} within a path segment, {@code **} across segments). */
    private static final List<String> RESOURCE_GLOBS = List.of(
            "xsd/**.xsd", "xsd/catalog.cat",
            "policy/*.xml",
            "suite/*.xml",
            "dss-messages*.properties",
            "it/codingduck/dssnative/version.properties",
            "org/apache/pdfbox/resources/**",   // standard-14 AFM metrics, glyph lists, ICC, fallback font (~1.1 MB)
            "org/apache/fontbox/cmap/**",       // predefined CMaps, e.g. CJK encodings (~3.2 MB)
            "fonts/PTSerifRegular.ttf");        // DSS's default font for visible signatures (~200 KB)
    private static final List<String> RESOURCE_BUNDLES = List.of("dss-messages");

    private final List<String> report = new ArrayList<>();

    @Override
    public String getDescription() {
        return "Registers DSS's JAXB models, BouncyCastle provider services and DSS resources";
    }

    @Override
    public void beforeAnalysis(BeforeAnalysisAccess access) {
        List<String> entries = classPathEntries(access.getApplicationClassPath());
        registerJaxbModels(access, entries);
        registerJaxbAnnotations(access, entries);
        registerBouncyCastle(access, entries);
        registerXmlSecImplementations(access, entries);
        registerPdfBoxSecurityHandlers(access, entries);
        registerTlSnapshotClasses(access, entries);
        registerResources(entries);
        if (Boolean.getBoolean("dssnative.feature.verbose")) {
            report.forEach(line -> System.out.println("[DssFeature] " + line));
        }
    }

    private void registerJaxbModels(BeforeAnalysisAccess access, List<String> entries) {
        int count = 0;
        for (String entry : entries) {
            if (JAXB_CLASS.matcher(entry).matches()) {
                Class<?> c = access.findClassByName(className(entry));
                if (c != null) {
                    registerFully(c);
                    count++;
                }
            }
        }
        report.add("JAXB model classes: " + count);
    }

    private void registerJaxbAnnotations(BeforeAnalysisAccess access, List<String> entries) {
        Class<?> locatable = access.findClassByName(JAXB_LOCATABLE);
        int count = 0;
        for (String entry : entries) {
            if (entry.startsWith(JAXB_ANNOTATIONS) && entry.endsWith(".class")) {
                Class<?> c = access.findClassByName(className(entry));
                if (c == null) {
                    continue;
                }
                if (!c.isAnnotation()) {
                    if (!c.isInterface() && !Modifier.isAbstract(c.getModifiers())) {
                        registerFully(c); // W3CDomHandler, CollapsedStringAdapter, ...
                    }
                    continue;
                }
                RuntimeReflection.register(c);
                RuntimeReflection.registerAllDeclaredMethods(c);
                RuntimeReflection.register(c.getDeclaredMethods());
                if (locatable != null) {
                    RuntimeProxyCreation.register(c, locatable);
                }
                count++;
            }
        }
        report.add("JAXB annotation types (members + Locatable proxies): " + count);
    }

    private void registerBouncyCastle(BeforeAnalysisAccess access, List<String> entries) {
        Class<?> providerClass = access.findClassByName(BC_PROVIDER);
        if (providerClass == null) {
            return;
        }
        registerFully(providerClass);
        int mappings = 0;
        for (String entry : entries) {
            if (BC_MAPPINGS.matcher(entry).matches()) {
                Class<?> c = access.findClassByName(className(entry));
                if (c != null) {
                    registerInstantiable(c);
                    mappings++;
                }
            }
        }
        // A throw-away instance in the image builder, only to read the list of service implementation classes.
        Provider provider;
        try {
            provider = (Provider) providerClass.getConstructor().newInstance();
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("cannot instantiate " + BC_PROVIDER + " at build time", e);
        }
        TreeSet<String> serviceClasses = new TreeSet<>();
        for (Provider.Service service : provider.getServices()) {
            serviceClasses.add(service.getClassName());
        }
        int services = 0;
        for (String name : serviceClasses) {
            Class<?> c = access.findClassByName(name);
            if (c != null) {
                registerInstantiable(c);
                services++;
            } else {
                report.add("BouncyCastle service class not on class path: " + name);
            }
        }
        report.add("BouncyCastle $Mappings classes: " + mappings + ", service classes: " + services);
    }

    private void registerXmlSecImplementations(BeforeAnalysisAccess access, List<String> entries) {
        int count = 0;
        for (String entry : entries) {
            if (XMLSEC_IMPLEMENTATION.matcher(entry).matches()) {
                Class<?> c = access.findClassByName(className(entry));
                if (c != null && !c.isInterface() && !Modifier.isAbstract(c.getModifiers())) {
                    // JavaUtils.newInstanceWithEmptyConstructor uses getDeclaredConstructor();
                    // SignatureAlgorithm also tries getConstructor(Provider.class).
                    RuntimeReflection.register(c);
                    RuntimeReflection.registerAllDeclaredConstructors(c);
                    RuntimeReflection.registerAllConstructors(c);
                    RuntimeReflection.register(c.getDeclaredConstructors());
                    count++;
                }
            }
        }
        report.add("xmlsec algorithm/c14n/transform/resolver implementations: " + count);
    }

    private void registerPdfBoxSecurityHandlers(BeforeAnalysisAccess access, List<String> entries) {
        int count = 0;
        for (String entry : entries) {
            if (PDFBOX_SECURITY_HANDLER.matcher(entry).matches()) {
                Class<?> c = access.findClassByName(className(entry));
                if (c != null && !Modifier.isAbstract(c.getModifiers())) {
                    // SecurityHandlerFactory.newSecurityHandler: getDeclaredConstructor(argTypes).newInstance(args)
                    RuntimeReflection.register(c);
                    RuntimeReflection.registerAllDeclaredConstructors(c);
                    RuntimeReflection.register(c.getDeclaredConstructors());
                    count++;
                }
            }
        }
        report.add("PDFBox security handlers: " + count);
    }

    /**
     * Java serialization of the trusted-list snapshot payload, both ways: exactly the classes its reader allows
     * ({@link TlSnapshotFile}), plus the JDK collections that are only ever written. Which DSS model classes occur
     * depends on the lists (condition types, MRA, pivots), so their packages are registered whole.
     */
    private void registerTlSnapshotClasses(BeforeAnalysisAccess access, List<String> entries) {
        List<String> names = new ArrayList<>();
        names.addAll(TlSnapshotFile.JDK_CLASSES);
        names.addAll(TlSnapshotFile.JDK_WRITE_ONLY_CLASSES);
        names.addAll(TlSnapshotFile.OTHER_CLASSES);
        names.addAll(TlSnapshotFile.DSS_WRITE_ONLY_CLASSES);
        for (String entry : entries) {
            if (entry.endsWith(".class")) {
                String name = className(entry);
                if (TlSnapshotFile.DSS_PACKAGES.stream().anyMatch(name::startsWith)) {
                    names.add(name);
                }
            }
        }
        int count = 0;
        for (String name : names) {
            Class<?> c = access.findClassByName(name);
            if (c != null && Serializable.class.isAssignableFrom(c)) {
                RuntimeSerialization.register(c);
                count++;
            }
        }
        report.add("trusted-list snapshot classes (serialization): " + count);
    }

    private void registerResources(List<String> entries) {
        Module module = DssFeature.class.getModule(); // the unnamed module: everything here is on the class path
        List<Predicate<String>> globs = RESOURCE_GLOBS.stream().map(DssFeature::globToPredicate).toList();
        int count = 0;
        for (String entry : entries) {
            if (!entry.endsWith(".class") && !entry.endsWith("/") && globs.stream().anyMatch(g -> g.test(entry))) {
                RuntimeResourceAccess.addResource(module, entry);
                count++;
            }
        }
        for (String bundle : RESOURCE_BUNDLES) {
            RuntimeResourceAccess.addResourceBundle(module, bundle);
        }
        report.add("resources by glob: " + count + ", bundles: " + RESOURCE_BUNDLES);
    }

    /** The class, all its constructors, methods and fields: queryable and usable reflectively. */
    private static void registerFully(Class<?> c) {
        RuntimeReflection.register(c);
        RuntimeReflection.registerAllDeclaredConstructors(c);
        RuntimeReflection.registerAllDeclaredMethods(c);
        RuntimeReflection.registerAllDeclaredFields(c);
        RuntimeReflection.register(c.getDeclaredConstructors());
        for (Method m : c.getDeclaredMethods()) {
            RuntimeReflection.register(m);
        }
        RuntimeReflection.register(c.getDeclaredFields());
    }

    /** Loadable by name and instantiable through any public constructor (what JCA's Service.newInstance does). */
    private static void registerInstantiable(Class<?> c) {
        RuntimeReflection.register(c);
        RuntimeReflection.registerAllConstructors(c);
        RuntimeReflection.register(c.getConstructors());
    }

    // ------------------------------------------------------------------ class path scanning

    /** Every entry name (resources and classes, '/'-separated) of every class-path jar or directory. */
    static List<String> classPathEntries(List<Path> classPath) {
        TreeSet<String> names = new TreeSet<>();
        for (Path p : classPath) {
            try {
                if (Files.isDirectory(p)) {
                    try (Stream<Path> walk = Files.walk(p)) {
                        walk.filter(Files::isRegularFile)
                                .forEach(f -> names.add(p.relativize(f).toString().replace('\\', '/')));
                    }
                } else if (Files.isRegularFile(p) && p.toString().endsWith(".jar")) {
                    try (JarFile jar = new JarFile(p.toFile())) {
                        Enumeration<JarEntry> e = jar.entries();
                        while (e.hasMoreElements()) {
                            names.add(e.nextElement().getName());
                        }
                    }
                }
            } catch (IOException e) {
                throw new UncheckedIOException("cannot scan class-path entry " + p, e);
            }
        }
        return new ArrayList<>(names);
    }

    private static String className(String entry) {
        return entry.substring(0, entry.length() - ".class".length()).replace('/', '.');
    }

    static Predicate<String> globToPredicate(String glob) {
        StringBuilder regex = new StringBuilder("^");
        for (int i = 0; i < glob.length(); i++) {
            char c = glob.charAt(i);
            if (c == '*' && i + 1 < glob.length() && glob.charAt(i + 1) == '*') {
                regex.append(".*");
                i++;
            } else if (c == '*') {
                regex.append("[^/]*");
            } else {
                regex.append(Pattern.quote(String.valueOf(c)));
            }
        }
        return Pattern.compile(regex.append('$').toString()).asMatchPredicate();
    }
}
