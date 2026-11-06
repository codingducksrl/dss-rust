/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.CRC32C;
import java.util.zip.CheckedOutputStream;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.tsl.CertificateTrustTime;
import eu.europa.esig.dss.model.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.model.tsl.TrustProperties;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;

/**
 * The trusted-list snapshot file: the trust pool an engine built from its trusted lists, so that another engine
 * can start from it without parsing the lists and validating their signatures again.
 *
 * <pre>
 *   8 bytes  "DSSTLSNP"
 *   4 bytes  format version (big-endian), {@value #FORMAT}
 *   4 bytes  header length H (big-endian)
 *   H bytes  header: UTF-8 JSON (versions, creation time, the trusted-list settings); readable on its own
 *   ...      payload: a Java serialization stream (trust properties, trust times, list summary, alerts)
 *   4 bytes  CRC-32C of everything before it (big-endian)
 * </pre>
 *
 * The CRC detects a damaged file, not a forged one: whether a snapshot can be trusted is for the application
 * that hands it over to decide. Reading is still defensive, since it deserializes: the payload may only hold the
 * classes listed here, checked by an {@link ObjectInputFilter} before anything is instantiated. Certificates are
 * stored as their DER encoding and parsed again with DSS's own loader.
 */
public final class TlSnapshotFile {

    static final int FORMAT = 1;
    private static final byte[] MAGIC = "DSSTLSNP".getBytes(StandardCharsets.US_ASCII);
    private static final int PREFIX = MAGIC.length + 8;
    private static final int TRAILER = 4;

    /**
     * JDK classes the payload may hold: boxed values, dates and collections. DssFeature registers them too.
     * {@code Map$Entry} is never deserialized: {@code HashMap} and {@code HashSet} ask the filter about the
     * {@code Map.Entry[]} they are about to allocate.
     */
    public static final List<String> JDK_CLASSES = List.of(
            "java.lang.Boolean", "java.lang.Byte", "java.lang.Character", "java.lang.Double", "java.lang.Enum",
            "java.lang.Float", "java.lang.Integer", "java.lang.Long", "java.lang.Number", "java.lang.Short",
            "java.lang.String", "java.util.ArrayList", "java.util.Arrays$ArrayList", "java.util.CollSer",
            "java.util.Collections$EmptyList", "java.util.Collections$EmptyMap", "java.util.Collections$EmptySet",
            "java.util.Collections$SingletonList", "java.util.Collections$SingletonMap",
            "java.util.Collections$SingletonSet", "java.util.Collections$UnmodifiableCollection",
            "java.util.Collections$UnmodifiableList", "java.util.Collections$UnmodifiableMap",
            "java.util.Collections$UnmodifiableRandomAccessList", "java.util.Collections$UnmodifiableSet",
            "java.util.Date", "java.util.EnumMap", "java.util.HashMap", "java.util.HashSet",
            "java.util.LinkedHashMap", "java.util.LinkedHashSet", "java.util.LinkedList", "java.util.Map$Entry",
            "java.util.TreeMap", "java.util.TreeSet");

    /**
     * JDK classes only ever <em>written</em>: their {@code writeReplace} turns them into {@code java.util.CollSer}.
     * Native Image needs them registered for serialization all the same.
     */
    public static final List<String> JDK_WRITE_ONLY_CLASSES = List.of(
            "java.util.ImmutableCollections$List12", "java.util.ImmutableCollections$ListN",
            "java.util.ImmutableCollections$Map1", "java.util.ImmutableCollections$MapN",
            "java.util.ImmutableCollections$Set12", "java.util.ImmutableCollections$SetN");

    /**
     * DSS classes only ever <em>written</em>, never in the payload: {@link Out#replaceObject} swaps them for a
     * {@link CertificateDer} or null, but {@code ObjectOutputStream} looks up their serialization descriptor first.
     */
    public static final List<String> DSS_WRITE_ONLY_CLASSES = List.of(
            "eu.europa.esig.dss.model.CommonDocument", "eu.europa.esig.dss.model.FileDocument",
            "eu.europa.esig.dss.model.InMemoryDocument", "eu.europa.esig.dss.model.x509.Token");

    /** DSS packages (and their subpackages) whose classes the payload may hold: the trusted-list model. */
    public static final List<String> DSS_PACKAGES = List.of(
            "eu.europa.esig.dss.enumerations.", "eu.europa.esig.dss.model.identifier.",
            "eu.europa.esig.dss.model.job.", "eu.europa.esig.dss.model.timedependent.",
            "eu.europa.esig.dss.model.tsl.", "eu.europa.esig.dss.tsl.dto.",
            "eu.europa.esig.dss.validation.job.cache.state.", "eu.europa.esig.dss.validation.job.dto.");

    /**
     * Single classes outside those packages. {@code CertificateToken} is never in the stream: the filter is asked
     * about it because {@link In#resolveObject} turns each {@link CertificateDer} into one.
     */
    public static final List<String> OTHER_CLASSES = List.of(
            "eu.europa.esig.dss.model.DSSMessageDigest", "eu.europa.esig.dss.model.Digest",
            "eu.europa.esig.dss.model.x509.CertificateToken", CertificateDer.class.getName());

    private static final int MAX_DEPTH = 200;
    private static final long MAX_REFERENCES = 50_000_000;
    private static final long MAX_ARRAY_LENGTH = 64L * 1024 * 1024;
    /** BouncyCastle: skip its primality tests of RSA moduli, on the reading thread only (see {@link #contents}). */
    private static final String BC_ALLOW_UNSAFE_MOD = "org.bouncycastle.rsa.allow_unsafe_mod";

    private TlSnapshotFile() {
    }

    /** What a published trust pool consists of. */
    record Contents(Map<CertificateToken, List<TrustProperties>> trustProperties,
                    Map<CertificateToken, List<CertificateTrustTime>> trustTimes,
                    TLValidationJobSummary summary,
                    List<Map<String, Object>> alerts) {
    }

    /** Stands in for a {@link CertificateToken} in the payload: its DER encoding, parsed again when reading. */
    static final class CertificateDer implements Serializable {
        private static final long serialVersionUID = 1L;
        private final byte[] der;

        CertificateDer(byte[] der) {
            this.der = der;
        }
    }

    /** Whether the payload may hold a class of this name (component type, for arrays). */
    public static boolean allowed(String className) {
        if (JDK_CLASSES.contains(className) || OTHER_CLASSES.contains(className)) {
            return true;
        }
        for (String p : DSS_PACKAGES) {
            if (className.startsWith(p)) {
                return true;
            }
        }
        return false;
    }

    static byte[] write(Map<String, Object> header, Contents contents) {
        byte[] headerJson = Json.write(header).getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream file = new ByteArrayOutputStream(1 << 20);
        CRC32C crc = new CRC32C();
        try {
            CheckedOutputStream checked = new CheckedOutputStream(file, crc);
            DataOutputStream prefix = new DataOutputStream(checked);
            prefix.write(MAGIC);
            prefix.writeInt(FORMAT);
            prefix.writeInt(headerJson.length);
            prefix.write(headerJson);
            prefix.flush();
            try (Out out = new Out(checked)) {
                out.writeObject(new HashMap<>(contents.trustProperties()));
                out.writeObject(new HashMap<>(contents.trustTimes()));
                out.writeObject(contents.summary());
                out.writeObject(new ArrayList<>(contents.alerts()));
            }
            new DataOutputStream(file).writeInt((int) crc.getValue());
        } catch (IOException e) {
            throw new UncheckedIOException(e); // a ByteArrayOutputStream does not fail; a NotSerializableException does
        }
        return file.toByteArray();
    }

    /** The header, after checking the layout, the format version and the CRC. Does not touch the payload. */
    static Map<String, Object> header(byte[] file) {
        if (file.length < PREFIX + TRAILER || !Arrays.equals(file, 0, MAGIC.length, MAGIC, 0, MAGIC.length)) {
            throw rejected("not a trusted-list snapshot");
        }
        ByteBuffer b = ByteBuffer.wrap(file);
        int format = b.getInt(MAGIC.length);
        if (format != FORMAT) {
            throw rejected("snapshot format " + format + "; this library reads format " + FORMAT);
        }
        CRC32C crc = new CRC32C();
        crc.update(file, 0, file.length - TRAILER);
        if ((int) crc.getValue() != b.getInt(file.length - TRAILER)) {
            throw rejected("the snapshot is damaged (checksum mismatch)");
        }
        int headerLength = b.getInt(MAGIC.length + 4);
        if (headerLength < 2 || headerLength > file.length - PREFIX - TRAILER) {
            throw rejected("the snapshot is damaged (header length " + headerLength + ")");
        }
        try {
            return Json.parseObject(new String(file, PREFIX, headerLength, StandardCharsets.UTF_8));
        } catch (Json.ParseException e) {
            throw rejected("the snapshot header is not valid JSON: " + e.getMessage());
        }
    }

    /**
     * The payload. Call {@link #header} first: this assumes the layout is sound.
     *
     * <p>Creating a {@link CertificateToken} makes BouncyCastle build the certificate's public key, and for RSA
     * keys BouncyCastle first runs probabilistic primality tests on the modulus (about 4 ms each): 20 s for the
     * ~5,000 certificates of the EU lists, three times as long as loading them from the cache. Those keys were
     * already tested when the lists were loaded to make the snapshot, so the tests are switched off while
     * reading, for this thread only, through BouncyCastle's thread-local override. Keys built later (during a
     * validation) are tested as usual.
     */
    static Contents contents(byte[] file) {
        int headerLength = ByteBuffer.wrap(file).getInt(MAGIC.length + 4);
        int start = PREFIX + headerLength;
        org.bouncycastle.util.Properties.setThreadOverride(BC_ALLOW_UNSAFE_MOD, true);
        try (In in = new In(new ByteArrayInputStream(file, start, file.length - TRAILER - start))) {
            try {
                Map<CertificateToken, List<TrustProperties>> trustProperties =
                        certificateMap(in.readObject(), TrustProperties.class, "trust properties");
                Map<CertificateToken, List<CertificateTrustTime>> trustTimes =
                        certificateMap(in.readObject(), CertificateTrustTime.class, "trust times");
                if (!(in.readObject() instanceof TLValidationJobSummary summary)) {
                    throw rejected("the snapshot has no trusted-list summary");
                }
                return new Contents(trustProperties, trustTimes, summary, alerts(in.readObject()));
            } catch (InvalidClassException e) {
                if (in.rejectedClass != null) {
                    throw rejected("the snapshot holds a class a snapshot never contains: " + in.rejectedClass);
                }
                throw rejected("cannot read the snapshot: " + e);
            }
        } catch (DssError e) {
            throw e;
        } catch (IOException | ClassNotFoundException | RuntimeException e) {
            throw rejected("cannot read the snapshot: " + e);
        } finally {
            org.bouncycastle.util.Properties.removeThreadOverride(BC_ALLOW_UNSAFE_MOD);
        }
    }

    static DssError rejected(String message) {
        return new DssError(DssError.Code.TL_SNAPSHOT_REJECTED, message);
    }

    private static <T> Map<CertificateToken, List<T>> certificateMap(Object o, Class<T> type, String what) {
        if (!(o instanceof Map<?, ?> map)) {
            throw rejected("the snapshot's " + what + " are not a map");
        }
        Map<CertificateToken, List<T>> out = new HashMap<>();
        for (Map.Entry<?, ?> e : map.entrySet()) {
            if (!(e.getKey() instanceof CertificateToken token) || !(e.getValue() instanceof List<?> list)) {
                throw rejected("the snapshot's " + what + " are not keyed by certificate");
            }
            List<T> values = new ArrayList<>(list.size());
            for (Object v : list) {
                if (!type.isInstance(v)) {
                    throw rejected("the snapshot's " + what + " hold a " + (v == null ? "null" : v.getClass().getName()));
                }
                values.add(type.cast(v));
            }
            out.put(token, values);
        }
        return out;
    }

    private static List<Map<String, Object>> alerts(Object o) {
        if (!(o instanceof List<?> list)) {
            throw rejected("the snapshot's alerts are not a list");
        }
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object a : list) {
            if (!(a instanceof Map<?, ?> map)) {
                throw rejected("the snapshot's alerts are not objects");
            }
            Map<String, Object> m = new LinkedHashMap<>();
            map.forEach((k, v) -> m.put(String.valueOf(k), v));
            out.add(m);
        }
        return out;
    }

    private static final class Out extends ObjectOutputStream {
        Out(OutputStream out) throws IOException {
            super(out);
            enableReplaceObject(true);
        }

        @Override
        protected Object replaceObject(Object obj) {
            if (obj instanceof CertificateToken token) {
                return new CertificateDer(token.getEncoded());
            }
            if (obj instanceof DSSDocument) {
                return null; // a downloaded list's file in the cache: not part of the trust pool
            }
            return obj;
        }
    }

    private static final class In extends ObjectInputStream {
        String rejectedClass;

        In(InputStream in) throws IOException {
            super(in);
            enableResolveObject(true);
            setObjectInputFilter(this::check);
        }

        private ObjectInputFilter.Status check(ObjectInputFilter.FilterInfo info) {
            if (info.depth() > MAX_DEPTH || info.references() > MAX_REFERENCES
                    || info.arrayLength() > MAX_ARRAY_LENGTH) {
                return ObjectInputFilter.Status.REJECTED;
            }
            Class<?> c = info.serialClass();
            if (c == null) {
                return ObjectInputFilter.Status.UNDECIDED;
            }
            boolean array = c.isArray();
            while (c.isArray()) {
                c = c.getComponentType();
            }
            // Object[]: ArrayList and CollSer ask before allocating theirs. A plain Object is never deserialized.
            if (c.isPrimitive() || (array && c == Object.class) || allowed(c.getName())) {
                return ObjectInputFilter.Status.ALLOWED;
            }
            rejectedClass = c.getName();
            return ObjectInputFilter.Status.REJECTED;
        }

        @Override
        protected Object resolveObject(Object obj) {
            return obj instanceof CertificateDer c ? DSSUtils.loadCertificate(c.der) : obj;
        }
    }
}
