/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;

import eu.europa.esig.dss.spi.client.http.DataLoader;

/**
 * Reuses GET responses (CRLs, AIA certificates) across engine calls for a while, so that validating many
 * documents from the same CAs does not download the same CRL for each one. POSTs (OCSP, TSA) are never cached.
 * Bounded in entries and in bytes, least recently used first out; an entry whose TTL has passed is fetched again.
 *
 * <p>How long a body is kept depends on what it is: a CRL until the configured TTL or its own {@code nextUpdate},
 * whichever comes first; a certificate or a CMS bundle (a {@code .p7c} from an AIA URL) for the configured TTL; and
 * anything else (an HTML page from a captive portal or a misconfigured mirror answering 200) for only
 * {@value #UNPARSEABLE_TTL_MS} ms, so that a fixed server is used again at once rather than after an hour.
 */
final class CachingDataLoader implements DataLoader {

    private static final long serialVersionUID = 1L;
    static final int DEFAULT_MAX_ENTRIES = 1_024;
    static final long DEFAULT_MAX_BYTES = 64L * 1024 * 1024;
    /** How long a 2xx body that is neither a CRL, a certificate nor a CMS bundle is kept. */
    static final long UNPARSEABLE_TTL_MS = 5_000;
    private static final byte[] PEM_PREFIX = "-----BEGIN ".getBytes(StandardCharsets.US_ASCII);

    private record Entry(byte[] body, long expiresAt) {
    }

    private final DataLoader delegate;
    private final long ttlMs;
    private final int maxEntries;
    private final long maxBytes;
    /** Access-ordered, so the first entry is the least recently used. Guarded by itself. */
    private final transient LinkedHashMap<String, Entry> entries = new LinkedHashMap<>(64, 0.75f, true);
    private long bytes;

    CachingDataLoader(DataLoader delegate, long ttlMs) {
        this(delegate, ttlMs, DEFAULT_MAX_ENTRIES, DEFAULT_MAX_BYTES);
    }

    CachingDataLoader(DataLoader delegate, long ttlMs, int maxEntries, long maxBytes) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        if (ttlMs < 1 || maxEntries < 1 || maxBytes < 1) {
            throw new IllegalArgumentException("ttl, entries and bytes must be positive");
        }
        this.ttlMs = ttlMs;
        this.maxEntries = maxEntries;
        this.maxBytes = maxBytes;
    }

    DataLoader delegate() {
        return delegate;
    }

    @Override
    public byte[] get(String url) {
        byte[] cached = lookup(url);
        if (cached != null) {
            return cached;
        }
        byte[] body = delegate.get(url);
        store(url, body);
        return body;
    }

    @Override
    public DataAndUrl get(List<String> urls) {
        if (urls != null) {
            for (String url : urls) {
                byte[] cached = lookup(url);
                if (cached != null) {
                    return new DataAndUrl(url, cached);
                }
            }
        }
        DataAndUrl result = delegate.get(urls);
        if (result != null && result.getUrlString() != null) {
            store(result.getUrlString(), result.getData());
        }
        return result;
    }

    @Override
    public byte[] post(String url, byte[] content) {
        return delegate.post(url, content);
    }

    @Override
    public void setContentType(String contentType) {
        delegate.setContentType(contentType);
    }

    /** Entries currently held, for tests. */
    int size() {
        synchronized (entries) {
            return entries.size();
        }
    }

    private byte[] lookup(String url) {
        synchronized (entries) {
            Entry e = entries.get(url);
            if (e == null) {
                return null;
            }
            if (e.expiresAt < System.currentTimeMillis()) {
                entries.remove(url);
                bytes -= e.body.length;
                return null;
            }
            return e.body;
        }
    }

    private void store(String url, byte[] body) {
        if (body == null || body.length > maxBytes) {
            return;
        }
        long now = System.currentTimeMillis();
        synchronized (entries) {
            Entry old = entries.put(url, new Entry(body, now + ttlFor(body, ttlMs, now)));
            bytes += body.length - (old == null ? 0 : old.body.length);
            Iterator<Map.Entry<String, Entry>> oldestFirst = entries.entrySet().iterator();
            while ((entries.size() > maxEntries || bytes > maxBytes) && oldestFirst.hasNext()) {
                Map.Entry<String, Entry> evicted = oldestFirst.next();
                if (evicted.getKey().equals(url)) {
                    continue; // the one just stored is the most recently used; evict others first
                }
                bytes -= evicted.getValue().body.length;
                oldestFirst.remove();
            }
        }
    }

    /**
     * The time a body may be reused for: {@code ttlMs} for a certificate or a CMS bundle, {@code ttlMs} capped at
     * the CRL's {@code nextUpdate} for a CRL, {@link #UNPARSEABLE_TTL_MS} for anything else (a PEM body is taken
     * as one of the former without decoding it). Never negative.
     */
    static long ttlFor(byte[] body, long ttlMs, long now) {
        if (body.length >= PEM_PREFIX.length && Arrays.equals(body, 0, PEM_PREFIX.length, PEM_PREFIX, 0,
                PEM_PREFIX.length)) {
            return ttlMs;
        }
        ASN1Primitive der;
        try {
            der = ASN1Primitive.fromByteArray(body);
        } catch (IOException | RuntimeException e) {
            return Math.min(ttlMs, UNPARSEABLE_TTL_MS);
        }
        if (!(der instanceof ASN1Sequence)) {
            return Math.min(ttlMs, UNPARSEABLE_TTL_MS);
        }
        try {
            CertificateList crl = CertificateList.getInstance(der);
            if (crl.getNextUpdate() == null) {
                return ttlMs;
            }
            long untilNextUpdate = crl.getNextUpdate().getDate().getTime() - now;
            return Math.max(0, Math.min(ttlMs, untilNextUpdate));
        } catch (RuntimeException notACrl) {
            // fall through
        }
        try {
            Certificate.getInstance(der);
            return ttlMs;
        } catch (RuntimeException notACertificate) {
            // fall through
        }
        try {
            ContentInfo.getInstance(der);
            return ttlMs;
        } catch (RuntimeException notCms) {
            return Math.min(ttlMs, UNPARSEABLE_TTL_MS);
        }
    }

    /** The cached URLs, least recently used first, for tests. */
    List<String> urls() {
        synchronized (entries) {
            return new ArrayList<>(entries.keySet());
        }
    }
}
