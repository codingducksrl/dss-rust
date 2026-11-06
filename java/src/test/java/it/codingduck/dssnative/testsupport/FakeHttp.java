/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.testsupport;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.function.Supplier;

import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;

/**
 * In-memory stand-in for DSS's HTTP data loader: unit tests never open a socket. Routes are URL → supplier, so
 * content (CRLs, trusted lists) can be generated fresh on each request.
 */
public final class FakeHttp implements DataLoader {

    private static final long serialVersionUID = 1L;

    private final transient Map<String, Supplier<byte[]>> routes = new ConcurrentHashMap<>();
    private final transient Map<String, Function<byte[], byte[]>> postRoutes = new ConcurrentHashMap<>();
    private final transient Map<String, AtomicInteger> hits = new ConcurrentHashMap<>();
    private volatile transient Runnable beforeEachRequest = () -> { };
    private volatile boolean offline;

    public FakeHttp route(String url, Supplier<byte[]> body) {
        routes.put(url, body);
        return this;
    }

    public FakeHttp route(String url, byte[] body) {
        return route(url, () -> body);
    }

    /** Answers POSTs to {@code url} from the request body (a TSA). Other POSTs are served like GETs. */
    public FakeHttp postRoute(String url, Function<byte[], byte[]> handler) {
        postRoutes.put(url, handler);
        return this;
    }

    /** Runs before serving any request; tests use it to slow down or block a refresh. */
    public FakeHttp beforeEachRequest(Runnable hook) {
        this.beforeEachRequest = hook;
        return this;
    }

    /** When set, every request fails as if the network were down. */
    public FakeHttp offline(boolean value) {
        this.offline = value;
        return this;
    }

    public int hits(String url) {
        AtomicInteger n = hits.get(url);
        return n == null ? 0 : n.get();
    }

    public int totalHits() {
        return hits.values().stream().mapToInt(AtomicInteger::get).sum();
    }

    @Override
    public byte[] get(String url) {
        hits.computeIfAbsent(url, k -> new AtomicInteger()).incrementAndGet();
        beforeEachRequest.run();
        if (offline) {
            throw new DSSExternalResourceException("FakeHttp is offline: " + url);
        }
        Supplier<byte[]> body = routes.get(url);
        if (body == null) {
            throw new DSSExternalResourceException("FakeHttp: no route for " + url);
        }
        return body.get();
    }

    @Override
    public DataAndUrl get(List<String> urls) {
        DSSExternalResourceException last = null;
        for (String url : urls) {
            try {
                return new DataAndUrl(url, get(url));
            } catch (DSSExternalResourceException e) {
                last = e;
            }
        }
        throw last != null ? last : new DSSExternalResourceException("FakeHttp: no URL given");
    }

    @Override
    public byte[] post(String url, byte[] content) {
        Function<byte[], byte[]> handler = postRoutes.get(url);
        if (handler == null) {
            return get(url);
        }
        hits.computeIfAbsent(url, k -> new AtomicInteger()).incrementAndGet();
        beforeEachRequest.run();
        if (offline) {
            throw new DSSExternalResourceException("FakeHttp is offline: " + url);
        }
        return handler.apply(content);
    }

    @Override
    public void setContentType(String contentType) {
        // irrelevant in memory
    }
}
