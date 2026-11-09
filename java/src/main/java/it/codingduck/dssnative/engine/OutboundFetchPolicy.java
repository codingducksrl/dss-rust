/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;

/**
 * The outbound-fetch policy, as a {@link DataLoader} decorator: what any HTTP client of the engine (trusted
 * lists, CRL, OCSP, AIA, TSA) may fetch, and how much. The URLs of CRL, OCSP and AIA requests come from the
 * documents being validated, so without this an attacker could point the engine at anything it can reach.
 *
 * <ul>
 *   <li><b>Scheme allow-list</b> ({@code http.allowed_schemes}, default http and https): LDAP, FTP and file URLs
 *       are refused unless enabled.</li>
 *   <li><b>Private addresses</b> ({@code http.block_private_addresses}, default on): loopback, private
 *       (10/8, 172.16/12, 192.168/16, fc00::/7), link-local (169.254/16, fe80::/10, cloud metadata services),
 *       carrier-grade NAT (100.64/10), multicast and unspecified addresses are refused, whether written as a
 *       literal or reached through a name. Names are resolved with the resolver given (the system one by
 *       default); a name that does not resolve is let through, since the client will fail on it anyway.</li>
 *   <li><b>Response size</b> ({@code http.max_response_bytes}): a body larger than this fails the request after
 *       download, before anything parses it.</li>
 *   <li><b>Deadline</b> ({@code http.request_deadline_ms}, 0 disables): a wall-clock bound on the whole request,
 *       redirects and retries included, on top of the client's connect and read timeouts, which a server that
 *       trickles bytes never trips. Runs the request on a daemon thread and abandons it when the deadline passes;
 *       the thread ends when the client's own socket timeout does.</li>
 * </ul>
 *
 * <p><b>Redirects</b>: a client that followed them itself would follow a public URL to a private address
 * without this policy seeing it. When the delegate is one of DSS's Apache HttpClient loaders ({@link
 * CommonsDataLoader}) with redirects enabled ({@code http.follow_redirects}, the default), the policy takes them
 * over: the client is told not to follow, a response handler turns a 3xx with a {@code Location} into a
 * {@link Redirect}, and the policy follows it only after checking the target like any other URL, up to
 * {@value #MAX_REDIRECTS} hops and within the same deadline. A POST (OCSP, TSA) is re-sent only on 307 and 308,
 * which keep the method. Any other delegate that signals a redirect the same way (a {@link Redirect} in the
 * cause chain of its exception) is followed the same way. With {@code http.follow_redirects} off, the client
 * fails on the 3xx and nothing is followed.
 *
 * <p>This class holds no reference to the configuration, so it is safe to share.
 */
public final class OutboundFetchPolicy implements DataLoader {

    private static final long serialVersionUID = 1L;
    private static final Logger LOG = LoggerFactory.getLogger(OutboundFetchPolicy.class);

    /** Resolves a host name to its addresses; {@link UnknownHostException} when it has none. */
    @FunctionalInterface
    public interface Resolver {
        List<InetAddress> resolve(String host) throws UnknownHostException;
    }

    /** The system resolver. */
    public static final Resolver SYSTEM_RESOLVER = host -> List.of(InetAddress.getAllByName(host));

    /** How many redirects one request may go through. */
    public static final int MAX_REDIRECTS = 10;

    /**
     * A redirect the HTTP client stopped at, for the policy to decide on; the response handler {@link #wrap}
     * installs throws it, and a delegate that handles its own HTTP may throw it (wrapped in a
     * {@link DSSExternalResourceException}) to have the policy follow a redirect.
     */
    public static final class Redirect extends IOException {
        private static final long serialVersionUID = 1L;
        private final int status;
        private final String location;

        public Redirect(int status, String location) {
            super("HTTP " + status + " redirect to " + location);
            this.status = status;
            this.location = Objects.requireNonNull(location, "location");
        }

        public int status() {
            return status;
        }

        public String location() {
            return location;
        }
    }

    /** Hands 3xx responses with a {@code Location} to the policy as a {@link Redirect}; the rest to the loader's own handler. */
    static final class RedirectInterceptingHandler implements HttpClientResponseHandler<byte[]> {
        private final HttpClientResponseHandler<byte[]> next;

        RedirectInterceptingHandler(HttpClientResponseHandler<byte[]> next) {
            this.next = Objects.requireNonNull(next, "next");
        }

        @Override
        public byte[] handleResponse(ClassicHttpResponse response) throws IOException, HttpException {
            int code = response.getCode();
            if (code == 301 || code == 302 || code == 303 || code == 307 || code == 308) {
                Header location = response.getFirstHeader("Location");
                if (location != null && location.getValue() != null && !location.getValue().isBlank()) {
                    EntityUtils.consumeQuietly(response.getEntity());
                    throw new Redirect(code, location.getValue().trim());
                }
            }
            return next.handleResponse(response);
        }
    }

    /** The policy's settings; {@link #of(EngineConfig)} reads them from {@code config.http}. */
    public record Settings(List<String> allowedSchemes, boolean blockPrivateAddresses, long maxResponseBytes,
                           long requestDeadlineMs) {
        public Settings {
            Objects.requireNonNull(allowedSchemes, "allowedSchemes");
            allowedSchemes = allowedSchemes.stream().map(s -> s.toLowerCase(Locale.ROOT)).toList();
            if (allowedSchemes.isEmpty()) {
                throw new IllegalArgumentException("at least one scheme must be allowed");
            }
            if (maxResponseBytes < 1) {
                throw new IllegalArgumentException("maxResponseBytes must be positive");
            }
            if (requestDeadlineMs < 0) {
                throw new IllegalArgumentException("requestDeadlineMs must not be negative");
            }
        }

        public static Settings of(EngineConfig config) {
            return new Settings(config.httpAllowedSchemes, config.httpBlockPrivateAddresses,
                    config.httpMaxResponseBytes, config.httpRequestDeadlineMs);
        }
    }

    /** Daemon threads that run requests under a deadline; idle ones end after a minute. */
    private static final ExecutorService DEADLINE_POOL = Executors.newCachedThreadPool(new java.util.concurrent.ThreadFactory() {
        private final AtomicInteger id = new AtomicInteger();

        @Override
        public Thread newThread(Runnable r) {
            Thread t = new Thread(r, "dss-fetch-" + id.incrementAndGet());
            t.setDaemon(true);
            return t;
        }
    });

    private final DataLoader delegate;
    private final Settings settings;
    private final transient Resolver resolver;

    /**
     * @param delegate the client; when it is a {@link CommonsDataLoader} with redirects enabled, it is changed to
     *                 leave redirects to this policy (see the class comment)
     */
    public OutboundFetchPolicy(DataLoader delegate, Settings settings, Resolver resolver) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.settings = Objects.requireNonNull(settings, "settings");
        this.resolver = Objects.requireNonNull(resolver, "resolver");
        if (delegate instanceof CommonsDataLoader client && client.isRedirectsEnabled()) {
            client.setRedirectsEnabled(false);
            if (!(client.getHttpClientResponseHandler() instanceof RedirectInterceptingHandler)) {
                client.setHttpClientResponseHandler(new RedirectInterceptingHandler(client.getHttpClientResponseHandler()));
            }
        }
    }

    /** {@code delegate} under the policy {@code config.http} describes, with the system resolver. */
    public static OutboundFetchPolicy wrap(DataLoader delegate, EngineConfig config) {
        return new OutboundFetchPolicy(delegate, Settings.of(config), SYSTEM_RESOLVER);
    }

    public DataLoader delegate() {
        return delegate;
    }

    public Settings settings() {
        return settings;
    }

    /**
     * Checks a URL against the policy without fetching it.
     *
     * @throws DSSExternalResourceException when the policy refuses it
     */
    public void check(String url) {
        URI uri;
        try {
            uri = new URI(url.trim());
        } catch (URISyntaxException e) {
            throw refused(url, "not a valid URL");
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!settings.allowedSchemes.contains(scheme)) {
            throw refused(url, "scheme '" + scheme + "' is not allowed (allowed: "
                    + String.join(", ", settings.allowedSchemes) + ")");
        }
        if (uri.getRawUserInfo() != null) {
            throw refused(url, "credentials in the URL are not allowed");
        }
        if (!settings.blockPrivateAddresses || !(scheme.equals("http") || scheme.equals("https"))) {
            return; // the address rules are about IP networks: nothing to check for other schemes
        }
        String host = uri.getHost();
        if (host == null) {
            throw refused(url, "no host");
        }
        String bare = host.startsWith("[") && host.endsWith("]") ? host.substring(1, host.length() - 1) : host;
        String lower = bare.toLowerCase(Locale.ROOT);
        if (lower.equals("localhost") || lower.endsWith(".localhost")) {
            throw refused(url, "loopback host");
        }
        List<InetAddress> addresses;
        if (isLiteral(bare)) {
            try {
                addresses = List.of(InetAddress.getByName(bare)); // a literal: no name lookup happens
            } catch (UnknownHostException e) {
                throw refused(url, "invalid address literal");
            }
        } else {
            try {
                addresses = resolver.resolve(bare);
            } catch (UnknownHostException e) {
                LOG.debug("Outbound policy cannot resolve {}: letting the client fail on it", host);
                return;
            }
        }
        for (InetAddress a : addresses) {
            String why = privateReason(a);
            if (why != null) {
                throw refused(url, host + " is a " + why + " address (" + a.getHostAddress() + ")");
            }
        }
    }

    /** Why {@code a} may not be contacted, or null when it is a public unicast address. */
    public static String privateReason(InetAddress a) {
        if (a.isLoopbackAddress()) {
            return "loopback";
        }
        if (a.isAnyLocalAddress()) {
            return "unspecified";
        }
        if (a.isMulticastAddress()) {
            return "multicast";
        }
        if (a.isLinkLocalAddress()) {
            return "link-local";
        }
        if (a.isSiteLocalAddress()) {
            return "private";
        }
        byte[] b = a.getAddress();
        if (a instanceof Inet4Address) {
            int first = b[0] & 0xff;
            int second = b[1] & 0xff;
            if (first == 0) {
                return "unspecified";
            }
            if (first == 100 && second >= 64 && second <= 127) {
                return "carrier-grade NAT";
            }
            if (first == 192 && second == 0 && (b[2] & 0xff) == 0) {
                return "IETF protocol assignment";
            }
            if (first == 255) {
                return "broadcast";
            }
        } else if (a instanceof Inet6Address) {
            if ((b[0] & 0xfe) == 0xfc) {
                return "unique-local";
            }
            if ((b[0] & 0xff) == 0xfe && (b[1] & 0xc0) == 0xc0) {
                return "site-local";
            }
        }
        return null;
    }

    private static boolean isLiteral(String host) {
        return host.indexOf(':') >= 0 || host.matches("[0-9.]+");
    }

    private static DSSExternalResourceException refused(String url, String reason) {
        return new DSSExternalResourceException("outbound request to " + url + " refused by policy: " + reason);
    }

    @Override
    public byte[] get(String url) {
        check(url);
        return sized(url, bounded(url, () -> follow(url, null)));
    }

    /**
     * The first URL that answers, as DSS's clients do it, each request under this policy (redirects included)
     * and all of them under one deadline.
     */
    @Override
    public DataAndUrl get(List<String> urls) {
        if (urls == null || urls.isEmpty()) {
            throw new DSSExternalResourceException("Cannot process the GET call. List of URLs is empty!");
        }
        List<String> allowed = new ArrayList<>();
        DSSExternalResourceException last = null;
        for (String url : urls) {
            try {
                check(url);
                allowed.add(url);
            } catch (DSSExternalResourceException e) {
                LOG.warn(e.getMessage());
                last = e;
            }
        }
        if (allowed.isEmpty()) {
            throw last;
        }
        return bounded(String.join(", ", allowed), () -> {
            DSSExternalResourceException failure = null;
            for (String url : allowed) {
                try {
                    return new DataAndUrl(url, sized(url, follow(url, null)));
                } catch (DSSExternalResourceException e) {
                    LOG.debug("Cannot fetch {}: {}", url, e.getMessage());
                    failure = e;
                }
            }
            throw failure;
        });
    }

    @Override
    public byte[] post(String url, byte[] content) {
        check(url);
        return sized(url, bounded(url, () -> follow(url, content)));
    }

    /**
     * Runs the request (a GET, or a POST of {@code content}); each time the client stops at a redirect, checks
     * the target and tries again there, up to {@link #MAX_REDIRECTS} times.
     */
    private byte[] follow(String url, byte[] content) {
        String current = url;
        for (int hop = 0;; hop++) {
            try {
                return content == null ? delegate.get(current) : delegate.post(current, content);
            } catch (DSSExternalResourceException e) {
                Redirect redirect = redirectIn(e);
                if (redirect == null) {
                    throw e;
                }
                if (hop >= MAX_REDIRECTS) {
                    throw new DSSExternalResourceException("request to " + url + " was redirected more than "
                            + MAX_REDIRECTS + " times (last to " + redirect.location() + ")");
                }
                if (content != null && redirect.status() != 307 && redirect.status() != 308) {
                    throw new DSSExternalResourceException("the POST to " + current + " answered HTTP " + redirect.status()
                            + " (redirect to " + redirect.location() + "), which a POST does not follow");
                }
                String next;
                try {
                    next = new URI(current).resolve(redirect.location().trim()).toString();
                } catch (URISyntaxException | IllegalArgumentException ex) {
                    throw new DSSExternalResourceException("redirect from " + current + " to '" + redirect.location()
                            + "' refused by policy: not a valid URL");
                }
                try {
                    check(next);
                } catch (DSSExternalResourceException refusal) {
                    throw new DSSExternalResourceException("redirect from " + current + " refused: " + refusal.getMessage(),
                            refusal);
                }
                LOG.debug("Following HTTP {} redirect from {} to {}", redirect.status(), current, next);
                current = next;
            }
        }
    }

    /** The {@link Redirect} in the cause chain of {@code e}, or null. */
    private static Redirect redirectIn(Throwable e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof Redirect r) {
                return r;
            }
            if (t.getCause() == t) {
                break;
            }
        }
        return null;
    }

    @Override
    public void setContentType(String contentType) {
        delegate.setContentType(contentType);
    }

    private byte[] sized(String url, byte[] body) {
        if (body != null && body.length > settings.maxResponseBytes) {
            throw new DSSExternalResourceException("response from " + url + " is " + body.length
                    + " bytes, above the limit of " + settings.maxResponseBytes + " (http.max_response_bytes)");
        }
        return body;
    }

    /** Runs {@code call} inline, or on the deadline pool when a deadline is set. */
    private <T> T bounded(String what, Callable<T> call) {
        if (settings.requestDeadlineMs == 0) {
            return callInline(call);
        }
        Future<T> future = DEADLINE_POOL.submit(call);
        try {
            return future.get(settings.requestDeadlineMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            throw new DSSExternalResourceException("request to " + what + " exceeded the deadline of "
                    + settings.requestDeadlineMs + " ms (http.request_deadline_ms)");
        } catch (InterruptedException e) {
            future.cancel(true);
            Thread.currentThread().interrupt();
            throw new DSSExternalResourceException("request to " + what + " interrupted");
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException r) {
                throw r;
            }
            if (cause instanceof Error err) {
                throw err;
            }
            throw new DSSExternalResourceException("request to " + what + " failed: " + cause, cause);
        }
    }

    private static <T> T callInline(Callable<T> call) {
        try {
            return call.call();
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new DSSExternalResourceException(e.getMessage(), e);
        }
    }
}
