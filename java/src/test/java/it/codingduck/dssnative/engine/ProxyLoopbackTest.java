/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import it.codingduck.dssnative.testsupport.FakeHttp;
import it.codingduck.dssnative.testsupport.Fixtures;
import it.codingduck.dssnative.testsupport.SyntheticTrustedLists;
import it.codingduck.dssnative.testsupport.TestEngines;

/**
 * {@code http.proxy}: the real HTTP stack sends every trusted-list request to a forward proxy on 127.0.0.1 (a
 * minimal one, speaking just enough HTTP/1.1 to serve absolute-URI GETs), never to the lists' own hosts, whose
 * names do not even resolve here.
 */
class ProxyLoopbackTest {

    private static final String TL_BASE = "http://tl.dss-native.test";

    @TempDir
    Path tmp;
    private TestEngines t;
    private ServerSocket proxy;
    private Thread acceptor;
    private FakeHttp content;
    private final List<String> requests = new CopyOnWriteArrayList<>();

    @BeforeEach
    void startProxy() throws IOException {
        t = new TestEngines(tmp);
        content = new FakeHttp();
        new SyntheticTrustedLists(t.pki, 1).withBaseUrl(TL_BASE).serveOn(content);
        proxy = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        acceptor = new Thread(this::accept, "test-proxy");
        acceptor.setDaemon(true);
        acceptor.start();
    }

    @AfterEach
    void stopProxy() throws IOException {
        proxy.close();
    }

    private void accept() {
        while (!proxy.isClosed()) {
            try {
                Socket socket = proxy.accept();
                Thread worker = new Thread(() -> serve(socket), "test-proxy-conn");
                worker.setDaemon(true);
                worker.start();
            } catch (IOException e) {
                return; // closed
            }
        }
    }

    /** One request per connection: "GET http://host/path HTTP/1.1", headers, then the body from {@link #content}. */
    private void serve(Socket socket) {
        try (socket) {
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.ISO_8859_1));
            String requestLine = in.readLine();
            String line;
            String proxyAuthorization = null;
            while ((line = in.readLine()) != null && !line.isEmpty()) {
                if (line.toLowerCase().startsWith("proxy-authorization:")) {
                    proxyAuthorization = line.substring("proxy-authorization:".length()).trim();
                }
            }
            requests.add(requestLine + (proxyAuthorization == null ? "" : " [" + proxyAuthorization + "]"));
            OutputStream out = socket.getOutputStream();
            if (proxyAuthorization == null) {
                // Like a real proxy: challenge first; HttpClient answers with the configured credentials.
                out.write(("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\n"
                        + "Content-Length: 0\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
                out.flush();
                return;
            }
            String[] parts = requestLine == null ? new String[0] : requestLine.split(" ");
            byte[] body = null;
            if (parts.length == 3 && parts[0].equals("GET") && parts[1].startsWith("http://")) {
                try {
                    body = content.get(parts[1]);
                } catch (RuntimeException e) {
                    body = null;
                }
            }
            if (body == null) {
                out.write("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
            } else {
                out.write(("HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: " + body.length
                        + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
                out.write(body);
            }
            out.flush();
        } catch (IOException e) {
            // the client went away
        }
    }

    @Test
    void trustedListsAreDownloadedThroughTheConfiguredProxy() {
        String config = "{\"lotl_url\":\"" + TL_BASE + "/eu-lotl.xml\","
                + "\"oj_url\":\"" + SyntheticTrustedLists.OJ_URL + "\","
                + "\"oj_keystore\":{\"path\":\"" + t.ojKeystore.toString().replace("\\", "\\\\") + "\",\"password\":\"dss-password\"},"
                + "\"revocation\":\"offline\",\"aia\":false,"
                // The policy would resolve the .test names to check them; off, they go straight to the proxy.
                + "\"http\":{\"block_private_addresses\":false,\"proxy\":{\"host\":\"127.0.0.1\",\"port\":"
                + proxy.getLocalPort() + ",\"username\":\"proxy-user\",\"password\":\"proxy-secret\"}}}";
        try (DssEngine engine = DssEngine.create(tmp.resolve("cache"), EngineConfig.fromJson(config))) {
            TrustedListManager.RefreshRecord rec = engine.refreshTrustedListsOnline();
            assertTrue(rec.completed(), Json.write(engine.trustedListStatus()));
            assertEquals(3, rec.trustedCertificates(), Json.write(engine.trustedListStatus()));
            assertEquals("TOTAL_PASSED/-", FixtureValidationTest.verdicts(
                    engine.validate(Fixtures.read("pades/b-lta.pdf"), ValidationOptions.DEFAULT)).get(0));
        }
        assertTrue(requests.stream().anyMatch(r -> r.startsWith("GET " + TL_BASE + "/eu-lotl.xml HTTP/1.1")),
                requests.toString());
        assertTrue(requests.stream().anyMatch(r -> r.contains(TL_BASE + "/IT.xml")), requests.toString());
        String expected = "[Basic " + java.util.Base64.getEncoder().encodeToString(
                "proxy-user:proxy-secret".getBytes(StandardCharsets.UTF_8)) + "]";
        assertTrue(requests.stream().anyMatch(r -> r.endsWith(expected)), "credentials go to the proxy: " + requests);
    }
}
