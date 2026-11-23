package com.universalsso.client;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/** In-process fake that mimics the ssod contract for tests. */
final class FakeGateway implements AutoCloseable {
    private final HttpServer server;

    FakeGateway() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        json("/healthz", 200, "{\"status\":\"ok\"}");
        json("/providers", 200, "{\"providers\":[\"mock\",\"okta\"]}");
        redirect("/auth/mock/login", "/mock/authorize?state=s1&code_challenge=c&code_challenge_method=S256");
        redirect("/mock/authorize", "/auth/mock/callback?code=mock-code&state=s1");
        json(
                "/auth/mock/callback",
                200,
                "{\"provider_id\":\"mock\",\"user\":{\"id\":\"u1\",\"email\":\"a@b.test\",\"display_name\":\"Mock User\"}}");
        redirect(
                "/auth/okta/login",
                "https://tenant.example.test/authorize?state=s2&code_challenge=c&code_challenge_method=S256");
        json("/auth/missing/login", 404, "{\"code\":\"PROVIDER_NOT_FOUND\",\"message\":\"missing\"}");
        redirect("/auth/weak/login", "https://tenant.example.test/authorize?state=s3");
        json("/", 500, "boom");
        server.start();
    }

    String baseUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    Map<String, String> env(String provider) {
        return Map.of("SSO_GATEWAY_URL", baseUrl(), "SSO_PROVIDER", provider);
    }

    private void json(String path, int status, String body) {
        server.createContext(path, ex -> {
            byte[] b = body.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "application/json");
            ex.sendResponseHeaders(status, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
    }

    private void redirect(String path, String to) {
        server.createContext(path, ex -> {
            ex.getResponseHeaders().add("Location", to);
            ex.sendResponseHeaders(302, -1);
            ex.close();
        });
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
