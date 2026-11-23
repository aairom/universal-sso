package com.universalsso.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.Test;

class MainTest {
    private record Result(int code, String out, String err) {}

    private static Result call(Map<String, String> env, String... args) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        ByteArrayOutputStream e = new ByteArrayOutputStream();
        int code = Main.run(args, env::get, new PrintStream(o, true, StandardCharsets.UTF_8), new PrintStream(e, true, StandardCharsets.UTF_8));
        return new Result(code, o.toString(StandardCharsets.UTF_8), e.toString(StandardCharsets.UTF_8));
    }

    @Test
    void usageAndBadInput() {
        Map<String, String> none = Map.of();
        assertEquals(2, call(none).code());
        assertEquals(2, call(none, "bogus").code());
        assertEquals(2, call(none, "login", "--nope").code());
        assertEquals(2, call(Map.of("SSO_GATEWAY_URL", "ftp://x"), "check").code());
    }

    @Test
    void check() throws Exception {
        try (FakeGateway gw = new FakeGateway()) {
            Result ok = call(gw.env("mock"), "check");
            assertEquals(0, ok.code());
            assertTrue(ok.out().contains("providers: mock, okta"));
            Result missing = call(gw.env("saml"), "check");
            assertEquals(1, missing.code());
            assertTrue(missing.err().contains("not registered"));
        }
        assertEquals(1, call(Map.of("SSO_GATEWAY_URL", "http://127.0.0.1:1"), "check").code());
    }

    @Test
    void login() throws Exception {
        try (FakeGateway gw = new FakeGateway()) {
            Result browser = call(gw.env("okta"), "login");
            assertEquals(0, browser.code());
            assertTrue(browser.out().contains("https://tenant.example.test/authorize"));
            Result follow = call(gw.env("mock"), "login", "--follow");
            assertEquals(0, follow.code());
            assertTrue(follow.out().contains("signed in via mock as Mock User"));
            Result external = call(gw.env("okta"), "login", "--follow");
            assertEquals(1, external.code());
            assertTrue(external.err().contains("open the URL in a browser"));
            assertTrue(call(gw.env("missing"), "login").err().contains("no such provider"));
            assertTrue(call(gw.env("weak"), "login").err().contains("refused to continue"));
            assertTrue(call(gw.env("other"), "login").err().contains("login failed"));
        }
    }
}
