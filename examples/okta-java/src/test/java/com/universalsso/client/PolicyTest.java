package com.universalsso.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.universalsso.client.SsoException.PolicyException;
import java.net.URI;
import java.util.Map;
import org.junit.jupiter.api.Test;

class PolicyTest {
    private static final URI GW = URI.create("http://localhost:8080");
    private static final String PKCE = "state=a&code_challenge=x&code_challenge_method=S256";

    @Test
    void acceptsGoodRedirects() throws Exception {
        URI ok = URI.create("https://tenant.example.test/authorize?state=abc&code_challenge=x&code_challenge_method=S256");
        assertEquals("abc", Policy.checkAuthorizeUrl(ok, GW, "example.test"));
        URI local = URI.create("http://localhost:8080/mock/authorize?" + PKCE);
        assertEquals("a", Policy.checkAuthorizeUrl(local, GW, null));
    }

    @Test
    void refusesUnsafeRedirects() {
        Map<String, String> cases = Map.of(
                "scheme", "ftp://tenant.example.test/a?" + PKCE,
                "plain http", "http://tenant.example.test/a?" + PKCE,
                "wrong host", "https://evil.test/a?" + PKCE,
                "look-alike", "https://notexample.test/a?" + PKCE,
                "no state", "https://tenant.example.test/a?code_challenge=x&code_challenge_method=S256",
                "no pkce", "https://tenant.example.test/a?state=a",
                "plain pkce", "https://tenant.example.test/a?state=a&code_challenge=x&code_challenge_method=plain");
        cases.forEach((name, url) ->
                assertThrows(PolicyException.class, () -> Policy.checkAuthorizeUrl(URI.create(url), GW, "example.test"), name));
    }
}
