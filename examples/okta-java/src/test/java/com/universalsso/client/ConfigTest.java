package com.universalsso.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.universalsso.client.SsoException.ConfigException;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ConfigTest {
    private static Config of(Map<String, String> env) throws ConfigException {
        return Config.fromLookup(env::get, "okta");
    }

    @Test
    void defaults() throws Exception {
        Config c = of(Map.of());
        assertEquals("http://localhost:8080", c.gatewayUrl().toString());
        assertEquals("okta", c.provider());
        assertEquals(10, c.timeout().toSeconds());
        assertNull(c.expectedIdpHost());
        assertEquals("http://localhost:8080/healthz", c.endpoint("/healthz"));
    }

    @Test
    void rejectsInvalidValues() {
        for (Map<String, String> env : java.util.List.of(
                Map.of("SSO_GATEWAY_URL", "ftp://x"),
                Map.of("SSO_GATEWAY_URL", "http://gateway.example.test"),
                Map.of("SSO_PROVIDER", "Bad Provider"),
                Map.of("SSO_HTTP_TIMEOUT_SECONDS", "0"),
                Map.of("SSO_HTTP_TIMEOUT_SECONDS", "abc"),
                Map.of("SSO_GATEWAY_URL", "http://bad host"))) {
            assertThrows(ConfigException.class, () -> of(env), env.toString());
        }
    }

    @Test
    void normalizesValues() throws Exception {
        Config c = of(Map.of("SSO_GATEWAY_URL", "https://sso.example.test/base/", "SSO_EXPECTED_IDP_HOST", " IdP.Example.Test "));
        assertEquals("https://sso.example.test/base", c.gatewayUrl().toString());
        assertEquals("idp.example.test", c.expectedIdpHost());
    }
}
