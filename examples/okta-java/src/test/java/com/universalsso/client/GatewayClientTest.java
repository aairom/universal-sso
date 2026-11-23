package com.universalsso.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.universalsso.client.SsoException.ApiException;
import com.universalsso.client.SsoException.LeavesGatewayException;
import com.universalsso.client.SsoException.PolicyException;
import com.universalsso.client.SsoException.TransportException;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class GatewayClientTest {
    private static GatewayClient client(Map<String, String> env) throws Exception {
        return new GatewayClient(Config.fromLookup(env::get, "okta"));
    }

    @Test
    void healthAndProviders() throws Exception {
        try (FakeGateway gw = new FakeGateway()) {
            GatewayClient c = client(gw.env("mock"));
            c.health();
            assertEquals(List.of("mock", "okta"), c.providers());
        }
    }

    @Test
    void mockFlowCompletesWithoutBrowser() throws Exception {
        try (FakeGateway gw = new FakeGateway()) {
            GatewayClient c = client(gw.env("mock"));
            GatewayClient.Login login = c.startLogin();
            assertEquals("s1", login.state());
            GatewayClient.Profile p = c.followLocal(login);
            assertEquals("mock", p.providerId());
            assertEquals("a@b.test", p.user().email());
        }
    }

    @Test
    void externalIdpNeedsABrowser() throws Exception {
        try (FakeGateway gw = new FakeGateway()) {
            GatewayClient c = client(gw.env("okta"));
            GatewayClient.Login login = c.startLogin();
            assertEquals("s2", login.state());
            assertThrows(LeavesGatewayException.class, () -> c.followLocal(login));
        }
    }

    @Test
    void missingProviderIsStructuredError() throws Exception {
        try (FakeGateway gw = new FakeGateway()) {
            ApiException e = assertThrows(ApiException.class, () -> client(gw.env("missing")).startLogin());
            assertEquals(404, e.status());
            assertEquals("PROVIDER_NOT_FOUND", e.code());
        }
    }

    @Test
    void redirectWithoutPkceIsRefused() throws Exception {
        try (FakeGateway gw = new FakeGateway()) {
            assertThrows(PolicyException.class, () -> client(gw.env("weak")).startLogin());
        }
    }

    @Test
    void nonJsonErrorBody() throws Exception {
        try (FakeGateway gw = new FakeGateway()) {
            ApiException e = assertThrows(ApiException.class, () -> client(gw.env("other")).startLogin());
            assertEquals("UNKNOWN", e.code());
            assertEquals(500, e.status());
        }
    }

    @Test
    void unreachableGateway() throws Exception {
        GatewayClient c = client(Map.of("SSO_GATEWAY_URL", "http://127.0.0.1:1"));
        assertThrows(TransportException.class, c::health);
    }
}
