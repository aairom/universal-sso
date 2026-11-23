package com.universalsso.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.universalsso.client.SsoException.ApiException;
import com.universalsso.client.SsoException.LeavesGatewayException;
import com.universalsso.client.SsoException.PolicyException;
import com.universalsso.client.SsoException.TransportException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * HTTP client for the Universal SSO gateway.
 *
 * <p>Contract (see {@code cmd/ssod/handler.go}):
 *
 * <pre>
 * GET /healthz                   -> 200 {"status":"ok"}
 * GET /providers                 -> 200 {"providers":[...]}
 * GET /auth/{provider}/login     -> 302 Location: IdP authorization URL
 * GET /auth/{provider}/callback  -> 200 {"provider_id":"...","user":{...}}
 * any error                      -> {"code":"...","message":"..."}
 * </pre>
 *
 * Redirects are never followed automatically so every hop can be checked. Instances are thread-safe.
 */
public final class GatewayClient {
    private static final Logger LOG = Logger.getLogger(GatewayClient.class.getName());
    private static final int MAX_BODY = 1 << 20;
    private static final int MAX_HOPS = 5;
    private static final ObjectMapper JSON = new ObjectMapper();

    /** Normalized user profile returned by the gateway callback. */
    public record User(String id, String email, boolean emailVerified, String displayName, List<String> roles) {}

    /** Body of a successful callback. */
    public record Profile(String providerId, User user) {}

    /**
     * A started sign-in.
     *
     * @param authorizeUrl where the user's browser must go; it passed the redirect policy
     * @param state signed state the gateway issued for this attempt
     */
    public record Login(URI authorizeUrl, String state) {}

    private record Reply(int status, String location, byte[] body) {}

    private final Config cfg;
    private final HttpClient http;

    public GatewayClient(Config cfg) {
        this.cfg = cfg;
        this.http = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(cfg.timeout())
                .build();
    }

    /** The configuration in use. */
    public Config config() {
        return cfg;
    }

    private Reply get(URI uri) throws TransportException {
        HttpRequest req = HttpRequest.newBuilder(uri)
                .timeout(cfg.timeout())
                .header("Accept", "application/json")
                .GET()
                .build();
        try {
            HttpResponse<InputStream> resp = http.send(req, HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream in = resp.body()) {
                byte[] body = in.readNBytes(MAX_BODY);
                return new Reply(resp.statusCode(), resp.headers().firstValue("Location").orElse(null), body);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TransportException("request interrupted", e);
        } catch (IOException | IllegalArgumentException e) {
            throw new TransportException("request failed: " + e.getMessage(), e);
        }
    }

    private static ApiException apiError(Reply r) {
        try {
            JsonNode n = JSON.readTree(r.body());
            if (n != null && n.hasNonNull("code")) {
                return new ApiException(r.status(), n.get("code").asText(), n.path("message").asText(""));
            }
        } catch (IOException ignored) {
            // fall through to the raw body
        }
        String text = new String(r.body(), StandardCharsets.UTF_8).strip();
        return new ApiException(r.status(), "UNKNOWN", text.length() > 200 ? text.substring(0, 200) : text);
    }

    /** Returns normally when the gateway reports {@code {"status":"ok"}}. */
    public void health() throws TransportException {
        Reply r = get(URI.create(cfg.endpoint("/healthz")));
        boolean ok = false;
        try {
            ok = r.status() == 200 && "ok".equals(JSON.readTree(r.body()).path("status").asText());
        } catch (IOException ignored) {
            // treated as unhealthy
        }
        if (!ok) {
            throw new TransportException("gateway not healthy: HTTP " + r.status());
        }
    }

    /** Lists the provider ids registered in the gateway. */
    public List<String> providers() throws SsoException {
        Reply r = get(URI.create(cfg.endpoint("/providers")));
        if (r.status() != 200) {
            throw apiError(r);
        }
        try {
            List<String> ids = new ArrayList<>();
            for (JsonNode n : JSON.readTree(r.body()).path("providers")) {
                ids.add(n.asText());
            }
            return ids;
        } catch (IOException e) {
            throw new TransportException("decode providers: " + e.getMessage(), e);
        }
    }

    /**
     * Asks the gateway to begin a sign-in and validates the redirect.
     *
     * @throws ApiException the gateway refused (for example {@code PROVIDER_NOT_FOUND})
     * @throws PolicyException the redirect failed the safety policy
     */
    public Login startLogin() throws SsoException {
        String path = "/auth/" + URLEncoder.encode(cfg.provider(), StandardCharsets.UTF_8) + "/login";
        Reply r = get(URI.create(cfg.endpoint(path)));
        if (r.status() != 302 && r.status() != 303) {
            throw apiError(r);
        }
        if (r.location() == null) {
            throw new TransportException("gateway redirect has no Location header");
        }
        URI target = resolve(cfg.gatewayUrl(), r.location());
        String state = Policy.checkAuthorizeUrl(target, cfg.gatewayUrl(), cfg.expectedIdpHost());
        LOG.fine(() -> "login started provider=" + cfg.provider() + " idp_host=" + target.getAuthority());
        return new Login(target, state);
    }

    private static URI resolve(URI base, String location) throws TransportException {
        try {
            return URI.create(base.toString() + "/").resolve(location);
        } catch (IllegalArgumentException e) {
            throw new TransportException("bad Location header: " + e.getMessage(), e);
        }
    }

    private boolean sameHost(URI u) {
        return Objects.equals(u.getRawAuthority(), cfg.gatewayUrl().getRawAuthority());
    }

    /**
     * Completes a sign-in without a browser while every redirect stays on the gateway host. That
     * holds for the mock provider, which is why it is used for tests and demos. A real identity
     * provider needs a person at a browser.
     *
     * @throws LeavesGatewayException a redirect points at another host
     */
    public Profile followLocal(Login login) throws SsoException {
        URI next = login.authorizeUrl();
        if (!sameHost(next)) {
            throw new LeavesGatewayException();
        }
        for (int hop = 0; hop < MAX_HOPS; hop++) {
            Reply r = get(next);
            if (r.status() == 200) {
                return parseProfile(r.body());
            }
            if (r.status() != 302 || r.location() == null) {
                throw apiError(r);
            }
            next = next.resolve(r.location());
            if (!sameHost(next)) {
                throw new LeavesGatewayException();
            }
        }
        throw new TransportException("too many redirects");
    }

    private static Profile parseProfile(byte[] body) throws TransportException {
        try {
            JsonNode root = JSON.readTree(body);
            JsonNode u = root.path("user");
            if (u.path("id").asText("").isEmpty()) {
                throw new TransportException("callback response is not a profile");
            }
            List<String> roles = new ArrayList<>();
            for (JsonNode n : u.path("roles")) {
                roles.add(n.asText());
            }
            return new Profile(
                    root.path("provider_id").asText(""),
                    new User(
                            u.path("id").asText(),
                            u.path("email").asText(""),
                            u.path("email_verified").asBoolean(false),
                            u.path("display_name").asText(""),
                            roles));
        } catch (IOException e) {
            throw new TransportException("callback response is not a profile", e);
        }
    }
}
