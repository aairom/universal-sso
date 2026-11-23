package com.universalsso.client;

import com.universalsso.client.SsoException.PolicyException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * Client-side safety policy for the authorization redirect.
 *
 * <p>The gateway owns the signed state, the PKCE verifier and the client secret. This class only
 * checks that the redirect about to be handed to a browser is sane for an OAuth 2.0 / OIDC
 * authorization-code flow (Okta uses one).
 */
public final class Policy {
    private Policy() {}

    /**
     * Verifies {@code redirect} and returns the {@code state} value it carries.
     *
     * <ul>
     *   <li>the scheme is http or https, and https is required unless the redirect stays on the
     *       gateway's own host (the mock provider);
     *   <li>when {@code expectedHost} is set, the host equals it or is a subdomain;
     *   <li>{@code state} is present and non-empty;
     *   <li>PKCE is in use: {@code code_challenge} present and {@code code_challenge_method} is
     *       {@code S256}.
     * </ul>
     *
     * @throws PolicyException when any rule is violated
     */
    public static String checkAuthorizeUrl(URI redirect, URI gateway, String expectedHost) throws PolicyException {
        String scheme = redirect.getScheme();
        if (scheme == null || !(scheme.equals("http") || scheme.equals("https"))) {
            throw new PolicyException("scheme '" + scheme + "' is not http or https");
        }
        boolean sameHost = Objects.equals(redirect.getRawAuthority(), gateway.getRawAuthority());
        if (!sameHost && !scheme.equals("https")) {
            throw new PolicyException("external identity provider must use https");
        }
        if (expectedHost != null) {
            String host = redirect.getHost() == null ? "" : redirect.getHost().toLowerCase(Locale.ROOT);
            if (!host.equals(expectedHost) && !host.endsWith("." + expectedHost)) {
                throw new PolicyException("host '" + host + "' is not '" + expectedHost + "' or a subdomain");
            }
        }
        Map<String, String> q = parseQuery(redirect.getRawQuery());
        String state = q.getOrDefault("state", "");
        if (state.isEmpty()) {
            throw new PolicyException("redirect has no state parameter");
        }
        if (q.getOrDefault("code_challenge", "").isEmpty() || !"S256".equals(q.get("code_challenge_method"))) {
            throw new PolicyException("redirect does not use PKCE with S256");
        }
        return state;
    }

    private static Map<String, String> parseQuery(String raw) {
        Map<String, String> out = new HashMap<>();
        if (raw == null) {
            return out;
        }
        for (String pair : raw.split("&")) {
            int i = pair.indexOf('=');
            String k = i < 0 ? pair : pair.substring(0, i);
            String v = i < 0 ? "" : pair.substring(i + 1);
            out.putIfAbsent(URLDecoder.decode(k, StandardCharsets.UTF_8), URLDecoder.decode(v, StandardCharsets.UTF_8));
        }
        return out;
    }
}
