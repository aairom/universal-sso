package com.universalsso.client;

import com.universalsso.client.SsoException.ConfigException;
import java.net.URI;
import java.time.Duration;
import java.util.Locale;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * Settings for talking to the Universal SSO gateway ({@code ssod}), read from the environment.
 *
 * @param gatewayUrl base URL of ssod without a trailing slash; plain http only for loopback hosts
 * @param provider provider id registered in the gateway ({@code okta} by default)
 * @param expectedIdpHost when non-null, the login redirect must go to this host or a subdomain
 * @param timeout bound for every HTTP request
 */
public record Config(URI gatewayUrl, String provider, String expectedIdpHost, Duration timeout) {

    /** Gateway URL used when {@code SSO_GATEWAY_URL} is not set. */
    public static final String DEFAULT_GATEWAY_URL = "http://localhost:8080";

    private static final Pattern PROVIDER = Pattern.compile("^[a-z0-9_-]{1,64}$");
    private static final Set<String> LOOPBACK = Set.of("localhost", "127.0.0.1", "[::1]", "::1");

    /**
     * Builds a Config from {@code getenv} (testable without the real environment).
     *
     * @throws ConfigException when a value is invalid
     */
    public static Config fromLookup(Function<String, String> getenv, String defaultProvider) throws ConfigException {
        String raw = orDefault(getenv.apply("SSO_GATEWAY_URL"), DEFAULT_GATEWAY_URL);
        URI uri;
        try {
            uri = new URI(raw);
        } catch (java.net.URISyntaxException e) {
            throw new ConfigException("SSO_GATEWAY_URL must be an http(s) URL with a host");
        }
        String scheme = uri.getScheme();
        if (uri.getHost() == null || scheme == null || !(scheme.equals("http") || scheme.equals("https"))) {
            throw new ConfigException("SSO_GATEWAY_URL must be an http(s) URL with a host");
        }
        if (scheme.equals("http") && !LOOPBACK.contains(uri.getHost())) {
            throw new ConfigException("SSO_GATEWAY_URL uses plain http for a non-loopback host: use https");
        }
        String path = uri.getRawPath() == null ? "" : uri.getRawPath().replaceAll("/+$", "");
        URI base = URI.create(scheme + "://" + uri.getRawAuthority() + path);

        String provider = orDefault(getenv.apply("SSO_PROVIDER"), defaultProvider);
        if (!PROVIDER.matcher(provider).matches()) {
            throw new ConfigException("SSO_PROVIDER '" + provider + "' must match [a-z0-9_-]{1,64}");
        }

        long seconds = 10;
        String t = trimToNull(getenv.apply("SSO_HTTP_TIMEOUT_SECONDS"));
        if (t != null) {
            try {
                seconds = Long.parseLong(t);
            } catch (NumberFormatException e) {
                seconds = -1;
            }
            if (seconds < 1 || seconds > 300) {
                throw new ConfigException("SSO_HTTP_TIMEOUT_SECONDS must be an integer from 1 to 300");
            }
        }
        String host = trimToNull(getenv.apply("SSO_EXPECTED_IDP_HOST"));
        return new Config(base, provider, host == null ? null : host.toLowerCase(Locale.ROOT), Duration.ofSeconds(seconds));
    }

    /** Absolute URL for a gateway path such as {@code /healthz}. */
    public String endpoint(String path) {
        return gatewayUrl.toString() + path;
    }

    private static String trimToNull(String s) {
        if (s == null) {
            return null;
        }
        String t = s.strip();
        return t.isEmpty() ? null : t;
    }

    private static String orDefault(String s, String def) {
        String t = trimToNull(s);
        return t == null ? def : t;
    }
}
