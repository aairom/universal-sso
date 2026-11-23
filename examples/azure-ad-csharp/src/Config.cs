using System.Text.RegularExpressions;

namespace UniversalSso.Client;

/// <summary>
/// Settings for talking to the Universal SSO gateway (<c>ssod</c>), read from the environment.
/// </summary>
/// <param name="GatewayUrl">Base URL of ssod without a trailing slash; plain http only for loopback hosts.</param>
/// <param name="Provider">Provider id registered in the gateway (<c>azure</c> by default).</param>
/// <param name="ExpectedIdpHost">When set, the login redirect must go to this host or a subdomain.</param>
/// <param name="Timeout">Bound for every HTTP request.</param>
public sealed partial record Config(Uri GatewayUrl, string Provider, string? ExpectedIdpHost, TimeSpan Timeout)
{
    /// <summary>Gateway URL used when <c>SSO_GATEWAY_URL</c> is not set.</summary>
    public const string DefaultGatewayUrl = "http://localhost:8080";

    [GeneratedRegex("^[a-z0-9_-]{1,64}$")]
    private static partial Regex ProviderPattern();

    /// <summary>Builds a Config from <paramref name="getenv"/> (testable without the real environment).</summary>
    /// <exception cref="ConfigException">A value is invalid.</exception>
    public static Config FromLookup(Func<string, string?> getenv, string defaultProvider)
    {
        string? Get(string key) => string.IsNullOrWhiteSpace(getenv(key)) ? null : getenv(key)!.Trim();

        var raw = Get("SSO_GATEWAY_URL") ?? DefaultGatewayUrl;
        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
            || string.IsNullOrEmpty(uri.Host))
        {
            throw new ConfigException("SSO_GATEWAY_URL must be an http(s) URL with a host");
        }
        if (uri.Scheme == Uri.UriSchemeHttp && !uri.IsLoopback)
        {
            throw new ConfigException("SSO_GATEWAY_URL uses plain http for a non-loopback host: use https");
        }
        var baseUrl = new Uri(uri.GetLeftPart(UriPartial.Authority) + uri.AbsolutePath.TrimEnd('/'));

        var provider = Get("SSO_PROVIDER") ?? defaultProvider;
        if (!ProviderPattern().IsMatch(provider))
        {
            throw new ConfigException($"SSO_PROVIDER '{provider}' must match [a-z0-9_-]{{1,64}}");
        }

        var seconds = 10;
        var t = Get("SSO_HTTP_TIMEOUT_SECONDS");
        if (t is not null && (!int.TryParse(t, out seconds) || seconds is < 1 or > 300))
        {
            throw new ConfigException("SSO_HTTP_TIMEOUT_SECONDS must be an integer from 1 to 300");
        }

        return new Config(baseUrl, provider, Get("SSO_EXPECTED_IDP_HOST")?.ToLowerInvariant(), TimeSpan.FromSeconds(seconds));
    }

    /// <summary>Absolute URL for a gateway path such as <c>/healthz</c>.</summary>
    public string Endpoint(string path) => GatewayUrl.ToString().TrimEnd('/') + path;
}
