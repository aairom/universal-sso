using System.Web;

namespace UniversalSso.Client;

/// <summary>
/// Client-side safety policy for the authorization redirect.
/// The gateway owns the signed state, the PKCE verifier and the client secret. This class only checks
/// that the redirect about to be handed to a browser is sane for an OAuth 2.0 / OIDC authorization-code
/// flow (Microsoft Entra ID uses one).
/// </summary>
public static class Policy
{
    /// <summary>
    /// Verifies <paramref name="redirect"/> and returns the <c>state</c> value it carries.
    /// Rules: the scheme is http or https, and https is required unless the redirect stays on the
    /// gateway's own host (the mock provider); when <paramref name="expectedHost"/> is set the host equals
    /// it or is a subdomain; <c>state</c> is present; PKCE is used with <c>code_challenge_method=S256</c>.
    /// </summary>
    /// <exception cref="PolicyException">A rule is violated.</exception>
    public static string CheckAuthorizeUrl(Uri redirect, Uri gateway, string? expectedHost)
    {
        if (redirect.Scheme != Uri.UriSchemeHttp && redirect.Scheme != Uri.UriSchemeHttps)
        {
            throw new PolicyException($"scheme '{redirect.Scheme}' is not http or https");
        }
        var sameHost = redirect.Authority == gateway.Authority;
        if (!sameHost && redirect.Scheme != Uri.UriSchemeHttps)
        {
            throw new PolicyException("external identity provider must use https");
        }
        if (expectedHost is not null)
        {
            var host = redirect.Host.ToLowerInvariant();
            if (host != expectedHost && !host.EndsWith("." + expectedHost, StringComparison.Ordinal))
            {
                throw new PolicyException($"host '{host}' is not '{expectedHost}' or a subdomain");
            }
        }
        var q = HttpUtility.ParseQueryString(redirect.Query);
        var state = q["state"];
        if (string.IsNullOrEmpty(state))
        {
            throw new PolicyException("redirect has no state parameter");
        }
        if (string.IsNullOrEmpty(q["code_challenge"]) || q["code_challenge_method"] != "S256")
        {
            throw new PolicyException("redirect does not use PKCE with S256");
        }
        return state;
    }
}
