using System.Text;
using System.Text.Json;

namespace UniversalSso.Client;

/// <summary>Normalized user profile returned by the gateway callback.</summary>
public sealed record User(string Id, string Email, bool EmailVerified, string DisplayName, IReadOnlyList<string> Roles);

/// <summary>Body of a successful callback.</summary>
public sealed record Profile(string ProviderId, User User);

/// <summary>A started sign-in: where the browser must go, and the state the gateway issued.</summary>
public sealed record Login(Uri AuthorizeUrl, string State);

/// <summary>
/// HTTP client for the Universal SSO gateway. Contract (see <c>cmd/ssod/handler.go</c>):
/// <c>GET /healthz</c> returns 200 <c>{"status":"ok"}</c>; <c>GET /providers</c> returns 200
/// <c>{"providers":[...]}</c>; <c>GET /auth/{provider}/login</c> returns 302 to the IdP;
/// <c>GET /auth/{provider}/callback</c> returns 200 <c>{"provider_id","user"}</c>; errors are
/// <c>{"code","message"}</c>. Redirects are never followed automatically so every hop can be checked.
/// Instances are thread-safe.
/// </summary>
public sealed class GatewayClient : IDisposable
{
    private const int MaxBody = 1 << 20;
    private const int MaxHops = 5;

    private readonly HttpClient _http;

    /// <summary>Creates a client for <paramref name="config"/>.</summary>
    public GatewayClient(Config config) : this(config, new HttpClientHandler { AllowAutoRedirect = false }) { }

    /// <summary>Creates a client with a custom handler (used by tests).</summary>
    internal GatewayClient(Config config, HttpMessageHandler handler)
    {
        Config = config;
        _http = new HttpClient(handler, disposeHandler: true) { Timeout = config.Timeout };
        _http.DefaultRequestHeaders.Accept.ParseAdd("application/json");
    }

    /// <summary>The configuration in use.</summary>
    public Config Config { get; }

    /// <inheritdoc />
    public void Dispose() => _http.Dispose();

    private sealed record Reply(int Status, Uri? Location, byte[] Body);

    private async Task<Reply> GetAsync(Uri uri, CancellationToken ct)
    {
        try
        {
            using var resp = await _http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            await using var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            using var buf = new MemoryStream();
            var chunk = new byte[8192];
            int n;
            while (buf.Length < MaxBody && (n = await stream.ReadAsync(chunk, ct).ConfigureAwait(false)) > 0)
            {
                buf.Write(chunk, 0, Math.Min(n, MaxBody - (int)buf.Length));
            }
            return new Reply((int)resp.StatusCode, resp.Headers.Location, buf.ToArray());
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or IOException)
        {
            throw new TransportException($"request failed: {e.Message}", e);
        }
    }

    private static ApiException ApiError(Reply r)
    {
        try
        {
            using var doc = JsonDocument.Parse(r.Body);
            if (doc.RootElement.ValueKind == JsonValueKind.Object
                && doc.RootElement.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.String)
            {
                var msg = doc.RootElement.TryGetProperty("message", out var m) ? m.GetString() ?? "" : "";
                return new ApiException(r.Status, code.GetString()!, msg);
            }
        }
        catch (JsonException)
        {
            // fall through to the raw body
        }
        var text = Encoding.UTF8.GetString(r.Body).Trim();
        return new ApiException(r.Status, "UNKNOWN", text.Length > 200 ? text[..200] : text);
    }

    /// <summary>Completes normally when the gateway reports <c>{"status":"ok"}</c>.</summary>
    public async Task HealthAsync(CancellationToken ct = default)
    {
        var r = await GetAsync(new Uri(Config.Endpoint("/healthz")), ct).ConfigureAwait(false);
        var ok = false;
        try
        {
            using var doc = JsonDocument.Parse(r.Body);
            ok = r.Status == 200 && doc.RootElement.TryGetProperty("status", out var s) && s.GetString() == "ok";
        }
        catch (JsonException)
        {
            // treated as unhealthy
        }
        if (!ok)
        {
            throw new TransportException($"gateway not healthy: HTTP {r.Status}");
        }
    }

    /// <summary>Lists the provider ids registered in the gateway.</summary>
    public async Task<IReadOnlyList<string>> ProvidersAsync(CancellationToken ct = default)
    {
        var r = await GetAsync(new Uri(Config.Endpoint("/providers")), ct).ConfigureAwait(false);
        if (r.Status != 200)
        {
            throw ApiError(r);
        }
        try
        {
            using var doc = JsonDocument.Parse(r.Body);
            return doc.RootElement.GetProperty("providers").EnumerateArray().Select(e => e.GetString() ?? "").ToList();
        }
        catch (Exception e) when (e is JsonException or KeyNotFoundException or InvalidOperationException)
        {
            throw new TransportException($"decode providers: {e.Message}", e);
        }
    }

    /// <summary>Asks the gateway to begin a sign-in and validates the redirect.</summary>
    /// <exception cref="ApiException">The gateway refused (for example <c>PROVIDER_NOT_FOUND</c>).</exception>
    /// <exception cref="PolicyException">The redirect failed the safety policy.</exception>
    public async Task<Login> StartLoginAsync(CancellationToken ct = default)
    {
        var path = "/auth/" + Uri.EscapeDataString(Config.Provider) + "/login";
        var r = await GetAsync(new Uri(Config.Endpoint(path)), ct).ConfigureAwait(false);
        if (r.Status is not (302 or 303))
        {
            throw ApiError(r);
        }
        if (r.Location is null)
        {
            throw new TransportException("gateway redirect has no Location header");
        }
        var target = r.Location.IsAbsoluteUri ? r.Location : new Uri(Config.GatewayUrl, r.Location);
        var state = Policy.CheckAuthorizeUrl(target, Config.GatewayUrl, Config.ExpectedIdpHost);
        return new Login(target, state);
    }

    private bool SameHost(Uri u) => u.Authority == Config.GatewayUrl.Authority;

    /// <summary>
    /// Completes a sign-in without a browser while every redirect stays on the gateway host. That holds
    /// for the mock provider, which is why it is used for tests and demos. A real identity provider
    /// needs a person at a browser.
    /// </summary>
    /// <exception cref="LeavesGatewayException">A redirect points at another host.</exception>
    public async Task<Profile> FollowLocalAsync(Login login, CancellationToken ct = default)
    {
        var next = login.AuthorizeUrl;
        if (!SameHost(next))
        {
            throw new LeavesGatewayException();
        }
        for (var hop = 0; hop < MaxHops; hop++)
        {
            var r = await GetAsync(next, ct).ConfigureAwait(false);
            if (r.Status == 200)
            {
                return ParseProfile(r.Body);
            }
            if (r.Status != 302 || r.Location is null)
            {
                throw ApiError(r);
            }
            next = r.Location.IsAbsoluteUri ? r.Location : new Uri(next, r.Location);
            if (!SameHost(next))
            {
                throw new LeavesGatewayException();
            }
        }
        throw new TransportException("too many redirects");
    }

    private static Profile ParseProfile(byte[] body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            var u = doc.RootElement.GetProperty("user");
            var id = u.GetProperty("id").GetString();
            if (string.IsNullOrEmpty(id))
            {
                throw new TransportException("callback response is not a profile");
            }
            string Str(string name) => u.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString()! : "";
            var roles = u.TryGetProperty("roles", out var r) && r.ValueKind == JsonValueKind.Array
                ? r.EnumerateArray().Select(e => e.GetString() ?? "").ToList()
                : [];
            var verified = u.TryGetProperty("email_verified", out var ev) && ev.ValueKind == JsonValueKind.True;
            return new Profile(doc.RootElement.GetProperty("provider_id").GetString() ?? "", new User(id, Str("email"), verified, Str("display_name"), roles));
        }
        catch (Exception e) when (e is JsonException or KeyNotFoundException or InvalidOperationException)
        {
            throw new TransportException("callback response is not a profile", e);
        }
    }
}
