using System.Net;
using System.Text;

namespace UniversalSso.Client.Tests;

/// <summary>In-memory fake that mimics the ssod contract, so tests need no sockets.</summary>
internal sealed class FakeGateway : HttpMessageHandler
{
    public const string Base = "http://127.0.0.1:8080";

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var path = request.RequestUri!.AbsolutePath;
        HttpResponseMessage Json(int status, string body) =>
            new((HttpStatusCode)status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        HttpResponseMessage Redirect(string to)
        {
            var r = new HttpResponseMessage(HttpStatusCode.Found);
            r.Headers.Location = new Uri(to, UriKind.RelativeOrAbsolute);
            return r;
        }
        var resp = path switch
        {
            "/healthz" => Json(200, """{"status":"ok"}"""),
            "/providers" => Json(200, """{"providers":["mock","azure"]}"""),
            "/auth/mock/login" => Redirect("/mock/authorize?state=s1&code_challenge=c&code_challenge_method=S256"),
            "/mock/authorize" => Redirect("/auth/mock/callback?code=mock-code&state=s1"),
            "/auth/mock/callback" => Json(200, """{"provider_id":"mock","user":{"id":"u1","email":"a@example.com","display_name":"Mock User"}}"""),
            "/auth/azure/login" => Redirect("https://login.example.test/authorize?state=s2&code_challenge=c&code_challenge_method=S256"),
            "/auth/missing/login" => Json(404, """{"code":"PROVIDER_NOT_FOUND","message":"missing"}"""),
            "/auth/weak/login" => Redirect("https://login.example.test/authorize?state=s3"),
            "/auth/down/login" => throw new HttpRequestException("connection refused"),
            _ => Json(500, "boom"),
        };
        return Task.FromResult(resp);
    }

    public static Func<string, string?> Env(string provider, string? baseUrl = null) =>
        k => k switch
        {
            "SSO_GATEWAY_URL" => baseUrl ?? Base,
            "SSO_PROVIDER" => provider,
            _ => null,
        };

    public static GatewayClient Client(string provider) =>
        new(Config.FromLookup(Env(provider), "azure"), new FakeGateway());
}
