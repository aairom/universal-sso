namespace UniversalSso.Client.Tests;

public class ConfigTests
{
    private static Config Of(Dictionary<string, string> env) => Config.FromLookup(k => env.GetValueOrDefault(k), "azure");

    [Fact]
    public void Defaults()
    {
        var c = Of([]);
        Assert.Equal("http://localhost:8080/", c.GatewayUrl.ToString());
        Assert.Equal("azure", c.Provider);
        Assert.Equal(TimeSpan.FromSeconds(10), c.Timeout);
        Assert.Null(c.ExpectedIdpHost);
        Assert.Equal("http://localhost:8080/healthz", c.Endpoint("/healthz"));
    }

    [Theory]
    [InlineData("SSO_GATEWAY_URL", "ftp://x")]
    [InlineData("SSO_GATEWAY_URL", "http://gateway.example.test")]
    [InlineData("SSO_GATEWAY_URL", "not a url")]
    [InlineData("SSO_PROVIDER", "Bad Provider")]
    [InlineData("SSO_HTTP_TIMEOUT_SECONDS", "0")]
    [InlineData("SSO_HTTP_TIMEOUT_SECONDS", "abc")]
    [InlineData("SSO_HTTP_TIMEOUT_SECONDS", "301")]
    public void RejectsInvalidValues(string key, string value) =>
        Assert.Throws<ConfigException>(() => Of(new() { [key] = value }));

    [Fact]
    public void NormalizesValues()
    {
        var c = Of(new() { ["SSO_GATEWAY_URL"] = "https://sso.example.test/base/", ["SSO_EXPECTED_IDP_HOST"] = " IdP.Example.Test " });
        Assert.Equal("https://sso.example.test/base", c.GatewayUrl.ToString());
        Assert.Equal("idp.example.test", c.ExpectedIdpHost);
        Assert.Equal("https://sso.example.test/base/healthz", c.Endpoint("/healthz"));
    }
}
