namespace UniversalSso.Client.Tests;

public class PolicyTests
{
    private static readonly Uri Gw = new("http://localhost:8080");
    private const string Pkce = "state=a&code_challenge=x&code_challenge_method=S256";

    [Fact]
    public void AcceptsGoodRedirects()
    {
        var ok = new Uri("https://login.example.test/authorize?state=abc&code_challenge=x&code_challenge_method=S256");
        Assert.Equal("abc", Policy.CheckAuthorizeUrl(ok, Gw, "example.test"));
        Assert.Equal("a", Policy.CheckAuthorizeUrl(new Uri($"http://localhost:8080/mock/authorize?{Pkce}"), Gw, null));
    }

    [Theory]
    [InlineData("ftp://login.example.test/a?state=a&code_challenge=x&code_challenge_method=S256")]
    [InlineData("http://login.example.test/a?state=a&code_challenge=x&code_challenge_method=S256")]
    [InlineData("https://evil.test/a?state=a&code_challenge=x&code_challenge_method=S256")]
    [InlineData("https://notexample.test/a?state=a&code_challenge=x&code_challenge_method=S256")]
    [InlineData("https://login.example.test/a?code_challenge=x&code_challenge_method=S256")]
    [InlineData("https://login.example.test/a?state=a")]
    [InlineData("https://login.example.test/a?state=a&code_challenge=x&code_challenge_method=plain")]
    public void RefusesUnsafeRedirects(string url) =>
        Assert.Throws<PolicyException>(() => Policy.CheckAuthorizeUrl(new Uri(url), Gw, "example.test"));
}
