namespace UniversalSso.Client.Tests;

public class GatewayClientTests
{
    [Fact]
    public async Task HealthAndProviders()
    {
        using var c = FakeGateway.Client("mock");
        await c.HealthAsync();
        Assert.Equal(["mock", "azure"], await c.ProvidersAsync());
    }

    [Fact]
    public async Task MockFlowCompletesWithoutBrowser()
    {
        using var c = FakeGateway.Client("mock");
        var login = await c.StartLoginAsync();
        Assert.Equal("s1", login.State);
        var p = await c.FollowLocalAsync(login);
        Assert.Equal("mock", p.ProviderId);
        Assert.Equal("a@b.test", p.User.Email);
    }

    [Fact]
    public async Task ExternalIdpNeedsABrowser()
    {
        using var c = FakeGateway.Client("azure");
        var login = await c.StartLoginAsync();
        Assert.Equal("s2", login.State);
        await Assert.ThrowsAsync<LeavesGatewayException>(() => c.FollowLocalAsync(login));
    }

    [Fact]
    public async Task MissingProviderIsStructuredError()
    {
        using var c = FakeGateway.Client("missing");
        var e = await Assert.ThrowsAsync<ApiException>(() => c.StartLoginAsync());
        Assert.Equal(404, e.Status);
        Assert.Equal("PROVIDER_NOT_FOUND", e.Code);
    }

    [Fact]
    public async Task RedirectWithoutPkceIsRefused()
    {
        using var c = FakeGateway.Client("weak");
        await Assert.ThrowsAsync<PolicyException>(() => c.StartLoginAsync());
    }

    [Fact]
    public async Task NonJsonErrorBody()
    {
        using var c = FakeGateway.Client("other");
        var e = await Assert.ThrowsAsync<ApiException>(() => c.StartLoginAsync());
        Assert.Equal("UNKNOWN", e.Code);
        Assert.Equal("boom", e.Message[(e.Message.LastIndexOf(' ') + 1)..]);
    }

    [Fact]
    public async Task TransportFailureIsWrapped()
    {
        using var c = FakeGateway.Client("down");
        await Assert.ThrowsAsync<TransportException>(() => c.StartLoginAsync());
    }

    [Fact]
    public async Task UnreachableGateway()
    {
        using var c = new GatewayClient(Config.FromLookup(k => k == "SSO_GATEWAY_URL" ? "http://127.0.0.1:1" : null, "azure"));
        await Assert.ThrowsAsync<TransportException>(() => c.HealthAsync());
    }
}
