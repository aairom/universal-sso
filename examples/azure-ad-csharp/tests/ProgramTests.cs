namespace UniversalSso.Client.Tests;

public class ProgramTests
{
    private static async Task<(int Code, string Out, string Err)> Call(Func<string, string?> env, params string[] args)
    {
        var o = new StringWriter();
        var e = new StringWriter();
        var code = await Program.RunAsync(args, env, o, e);
        return (code, o.ToString(), e.ToString());
    }

    [Fact]
    public async Task UsageAndBadInput()
    {
        var none = new Func<string, string?>(_ => null);
        Assert.Equal(2, (await Call(none)).Code);
        Assert.Equal(2, (await Call(none, "bogus")).Code);
        Assert.Equal(2, (await Call(none, "login", "--nope")).Code);
        Assert.Equal(2, (await Call(FakeGateway.Env("azure", "ftp://x"), "check")).Code);
    }

    [Fact]
    public async Task CheckUnreachableGatewayExits1()
    {
        var r = await Call(FakeGateway.Env("azure", "http://127.0.0.1:1"), "check");
        Assert.Equal(1, r.Code);
        Assert.Contains("gateway check failed", r.Err);
    }
}
