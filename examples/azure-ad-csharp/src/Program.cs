namespace UniversalSso.Client;

/// <summary>
/// Command line for the gateway client:
/// <c>check</c> (gateway reachable and provider registered), <c>login</c> (print the URL to open in a
/// browser) and <c>login --follow</c> (finish the sign-in without a browser; mock provider only).
/// </summary>
public static class Program
{
    /// <summary>Gateway provider id used when <c>SSO_PROVIDER</c> is unset.</summary>
    public const string DefaultProvider = "azure";

    /// <summary>Process entry point.</summary>
    public static async Task<int> Main(string[] args)
    {
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };
        return await RunAsync(args, Environment.GetEnvironmentVariable, Console.Out, Console.Error, cts.Token).ConfigureAwait(false);
    }

    /// <summary>Runs one command and returns the process exit code.</summary>
    public static async Task<int> RunAsync(string[] args, Func<string, string?> getenv, TextWriter stdout, TextWriter stderr, CancellationToken ct = default)
    {
        if (args.Length == 0)
        {
            await stderr.WriteLineAsync("usage: check | login [--follow]");
            return 2;
        }
        Config cfg;
        try
        {
            cfg = Config.FromLookup(getenv, DefaultProvider);
        }
        catch (ConfigException e)
        {
            await stderr.WriteLineAsync($"configuration error: {e.Message}");
            return 2;
        }
        using var client = new GatewayClient(cfg);
        switch (args[0])
        {
            case "check":
                return await CheckAsync(client, stdout, stderr, ct);
            case "login":
                var follow = false;
                foreach (var a in args.Skip(1))
                {
                    if (a == "--follow")
                    {
                        follow = true;
                    }
                    else
                    {
                        await stderr.WriteLineAsync($"unknown option '{a}'");
                        return 2;
                    }
                }
                return await LoginAsync(client, follow, stdout, stderr, ct);
            default:
                await stderr.WriteLineAsync($"unknown command '{args[0]}'");
                return 2;
        }
    }

    private static async Task<int> CheckAsync(GatewayClient client, TextWriter stdout, TextWriter stderr, CancellationToken ct)
    {
        IReadOnlyList<string> ids;
        try
        {
            await client.HealthAsync(ct);
            ids = await client.ProvidersAsync(ct);
        }
        catch (SsoException e)
        {
            await stderr.WriteLineAsync($"gateway check failed: {e.Message}");
            return 1;
        }
        await stdout.WriteLineAsync($"gateway ok, providers: {string.Join(", ", ids)}");
        if (!ids.Contains(client.Config.Provider))
        {
            await stderr.WriteLineAsync($"provider '{client.Config.Provider}' is not registered in the gateway");
            return 1;
        }
        return 0;
    }

    private static async Task<int> LoginAsync(GatewayClient client, bool follow, TextWriter stdout, TextWriter stderr, CancellationToken ct)
    {
        try
        {
            var started = await client.StartLoginAsync(ct);
            if (!follow)
            {
                await stdout.WriteLineAsync("Open this URL in a browser to sign in:");
                await stdout.WriteLineAsync(started.AuthorizeUrl.ToString());
                await stdout.WriteLineAsync("The identity provider returns the browser to the gateway callback, which completes the login.");
                return 0;
            }
            var p = await client.FollowLocalAsync(started, ct);
            await stdout.WriteLineAsync($"signed in via {p.ProviderId} as {p.User.DisplayName} ({p.User.Email})");
            return 0;
        }
        catch (ApiException e) when (e.Code == "PROVIDER_NOT_FOUND")
        {
            await stderr.WriteLineAsync("the gateway has no such provider. Its adapter may not be implemented yet: see Docs/Architecture.md");
        }
        catch (PolicyException e)
        {
            await stderr.WriteLineAsync($"refused to continue: {e.Message}");
        }
        catch (LeavesGatewayException e)
        {
            await stderr.WriteLineAsync(e.Message);
        }
        catch (SsoException e)
        {
            await stderr.WriteLineAsync($"login failed: {e.Message}");
        }
        return 1;
    }
}
