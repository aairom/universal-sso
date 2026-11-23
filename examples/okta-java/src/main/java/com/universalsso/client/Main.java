package com.universalsso.client;

import com.universalsso.client.SsoException.ApiException;
import com.universalsso.client.SsoException.ConfigException;
import com.universalsso.client.SsoException.LeavesGatewayException;
import com.universalsso.client.SsoException.PolicyException;
import java.io.PrintStream;
import java.util.List;
import java.util.function.Function;

/**
 * Command line for the gateway client.
 *
 * <pre>
 * check            gateway reachable and provider registered
 * login            print the URL to open in a browser
 * login --follow   finish the sign-in without a browser (mock provider only)
 * </pre>
 */
public final class Main {
    /** Gateway provider id used when {@code SSO_PROVIDER} is unset. */
    static final String DEFAULT_PROVIDER = "okta";

    private Main() {}

    public static void main(String[] args) {
        System.exit(run(args, System::getenv, System.out, System.err));
    }

    /** Runs one command and returns the process exit code. */
    static int run(String[] args, Function<String, String> getenv, PrintStream out, PrintStream err) {
        if (args.length == 0) {
            err.println("usage: check | login [--follow]");
            return 2;
        }
        Config cfg;
        try {
            cfg = Config.fromLookup(getenv, DEFAULT_PROVIDER);
        } catch (ConfigException e) {
            err.println("configuration error: " + e.getMessage());
            return 2;
        }
        GatewayClient client = new GatewayClient(cfg);
        switch (args[0]) {
            case "check":
                return check(client, out, err);
            case "login":
                boolean follow = false;
                for (int i = 1; i < args.length; i++) {
                    if (args[i].equals("--follow")) {
                        follow = true;
                    } else {
                        err.println("unknown option '" + args[i] + "'");
                        return 2;
                    }
                }
                return login(client, follow, out, err);
            default:
                err.println("unknown command '" + args[0] + "'");
                return 2;
        }
    }

    private static int check(GatewayClient client, PrintStream out, PrintStream err) {
        List<String> ids;
        try {
            client.health();
            ids = client.providers();
        } catch (SsoException e) {
            err.println("gateway check failed: " + e.getMessage());
            return 1;
        }
        out.println("gateway ok, providers: " + String.join(", ", ids));
        if (!ids.contains(client.config().provider())) {
            err.println("provider '" + client.config().provider() + "' is not registered in the gateway");
            return 1;
        }
        return 0;
    }

    private static int login(GatewayClient client, boolean follow, PrintStream out, PrintStream err) {
        try {
            GatewayClient.Login started = client.startLogin();
            if (!follow) {
                out.println("Open this URL in a browser to sign in:");
                out.println(started.authorizeUrl());
                out.println("The identity provider returns the browser to the gateway callback, which completes the login.");
                return 0;
            }
            GatewayClient.Profile p = client.followLocal(started);
            out.println("signed in via " + p.providerId() + " as " + p.user().displayName() + " (" + p.user().email() + ")");
            return 0;
        } catch (ApiException e) {
            if (e.code().equals("PROVIDER_NOT_FOUND")) {
                err.println("the gateway has no such provider. Its adapter may not be implemented yet: see Docs/Architecture.md");
            } else {
                err.println("login failed: " + e.getMessage());
            }
        } catch (PolicyException e) {
            err.println("refused to continue: " + e.getMessage());
        } catch (LeavesGatewayException e) {
            err.println(e.getMessage());
        } catch (SsoException e) {
            err.println("login failed: " + e.getMessage());
        }
        return 1;
    }
}
