// Command saml2-go is a small client for the Universal SSO gateway (ssod) that
// signs a user in through a SAML 2.0 provider registered in the gateway.
//
// Usage:
//
//	saml2-go check             verify the gateway is reachable and list providers
//	saml2-go login             start a sign-in and print the URL to open in a browser
//	saml2-go login -follow     complete the sign-in without a browser (mock provider only)
//
// Configuration comes from the environment (see .env.example).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/universal-sso/universal-sso/examples/saml2-go/internal/gateway"
)

// defaultProvider is the gateway provider id used when SSO_PROVIDER is unset.
const defaultProvider = "saml"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

// run executes one command and returns the process exit code.
func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: saml2-go check | login [-follow]")
		return 2
	}
	cfg, err := gateway.LoadConfig(getenv, defaultProvider)
	if err != nil {
		fmt.Fprintln(stderr, "configuration error:", err)
		return 2
	}
	level := slog.LevelWarn
	if strings.EqualFold(getenv("SSO_LOG_LEVEL"), "debug") {
		level = slog.LevelDebug
	} else if strings.EqualFold(getenv("SSO_LOG_LEVEL"), "info") {
		level = slog.LevelInfo
	}
	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))
	client := gateway.NewClient(cfg, log)

	switch args[0] {
	case "check":
		return cmdCheck(ctx, client, cfg, stdout, stderr)
	case "login":
		fs := flag.NewFlagSet("login", flag.ContinueOnError)
		fs.SetOutput(stderr)
		follow := fs.Bool("follow", false, "complete the sign-in without a browser (mock provider only)")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		return cmdLogin(ctx, client, *follow, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		return 2
	}
}

func cmdCheck(ctx context.Context, c *gateway.Client, cfg gateway.Config, stdout, stderr io.Writer) int {
	if err := c.Health(ctx); err != nil {
		fmt.Fprintln(stderr, "gateway check failed:", err)
		return 1
	}
	ids, err := c.Providers(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "listing providers failed:", err)
		return 1
	}
	fmt.Fprintf(stdout, "gateway ok, providers: %s\n", strings.Join(ids, ", "))
	for _, id := range ids {
		if id == cfg.Provider {
			return 0
		}
	}
	fmt.Fprintf(stderr, "provider %q is not registered in the gateway\n", cfg.Provider)
	return 1
}

func cmdLogin(ctx context.Context, c *gateway.Client, follow bool, stdout, stderr io.Writer) int {
	l, err := c.StartLogin(ctx)
	if err != nil {
		return reportLoginError(err, stderr)
	}
	if !follow {
		fmt.Fprintln(stdout, "Open this URL in a browser to sign in:")
		fmt.Fprintln(stdout, l.AuthorizeURL.String())
		fmt.Fprintln(stdout, "The identity provider returns the browser to the gateway callback, which completes the login.")
		return 0
	}
	p, err := c.FollowLocal(ctx, l)
	if err != nil {
		if errors.Is(err, gateway.ErrLeavesGateway) {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return reportLoginError(err, stderr)
	}
	fmt.Fprintf(stdout, "signed in via %s as %s (%s)\n", p.ProviderID, p.User.DisplayName, p.User.Email)
	return 0
}

func reportLoginError(err error, stderr io.Writer) int {
	var api *gateway.APIError
	switch {
	case errors.As(err, &api) && api.Code == "PROVIDER_NOT_FOUND":
		fmt.Fprintf(stderr, "the gateway has no such provider (%s). Its adapter may not be implemented yet: see Docs/Architecture.md\n", api.Message)
	case errors.Is(err, gateway.ErrPolicy):
		fmt.Fprintln(stderr, "refused to continue:", err)
	default:
		fmt.Fprintln(stderr, "login failed:", err)
	}
	return 1
}
