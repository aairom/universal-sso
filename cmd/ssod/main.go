// Command ssod runs the Universal SSO gateway with the mock provider and,
// when configured, the Google, Okta, Auth0, Microsoft Entra (id "azure") and
// generic OAuth 2.0 (id "oauth2") providers.
//
// Configuration (environment, see .env.example):
//
//	SSO_SERVER_HOST                      bind address (default 127.0.0.1)
//	SSO_SERVER_PORT                      listen port (default 8080)
//	SSO_SERVER_BASE_URL                  public base URL, used for the default Google redirect URL
//	SSO_STATE_SECRET                     HMAC secret, at least 32 bytes (required);
//	                                     the example value from .env.example is refused
//	SSO_PROVIDERS_GOOGLE_CLIENT_ID       enables the Google provider when set
//	SSO_PROVIDERS_GOOGLE_CLIENT_SECRET   Google client secret
//	SSO_PROVIDERS_GOOGLE_REDIRECT_URL    optional, default <SSO_SERVER_BASE_URL>/auth/google/callback
//	SSO_PROVIDERS_GOOGLE_HOSTED_DOMAIN   optional, restrict sign-in to one Workspace domain
//	SSO_PROVIDERS_OKTA_*                 CLIENT_ID, CLIENT_SECRET, ISSUER_URL, REDIRECT_URL (optional)
//	SSO_PROVIDERS_AUTH0_*                CLIENT_ID, CLIENT_SECRET, ISSUER_URL, REDIRECT_URL (optional),
//	                                     AUDIENCE (optional), ROLES_CLAIM (optional)
//	SSO_PROVIDERS_AZURE_*                CLIENT_ID, CLIENT_SECRET, TENANT_ID, REDIRECT_URL (optional),
//	                                     ALLOWED_TENANTS (optional, multi-tenant), AUTHORITY (optional)
//	SSO_PROVIDERS_OAUTH2_*               CLIENT_ID, CLIENT_SECRET, AUTH_URL, TOKEN_URL, USERINFO_URL,
//	                                     REDIRECT_URL (optional), SCOPES (optional), USER_ID_FIELD (default id),
//	                                     AUTH_STYLE (basic default, or post), REVOKE_URL (optional)
//
// A vendor whose client id is empty or an unedited sample stays disabled.
//
// SIGINT/SIGTERM trigger a graceful shutdown.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/universal-sso/universal-sso/pkg/sso"
	"github.com/universal-sso/universal-sso/pkg/sso/google"
	"github.com/universal-sso/universal-sso/pkg/sso/mock"
)

const (
	stateTTL        = 10 * time.Minute
	shutdownTimeout = 10 * time.Second

	// exampleStatePrefix starts the public sample SSO_STATE_SECRET shipped in
	// .env.example. A secret with this prefix is a published HMAC key.
	exampleStatePrefix = "change-this"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// isPlaceholder reports whether v is empty or an unedited .env.example value.
func isPlaceholder(v string) bool {
	return v == "" || strings.HasSuffix(v, "-placeholder")
}

// googleFromEnv builds the Google provider. It returns (nil, nil) when Google
// is not configured, so a fresh copy of .env.example still starts the server.
func googleFromEnv(getenv func(string) string) (sso.Provider, error) {
	id, secret := getenv("SSO_PROVIDERS_GOOGLE_CLIENT_ID"), getenv("SSO_PROVIDERS_GOOGLE_CLIENT_SECRET") // nosecret: env var names
	if isPlaceholder(id) {
		return nil, nil
	}
	if strings.HasPrefix(id, "GOCSPX-") {
		return nil, fmt.Errorf("SSO_PROVIDERS_GOOGLE_CLIENT_ID holds a client secret (GOCSPX-...): put the real Client ID (...apps.googleusercontent.com) there and the secret on the CLIENT_SECRET line, then run make google-check") // nosecret
	}
	if isPlaceholder(secret) {
		return nil, fmt.Errorf("SSO_PROVIDERS_GOOGLE_CLIENT_SECRET is not set (client id is configured): run make google-check") // nosecret
	}
	redirect := getenv("SSO_PROVIDERS_GOOGLE_REDIRECT_URL")
	if redirect == "" {
		base := strings.TrimRight(getenv("SSO_SERVER_BASE_URL"), "/")
		if base == "" {
			return nil, fmt.Errorf("set SSO_PROVIDERS_GOOGLE_REDIRECT_URL or SSO_SERVER_BASE_URL")
		}
		redirect = base + "/auth/google/callback"
	}
	return google.New(google.Config{
		ClientID: id, ClientSecret: secret, RedirectURL: redirect,
		HostedDomain: getenv("SSO_PROVIDERS_GOOGLE_HOSTED_DOMAIN"),
	})
}

// build wires the Manager from the environment.
func build(getenv func(string) string) (*sso.Manager, error) {
	stateSecret := getenv("SSO_STATE_SECRET")
	if strings.HasPrefix(stateSecret, exampleStatePrefix) {
		return nil, errors.New("SSO_STATE_SECRET still holds the public example value from .env.example: generate your own with `openssl rand -base64 48`")
	}
	signer, err := sso.NewStateSigner([]byte(stateSecret), stateTTL)
	if err != nil {
		return nil, err
	}
	m := sso.NewManager(sso.NewMemoryCache(time.Minute), signer, stateTTL)
	mp := mock.New("mock")
	mp.SetAuthorizeURL("/mock/authorize") // served by ssod itself, see handler.go
	if err := m.Register(mp); err != nil {
		return nil, err
	}
	gp, err := googleFromEnv(getenv)
	if err != nil {
		return nil, fmt.Errorf("google provider: %w", err)
	}
	if gp != nil {
		if err := m.Register(gp); err != nil {
			return nil, err
		}
	}
	for _, v := range []struct {
		name string
		from func(func(string) string) (sso.Provider, error)
	}{{"okta", oktaFromEnv}, {"auth0", auth0FromEnv}, {"azure", azureFromEnv}, {"oauth2", oauth2FromEnv}, {"saml", samlFromEnv}} {
		vp, err := v.from(getenv)
		if err != nil {
			return nil, fmt.Errorf("%s provider: %w", v.name, err)
		}
		if vp != nil {
			if err := m.Register(vp); err != nil {
				return nil, err
			}
		}
	}
	return m, nil
}

func main() {
	m, err := build(os.Getenv)
	if err != nil {
		log.Fatalf("ssod: configuration error: %v", err)
	}

	handler, err := wrap(newHandler(m), os.Getenv)
	if err != nil {
		log.Fatalf("ssod: %v", err)
	}
	addr := net.JoinHostPort(envOr("SSO_SERVER_HOST", "127.0.0.1"), envOr("SSO_SERVER_PORT", "8080"))
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	log.Printf("ssod: listening on http://%s, providers: %s", addr, strings.Join(m.Providers(), ", "))

	select {
	case err := <-errCh:
		log.Fatalf("ssod: server error: %v", err)
	case <-ctx.Done():
		log.Printf("ssod: shutdown signal received, draining connections")
	}

	shutCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("ssod: shutdown failed: %v", err)
	}
	log.Printf("ssod: stopped cleanly")
}
