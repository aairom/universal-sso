package auth0

import (
	"context"
	"net/url"
	"testing"

	"github.com/universal-sso/universal-sso/pkg/sso"
	"github.com/universal-sso/universal-sso/pkg/sso/oidc/oidctest"
)

const (
	client   = "auth0-test-client"
	redirect = "http://localhost:8080/auth/auth0/callback"
	verifier = "v-0123456789012345678901234567890123456789012"
	nonce    = "n-1"
)

func TestAuth0Flow(t *testing.T) {
	f := oidctest.New(t)
	// Auth0 issues tokens whose iss ends in a slash even if the configured URL has none.
	p, err := New(Config{
		ClientID: client, ClientSecret: "test-value", RedirectURL: redirect, // nosecret: fixture
		IssuerURL: f.URL(), Audience: "https://api.example.test", RolesClaim: "https://example.test/roles",
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.ID() != "auth0" || p.Name() != "Auth0" {
		t.Fatalf("identity: %s %s", p.ID(), p.Name())
	}
	ctx := context.Background()
	f.DiscoveryIssuer(f.URL() + "/")

	a, err := p.GetAuthURL(ctx, sso.AuthURLRequest{State: "s", Nonce: nonce, CodeVerifier: verifier, ExtraParams: map[string]string{"audience": "evil"}})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(a.URL)
	if got := u.Query().Get("audience"); got != "evil" {
		// Request-level extras win over config defaults for non-security parameters.
		t.Errorf("audience = %q", got)
	}
	a2, _ := p.GetAuthURL(ctx, sso.AuthURLRequest{State: "s", Nonce: nonce, CodeVerifier: verifier})
	if u2, _ := url.Parse(a2.URL); u2.Query().Get("audience") != "https://api.example.test" {
		t.Errorf("default audience missing: %s", a2.URL)
	}

	c := oidctest.GoodClaims(f.URL()+"/", client, nonce)
	c["nickname"] = "ab"
	c["https://example.test/roles"] = []string{"admin"}
	c["org_id"] = "org_1"
	f.SetClaims(c)
	res, err := p.HandleCallback(ctx, sso.CallbackRequest{Code: "c", CodeVerifier: verifier, Nonce: nonce})
	if err != nil {
		t.Fatal(err)
	}
	if res.User.Username != "ab" || len(res.User.Roles) != 1 || res.User.Roles[0] != "admin" || res.User.TenantID != "org_1" {
		t.Errorf("user = %+v", res.User)
	}
}

func TestAuth0IssuerWithoutSlashIsRejected(t *testing.T) {
	f := oidctest.New(t)
	p, _ := New(Config{ClientID: client, ClientSecret: "test-value", RedirectURL: redirect, IssuerURL: f.URL()}) // nosecret
	f.DiscoveryIssuer(f.URL() + "/")
	// The tenant always signs iss with a trailing slash. A slashless iss is a different issuer.
	tok := f.Sign(oidctest.GoodClaims(f.URL(), client, nonce))
	if _, err := p.ValidateToken(context.Background(), tok); err == nil {
		t.Error("slashless issuer accepted")
	}
}

func TestAuth0Logout(t *testing.T) {
	f := oidctest.New(t)
	p, _ := New(Config{ClientID: client, ClientSecret: "test-value", RedirectURL: redirect, IssuerURL: f.URL() + "/"}) // nosecret
	ctx := context.Background()
	r, err := p.GetLogoutURL(ctx, sso.LogoutRequest{PostLogoutURL: "https://app.example.test/bye"})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(r.URL)
	if u.Path != "/v2/logout" || u.Query().Get("client_id") != client || u.Query().Get("returnTo") != "https://app.example.test/bye" {
		t.Errorf("logout = %s", r.URL)
	}
	r, _ = p.GetLogoutURL(ctx, sso.LogoutRequest{})
	if u, _ := url.Parse(r.URL); u.Query().Has("returnTo") {
		t.Errorf("returnTo set without post logout url: %s", r.URL)
	}
	if _, err := p.GetLogoutURL(ctx, sso.LogoutRequest{PostLogoutURL: "javascript:x"}); err == nil {
		t.Error("bad returnTo accepted")
	}
}

func TestAuth0Config(t *testing.T) {
	if _, err := New(Config{ClientID: client, ClientSecret: "s", RedirectURL: redirect}); err == nil { // nosecret
		t.Error("missing issuer accepted")
	}
	p, err := sso.NewProvider(DriverName, map[string]string{
		"client_id": client, "client_secret": "test-value", "redirect_url": redirect, // nosecret
		"issuer_url": "https://tenant.example.test", "audience": "a", "roles_claim": "r",
	})
	if err != nil || p.ID() != "auth0" {
		t.Fatalf("driver: %v %v", p, err)
	}
	if _, err := sso.NewProvider(DriverName, map[string]string{}); err == nil {
		t.Error("empty driver config accepted")
	}
}
