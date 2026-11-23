package okta

import (
	"context"
	"net/url"
	"testing"

	"github.com/universal-sso/universal-sso/pkg/sso"
	"github.com/universal-sso/universal-sso/pkg/sso/oidc/oidctest"
)

const (
	client   = "0oa-test-client"
	redirect = "http://localhost:8080/auth/okta/callback"
	verifier = "v-0123456789012345678901234567890123456789012"
	nonce    = "n-1"
)

func TestOktaFlow(t *testing.T) {
	f := oidctest.New(t)
	iss := f.URL() + "/oauth2/default"                                                                         // custom authorization server issuer has a path
	p, err := New(Config{ClientID: client, ClientSecret: "test-value", RedirectURL: redirect, IssuerURL: iss}) // nosecret: fixture
	if err != nil {
		t.Fatal(err)
	}
	if p.ID() != "okta" || p.Name() != "Okta" || p.Protocol() != sso.ProtocolOIDC {
		t.Fatalf("identity: %s %s %s", p.ID(), p.Name(), p.Protocol())
	}
	ctx := context.Background()

	a, err := p.GetAuthURL(ctx, sso.AuthURLRequest{State: "s", Nonce: nonce, CodeVerifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(a.URL)
	if u.Path != "/oauth2/default/authorize" || u.Query().Get("code_challenge_method") != "S256" {
		t.Errorf("auth url = %s", a.URL)
	}

	c := oidctest.GoodClaims(iss, client, nonce)
	c["preferred_username"] = "ab@example.test"
	c["groups"] = []string{"Everyone", "Admins"}
	f.SetClaims(c)
	res, err := p.HandleCallback(ctx, sso.CallbackRequest{Code: "c", CodeVerifier: verifier, Nonce: nonce})
	if err != nil {
		t.Fatal(err)
	}
	if res.ProviderID != "okta" || res.User.Username != "ab@example.test" || len(res.User.Groups) != 2 || res.User.Groups[1] != "Admins" || res.User.TenantID != iss {
		t.Errorf("user = %+v", res.User)
	}
	cl, err := p.ValidateToken(ctx, res.Tokens.IDToken)
	if err != nil || len(cl.Groups) != 2 {
		t.Errorf("claims = %+v err=%v", cl, err)
	}
	if _, err := p.GetLogoutURL(ctx, sso.LogoutRequest{IDTokenHint: res.Tokens.IDToken}); err != nil {
		t.Errorf("logout: %v", err)
	}
	if err := p.RevokeToken(ctx, "rt-1"); err != nil {
		t.Errorf("revoke: %v", err)
	}
}

func TestOktaRejectsForeignIssuer(t *testing.T) {
	f := oidctest.New(t)
	iss := f.URL() + "/oauth2/default"
	p, _ := New(Config{ClientID: client, ClientSecret: "test-value", RedirectURL: redirect, IssuerURL: iss}) // nosecret
	// A token from another Okta org must not validate here.
	tok := f.Sign(oidctest.GoodClaims("https://other.okta.example.test/oauth2/default", client, nonce))
	if _, err := p.ValidateToken(context.Background(), tok); err == nil {
		t.Error("foreign issuer accepted")
	}
}

func TestOktaConfig(t *testing.T) {
	if _, err := New(Config{ClientID: client, ClientSecret: "s", RedirectURL: redirect}); err == nil { // nosecret
		t.Error("missing issuer accepted")
	}
	if _, err := New(Config{ID: "okta-eu", ClientID: client, ClientSecret: "s", RedirectURL: redirect, IssuerURL: "http://org.example.test"}); err == nil { // nosecret
		t.Error("http issuer accepted")
	}
}

func TestOktaDriverRegistered(t *testing.T) {
	p, err := sso.NewProvider(DriverName, map[string]string{
		"client_id": client, "client_secret": "test-value", "redirect_url": redirect, // nosecret
		"issuer_url": "https://org.example.test/oauth2/default", "scopes": "openid groups",
	})
	if err != nil || p.ID() != "okta" {
		t.Fatalf("driver: %v %v", p, err)
	}
}
