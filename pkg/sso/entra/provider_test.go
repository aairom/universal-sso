package entra

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/universal-sso/universal-sso/pkg/sso"
	"github.com/universal-sso/universal-sso/pkg/sso/oidc/oidctest"
)

const (
	client   = "entra-test-client"
	redirect = "http://localhost:8080/auth/azure/callback"
	verifier = "v-0123456789012345678901234567890123456789012"
	nonce    = "n-1"
	tenantA  = "11111111-1111-1111-1111-111111111111"
	tenantB  = "22222222-2222-2222-2222-222222222222"
)

func prov(t *testing.T, f *oidctest.Fake, tenant string, mut func(*Config)) sso.Provider {
	t.Helper()
	cfg := Config{ClientID: client, ClientSecret: "test-value", RedirectURL: redirect, TenantID: tenant, Authority: f.URL()} // nosecret: fixture
	if mut != nil {
		mut(&cfg)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func claims(f *oidctest.Fake, tid string) map[string]any {
	c := oidctest.GoodClaims(f.URL()+"/"+tid+"/v2.0", client, nonce)
	c["tid"] = tid
	c["oid"] = "oid-1"
	c["preferred_username"] = "ab@example.test"
	c["roles"] = []string{"Reader"}
	c["groups"] = []string{"grp-1"}
	return c
}

func TestSingleTenantFlow(t *testing.T) {
	f := oidctest.New(t)
	p := prov(t, f, tenantA, nil)
	if p.ID() != "entra" || p.Name() != "Entra" {
		t.Fatalf("identity %s %s", p.ID(), p.Name())
	}
	ctx := context.Background()
	a, err := p.GetAuthURL(ctx, sso.AuthURLRequest{State: "s", Nonce: nonce, CodeVerifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	if u, _ := url.Parse(a.URL); u.Path != "/"+tenantA+"/v2.0/authorize" {
		t.Errorf("auth url = %s", a.URL)
	}
	f.SetClaims(claims(f, tenantA))
	res, err := p.HandleCallback(ctx, sso.CallbackRequest{Code: "c", CodeVerifier: verifier, Nonce: nonce})
	if err != nil {
		t.Fatal(err)
	}
	u := res.User
	if u.Username != "ab@example.test" || u.TenantID != tenantA || len(u.Roles) != 1 || u.Roles[0] != "Reader" || len(u.Groups) != 1 {
		t.Errorf("user = %+v", u)
	}
	if u.EmailVerified {
		t.Error("Entra e-mail claims are unverified and must not be reported as verified")
	}
	cl, err := p.ValidateToken(ctx, res.Tokens.IDToken)
	if err != nil || cl.TenantID != tenantA || cl.Roles[0] != "Reader" {
		t.Errorf("claims = %+v err=%v", cl, err)
	}
}

func TestSingleTenantRejectsOtherTenantToken(t *testing.T) {
	f := oidctest.New(t)
	p := prov(t, f, tenantA, nil)
	tok := f.Sign(claims(f, tenantB))
	if _, err := p.ValidateToken(context.Background(), tok); err == nil {
		t.Error("token from another tenant accepted by a single-tenant app")
	}
}

func TestMultiTenant(t *testing.T) {
	for _, tenant := range []string{"common", "organizations", "consumers", "Common"} {
		f := oidctest.New(t)
		// Microsoft serves a templated issuer for the multi-tenant endpoints.
		f.DiscoveryIssuer(f.URL() + "/{tenantid}/v2.0")
		p := prov(t, f, tenant, nil)
		ctx := context.Background()
		if _, err := p.GetAuthURL(ctx, sso.AuthURLRequest{State: "s", Nonce: nonce, CodeVerifier: verifier}); err != nil {
			t.Fatalf("%s: %v", tenant, err)
		}
		if _, err := p.ValidateToken(ctx, f.Sign(claims(f, tenantA))); err != nil {
			t.Errorf("%s: tenant A: %v", tenant, err)
		}
		if _, err := p.ValidateToken(ctx, f.Sign(claims(f, tenantB))); err != nil {
			t.Errorf("%s: tenant B: %v", tenant, err)
		}
	}
}

func TestMultiTenantIssuerMustMatchOwnTid(t *testing.T) {
	f := oidctest.New(t)
	f.DiscoveryIssuer(f.URL() + "/{tenantid}/v2.0")
	p := prov(t, f, "organizations", nil)
	ctx := context.Background()

	// iss names tenant A but the token claims to belong to tenant B.
	c := claims(f, tenantA)
	c["tid"] = tenantB
	if _, err := p.ValidateToken(ctx, f.Sign(c)); err == nil {
		t.Error("iss/tid mismatch accepted")
	}
	// Missing or malformed tid.
	for _, tid := range []any{nil, "", "not-a-guid", 7} {
		c := claims(f, tenantA)
		if tid == nil {
			delete(c, "tid")
		} else {
			c["tid"] = tid
		}
		if _, err := p.ValidateToken(ctx, f.Sign(c)); err == nil {
			t.Errorf("tid %v accepted", tid)
		}
	}
	// Foreign host with a well-formed path.
	c = claims(f, tenantA)
	c["iss"] = "https://evil.example.test/" + tenantA + "/v2.0"
	if _, err := p.ValidateToken(ctx, f.Sign(c)); err == nil {
		t.Error("foreign issuer host accepted")
	}
}

func TestAllowedTenants(t *testing.T) {
	f := oidctest.New(t)
	f.DiscoveryIssuer(f.URL() + "/{tenantid}/v2.0")
	p := prov(t, f, "organizations", func(c *Config) { c.AllowedTenants = []string{strings.ToUpper(tenantA)} })
	ctx := context.Background()
	if _, err := p.ValidateToken(ctx, f.Sign(claims(f, tenantA))); err != nil {
		t.Errorf("allowed tenant rejected: %v", err)
	}
	if _, err := p.ValidateToken(ctx, f.Sign(claims(f, tenantB))); err == nil {
		t.Error("tenant outside the allow-list accepted")
	}
}

func TestMultiTenantRejectsNonTemplateDiscoveryIssuer(t *testing.T) {
	f := oidctest.New(t)
	f.DiscoveryIssuer("https://evil.example.test/{tenantid}/v2.0")
	p := prov(t, f, "common", nil)
	if _, err := p.GetAuthURL(context.Background(), sso.AuthURLRequest{State: "s", Nonce: nonce, CodeVerifier: verifier}); err == nil {
		t.Error("foreign discovery issuer accepted")
	}
}

func TestTenantDomainPinsToGUIDIssuer(t *testing.T) {
	f := oidctest.New(t)
	f.DiscoveryIssuer(f.URL() + "/" + tenantA + "/v2.0")
	p := prov(t, f, "contoso.onmicrosoft.com", nil)
	ctx := context.Background()
	if _, err := p.GetAuthURL(ctx, sso.AuthURLRequest{State: "s", Nonce: nonce, CodeVerifier: verifier}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.ValidateToken(ctx, f.Sign(claims(f, tenantA))); err != nil {
		t.Errorf("own tenant: %v", err)
	}
	if _, err := p.ValidateToken(ctx, f.Sign(claims(f, tenantB))); err == nil {
		t.Error("other tenant accepted for a domain-pinned app")
	}

	// A discovery document naming a non-GUID or foreign issuer is refused.
	for _, iss := range []string{f.URL() + "/contoso/v2.0", "https://evil.example.test/" + tenantA + "/v2.0", f.URL() + "/" + tenantA + "/v1.0"} {
		f2 := oidctest.New(t)
		f2.DiscoveryIssuer(iss)
		p2 := prov(t, f2, "contoso.onmicrosoft.com", nil)
		if _, err := p2.GetAuthURL(ctx, sso.AuthURLRequest{State: "s", Nonce: nonce, CodeVerifier: verifier}); err == nil {
			t.Errorf("discovery issuer %q accepted", iss)
		}
	}
}

func TestEntraConfigValidation(t *testing.T) {
	base := Config{ClientID: client, ClientSecret: "s", RedirectURL: redirect, TenantID: tenantA} // nosecret
	cases := map[string]func(*Config){
		"no tenant":          func(c *Config) { c.TenantID = "" },
		"blank tenant":       func(c *Config) { c.TenantID = "  " },
		"path in tenant":     func(c *Config) { c.TenantID = "a/../b" },
		"query in tenant":    func(c *Config) { c.TenantID = "a?x=1" },
		"bad allowed":        func(c *Config) { c.AllowedTenants = []string{"nope"} },
		"http authority":     func(c *Config) { c.Authority = "http://login.example.test" },
		"relative authority": func(c *Config) { c.Authority = "login.example.test" },
		"no secret":          func(c *Config) { c.ClientSecret = "" },
	}
	for name, mut := range cases {
		c := base
		mut(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := New(base); err != nil {
		t.Errorf("valid config: %v", err)
	}
	c := base
	c.Authority = "https://login.microsoftonline.us"
	if _, err := New(c); err != nil {
		t.Errorf("sovereign cloud: %v", err)
	}
}

func TestEntraDriver(t *testing.T) {
	p, err := sso.NewProvider(DriverName, map[string]string{
		"client_id": client, "client_secret": "test-value", "redirect_url": redirect, // nosecret
		"tenant_id": "common", "allowed_tenants": tenantA + "," + tenantB, "scopes": "openid profile",
		"authority": "https://login.microsoftonline.com/",
	})
	if err != nil || p.ID() != "entra" {
		t.Fatalf("driver: %v %v", p, err)
	}
	if _, err := sso.NewProvider(DriverName, map[string]string{"client_id": client}); err == nil {
		t.Error("incomplete driver config accepted")
	}
}
