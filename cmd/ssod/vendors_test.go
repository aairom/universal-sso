package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/universal-sso/universal-sso/pkg/sso/oidc/oidctest"
)

const (
	tenantGUID = "11111111-1111-1111-1111-111111111111"
	vendorSec  = "test-value" // nosecret: fixture
)

func vendorEnvMap(extra map[string]string) func(string) string {
	m := map[string]string{"SSO_STATE_SECRET": strings.Repeat("s", 32), "SSO_SERVER_BASE_URL": "http://localhost:8080"}
	for k, v := range extra {
		m[k] = v
	}
	return func(k string) string { return m[k] }
}

func TestVendorsDisabledByDefault(t *testing.T) {
	// Unedited samples, including the legacy Okta sample id, keep every vendor off.
	m, err := build(vendorEnvMap(map[string]string{
		"SSO_PROVIDERS_OKTA_CLIENT_ID":     "0oa123456789okta",
		"SSO_PROVIDERS_AUTH0_CLIENT_ID":    "auth0-client-id-placeholder",
		"SSO_PROVIDERS_AZURE_CLIENT_ID":    "azure-client-id-placeholder",
		"SSO_PROVIDERS_OKTA_ISSUER_URL":    "https://dev-example.okta.com/oauth2/default",
		"SSO_PROVIDERS_AZURE_TENANT_ID":    "common",
		"SSO_PROVIDERS_OKTA_CLIENT_SECRET": "okta-client-secret-placeholder",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(m.Providers(), ","); got != "mock" {
		t.Errorf("providers = %s", got)
	}
}

func TestVendorsRegisteredWhenConfigured(t *testing.T) {
	m, err := build(vendorEnvMap(map[string]string{
		"SSO_PROVIDERS_OKTA_CLIENT_ID": "okta-id", "SSO_PROVIDERS_OKTA_CLIENT_SECRET": vendorSec, "SSO_PROVIDERS_OKTA_ISSUER_URL": "https://org.example.test/oauth2/default",
		"SSO_PROVIDERS_AUTH0_CLIENT_ID": "auth0-id", "SSO_PROVIDERS_AUTH0_CLIENT_SECRET": vendorSec, "SSO_PROVIDERS_AUTH0_ISSUER_URL": "https://t.example.test",
		"SSO_PROVIDERS_AUTH0_AUDIENCE": "https://api.example.test", "SSO_PROVIDERS_AUTH0_ROLES_CLAIM": "roles",
		"SSO_PROVIDERS_AZURE_CLIENT_ID": "azure-id", "SSO_PROVIDERS_AZURE_CLIENT_SECRET": vendorSec, "SSO_PROVIDERS_AZURE_TENANT_ID": "organizations",
		"SSO_PROVIDERS_AZURE_ALLOWED_TENANTS": tenantGUID + ", 22222222-2222-2222-2222-222222222222",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(m.Providers(), ","); got != "auth0,azure,mock,okta" {
		t.Errorf("providers = %s", got)
	}
}

func TestVendorConfigErrors(t *testing.T) {
	cases := map[string]map[string]string{
		"okta no secret":      {"SSO_PROVIDERS_OKTA_CLIENT_ID": "id", "SSO_PROVIDERS_OKTA_ISSUER_URL": "https://o.example.test"},
		"okta no issuer":      {"SSO_PROVIDERS_OKTA_CLIENT_ID": "id", "SSO_PROVIDERS_OKTA_CLIENT_SECRET": vendorSec},
		"okta http issuer":    {"SSO_PROVIDERS_OKTA_CLIENT_ID": "id", "SSO_PROVIDERS_OKTA_CLIENT_SECRET": vendorSec, "SSO_PROVIDERS_OKTA_ISSUER_URL": "http://o.example.test"},
		"auth0 no secret":     {"SSO_PROVIDERS_AUTH0_CLIENT_ID": "id", "SSO_PROVIDERS_AUTH0_ISSUER_URL": "https://o.example.test"},
		"auth0 no issuer":     {"SSO_PROVIDERS_AUTH0_CLIENT_ID": "id", "SSO_PROVIDERS_AUTH0_CLIENT_SECRET": vendorSec},
		"azure no tenant":     {"SSO_PROVIDERS_AZURE_CLIENT_ID": "id", "SSO_PROVIDERS_AZURE_CLIENT_SECRET": vendorSec},
		"azure bad allowlist": {"SSO_PROVIDERS_AZURE_CLIENT_ID": "id", "SSO_PROVIDERS_AZURE_CLIENT_SECRET": vendorSec, "SSO_PROVIDERS_AZURE_TENANT_ID": "common", "SSO_PROVIDERS_AZURE_ALLOWED_TENANTS": "nope"},
		"azure no secret":     {"SSO_PROVIDERS_AZURE_CLIENT_ID": "id", "SSO_PROVIDERS_AZURE_TENANT_ID": "common"},
	}
	for name, env := range cases {
		if _, err := build(vendorEnvMap(env)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	// No redirect and no base URL.
	env := map[string]string{"SSO_STATE_SECRET": strings.Repeat("s", 32), "SSO_PROVIDERS_OKTA_CLIENT_ID": "id", "SSO_PROVIDERS_OKTA_CLIENT_SECRET": vendorSec}
	if _, err := build(func(k string) string { return env[k] }); err == nil || !strings.Contains(err.Error(), "REDIRECT_URL") {
		t.Errorf("no redirect: %v", err)
	}
}

// gateway drives the real handler: login, then the IdP callback with the state.
type gateway struct {
	t   *testing.T
	srv *httptest.Server
}

func (g gateway) login(provider string) (idpURL *url.URL, status int) {
	g.t.Helper()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(g.srv.URL + "/auth/" + provider + "/login")
	if err != nil {
		g.t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		return nil, resp.StatusCode
	}
	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		g.t.Fatal(err)
	}
	return u, resp.StatusCode
}

func (g gateway) callback(provider, state string) (int, map[string]any) {
	g.t.Helper()
	resp, err := http.Get(g.srv.URL + "/auth/" + provider + "/callback?code=c1&state=" + url.QueryEscape(state))
	if err != nil {
		g.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return resp.StatusCode, out
}

// TestVendorEndToEnd runs login -> IdP redirect -> callback through the real
// gateway handler for each vendor against an in-process fake IdP.
func TestVendorEndToEnd(t *testing.T) {
	type tc struct {
		provider string
		env      func(f *oidctest.Fake) map[string]string
		issuer   func(f *oidctest.Fake) string
		path     string
		claims   map[string]any
		check    func(t *testing.T, user map[string]any)
	}
	cases := []tc{
		{
			provider: "okta", path: "/oauth2/default/authorize",
			env: func(f *oidctest.Fake) map[string]string {
				return map[string]string{"SSO_PROVIDERS_OKTA_CLIENT_ID": "okta-id", "SSO_PROVIDERS_OKTA_CLIENT_SECRET": vendorSec, "SSO_PROVIDERS_OKTA_ISSUER_URL": f.URL() + "/oauth2/default"}
			},
			issuer: func(f *oidctest.Fake) string { return f.URL() + "/oauth2/default" },
			claims: map[string]any{"preferred_username": "ab@example.test", "groups": []string{"Everyone"}},
			check: func(t *testing.T, u map[string]any) {
				if u["username"] != "ab@example.test" || u["groups"] == nil {
					t.Errorf("okta user = %v", u)
				}
			},
		},
		{
			provider: "auth0", path: "/authorize",
			env: func(f *oidctest.Fake) map[string]string {
				return map[string]string{"SSO_PROVIDERS_AUTH0_CLIENT_ID": "auth0-id", "SSO_PROVIDERS_AUTH0_CLIENT_SECRET": vendorSec, "SSO_PROVIDERS_AUTH0_ISSUER_URL": f.URL(), "SSO_PROVIDERS_AUTH0_AUDIENCE": "https://api.example.test"}
			},
			issuer: func(f *oidctest.Fake) string { return f.URL() + "/" },
			claims: map[string]any{"nickname": "ab", "roles": []string{"admin"}},
			check: func(t *testing.T, u map[string]any) {
				if u["username"] != "ab" || u["roles"] == nil {
					t.Errorf("auth0 user = %v", u)
				}
			},
		},
		{
			provider: "azure", path: "/" + tenantGUID + "/v2.0/authorize",
			env: func(f *oidctest.Fake) map[string]string {
				return map[string]string{"SSO_PROVIDERS_AZURE_CLIENT_ID": "azure-id", "SSO_PROVIDERS_AZURE_CLIENT_SECRET": vendorSec, "SSO_PROVIDERS_AZURE_TENANT_ID": tenantGUID, "SSO_PROVIDERS_AZURE_AUTHORITY": f.URL()}
			},
			issuer: func(f *oidctest.Fake) string { return f.URL() + "/" + tenantGUID + "/v2.0" },
			claims: map[string]any{"tid": tenantGUID, "preferred_username": "ab@example.test", "roles": []string{"Reader"}},
			check: func(t *testing.T, u map[string]any) {
				if u["tenant_id"] != tenantGUID || u["roles"] == nil {
					t.Errorf("azure user = %v", u)
				}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.provider, func(t *testing.T) {
			f := oidctest.New(t)
			m, err := build(vendorEnvMap(c.env(f)))
			if err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewServer(newHandler(m))
			defer srv.Close()
			g := gateway{t, srv}

			idp, _ := g.login(c.provider)
			if idp == nil {
				t.Fatal("login did not redirect")
			}
			q := idp.Query()
			if !strings.HasPrefix(idp.String(), f.URL()+c.path+"?") {
				t.Errorf("redirect target = %s", idp)
			}
			if q.Get("code_challenge_method") != "S256" || q.Get("state") == "" || q.Get("nonce") == "" || q.Get("response_type") != "code" {
				t.Errorf("authorization request lacks security parameters: %v", q)
			}
			if c.provider == "auth0" && q.Get("audience") != "https://api.example.test" {
				t.Errorf("audience = %q", q.Get("audience"))
			}

			// The IdP echoes the nonce it was given, as a real one does.
			claims := oidctest.GoodClaims(c.issuer(f), c.env(f)[strings.ToUpper("SSO_PROVIDERS_"+c.provider+"_CLIENT_ID")], q.Get("nonce"))
			if c.provider == "azure" {
				claims["aud"] = "azure-id"
			}
			for k, v := range c.claims {
				claims[k] = v
			}
			f.SetClaims(claims)
			f.DiscoveryIssuer(c.issuer(f))

			status, body := g.callback(c.provider, q.Get("state"))
			if status != http.StatusOK {
				t.Fatalf("callback = %d %v", status, body)
			}
			if body["provider_id"] != c.provider {
				t.Errorf("provider_id = %v", body["provider_id"])
			}
			if _, leaked := body["tokens"]; leaked {
				t.Error("tokens must not be echoed to the client")
			}
			user, _ := body["user"].(map[string]any)
			if user["id"] != "user-1" {
				t.Errorf("user = %v", user)
			}
			c.check(t, user)

			// A tampered state is refused before any token exchange.
			if status, _ := g.callback(c.provider, q.Get("state")+"x"); status != http.StatusBadRequest {
				t.Errorf("tampered state = %d", status)
			}
		})
	}
}

func TestVendorEndToEndRejectsWrongNonce(t *testing.T) {
	f := oidctest.New(t)
	m, err := build(vendorEnvMap(map[string]string{
		"SSO_PROVIDERS_OKTA_CLIENT_ID": "okta-id", "SSO_PROVIDERS_OKTA_CLIENT_SECRET": vendorSec, "SSO_PROVIDERS_OKTA_ISSUER_URL": f.URL() + "/oauth2/default",
	}))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(newHandler(m))
	defer srv.Close()
	g := gateway{t, srv}
	idp, _ := g.login("okta")
	f.SetClaims(oidctest.GoodClaims(f.URL()+"/oauth2/default", "okta-id", "replayed-nonce"))
	status, body := g.callback("okta", idp.Query().Get("state"))
	if status == http.StatusOK {
		t.Fatalf("replayed token accepted: %v", body)
	}
}
