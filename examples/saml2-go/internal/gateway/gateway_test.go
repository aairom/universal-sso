package gateway

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestLoadConfig(t *testing.T) {
	cfg, err := LoadConfig(env(nil), "saml")
	if err != nil || cfg.GatewayURL.String() != DefaultGatewayURL || cfg.Provider != "saml" {
		t.Fatalf("defaults: %+v %v", cfg, err)
	}
	bad := []map[string]string{
		{"SSO_GATEWAY_URL": "ftp://x"},
		{"SSO_GATEWAY_URL": "http://gateway.example.test"}, // plain http, not loopback
		{"SSO_PROVIDER": "Bad Provider!"},
		{"SSO_HTTP_TIMEOUT_SECONDS": "0"},
		{"SSO_HTTP_TIMEOUT_SECONDS": "abc"},
	}
	for _, m := range bad {
		if _, err := LoadConfig(env(m), "saml"); err == nil {
			t.Errorf("expected error for %v", m)
		}
	}
	cfg, err = LoadConfig(env(map[string]string{"SSO_GATEWAY_URL": "https://sso.example.test/base/", "SSO_EXPECTED_IDP_HOST": " IdP.Example.Test "}), "saml")
	if err != nil || cfg.GatewayURL.Path != "/base" || cfg.ExpectedIdPHost != "idp.example.test" {
		t.Fatalf("normalization: %+v %v", cfg, err)
	}
}

func deflateB64(t *testing.T, s string) string {
	t.Helper()
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func u(t *testing.T, s string) *url.URL {
	t.Helper()
	p, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCheckAuthorizeURLOAuth(t *testing.T) {
	gw := u(t, "http://localhost:8080")
	ok := "https://idp.example.test/authorize?state=abc&code_challenge=xyz&code_challenge_method=S256"
	if st, err := CheckAuthorizeURL(u(t, ok), gw, "example.test"); err != nil || st != "abc" {
		t.Fatalf("ok case: %q %v", st, err)
	}
	cases := map[string]string{
		"bad scheme":    "javascript:alert(1)",
		"plain http":    "http://idp.example.test/authorize?state=a&code_challenge=x&code_challenge_method=S256",
		"wrong host":    "https://evil.test/authorize?state=a&code_challenge=x&code_challenge_method=S256",
		"look-alike":    "https://notexample.test/authorize?state=a&code_challenge=x&code_challenge_method=S256",
		"no state":      "https://idp.example.test/authorize?code_challenge=x&code_challenge_method=S256",
		"no pkce":       "https://idp.example.test/authorize?state=a",
		"plain pkce":    "https://idp.example.test/authorize?state=a&code_challenge=x&code_challenge_method=plain",
		"saml no relay": "https://idp.example.test/sso?SAMLRequest=abc",
	}
	for name, raw := range cases {
		if _, err := CheckAuthorizeURL(u(t, raw), gw, "example.test"); !errors.Is(err, ErrPolicy) {
			t.Errorf("%s: expected ErrPolicy, got %v", name, err)
		}
	}
	// Same-host plain http is allowed (mock provider).
	if _, err := CheckAuthorizeURL(u(t, "http://localhost:8080/mock/authorize?state=a&code_challenge=x&code_challenge_method=S256"), gw, ""); err != nil {
		t.Errorf("gateway-local redirect rejected: %v", err)
	}
}

func TestCheckAuthorizeURLSAML(t *testing.T) {
	gw := u(t, "https://sso.example.test")
	dest := "https://idp.example.test/sso"
	good := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_1" Destination="` + dest + `" AssertionConsumerServiceURL="https://sso.example.test/auth/saml/callback"/>`
	mk := func(x string) *url.URL {
		return u(t, dest+"?"+url.Values{"SAMLRequest": {deflateB64(t, x)}, "RelayState": {"st"}}.Encode())
	}
	if st, err := CheckAuthorizeURL(mk(good), gw, "idp.example.test"); err != nil || st != "st" {
		t.Fatalf("good: %q %v", st, err)
	}
	for name, x := range map[string]string{
		"no id":        `<AuthnRequest/>`,
		"bad dest":     `<AuthnRequest ID="_1" Destination="https://evil.test/sso"/>`,
		"foreign acs":  `<AuthnRequest ID="_1" AssertionConsumerServiceURL="https://evil.test/cb"/>`,
		"not an xml":   `hello`,
		"wrong root":   `<Response ID="_1"/>`,
		"huge payload": `<AuthnRequest ID="_1">` + strings.Repeat("a", maxSAMLRequestBytes+10) + `</AuthnRequest>`,
	} {
		if _, err := CheckAuthorizeURL(mk(x), gw, ""); !errors.Is(err, ErrPolicy) {
			t.Errorf("%s: expected ErrPolicy, got %v", name, err)
		}
	}
	if err := InspectSAMLRequest("!!!not-base64", u(t, dest), gw); !errors.Is(err, ErrPolicy) {
		t.Errorf("bad base64: %v", err)
	}
	if err := InspectSAMLRequest(base64.StdEncoding.EncodeToString([]byte{0xff, 0xff}), u(t, dest), gw); !errors.Is(err, ErrPolicy) {
		t.Errorf("bad deflate: %v", err)
	}
}

// fakeGateway mimics ssod's contract for the mock provider and a missing provider.
func fakeGateway(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"status":"ok"}`)) })
	mux.HandleFunc("/providers", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"providers":["mock"]}`))
	})
	mux.HandleFunc("/auth/mock/login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/mock/authorize?state=s1&code_challenge=c&code_challenge_method=S256", http.StatusFound)
	})
	mux.HandleFunc("/mock/authorize", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/auth/mock/callback?code=mock-code&state=s1", http.StatusFound)
	})
	mux.HandleFunc("/auth/mock/callback", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"provider_id":"mock","user":{"id":"u1","email":"a@example.com","display_name":"Mock User"}}`))
	})
	mux.HandleFunc("/auth/saml/login", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"PROVIDER_NOT_FOUND","message":"saml"}`))
	})
	mux.HandleFunc("/auth/ext/login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://idp.example.test/authorize?state=s&code_challenge=c&code_challenge_method=S256", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newTestClient(t *testing.T, base, provider string) *Client {
	t.Helper()
	cfg, err := LoadConfig(env(map[string]string{"SSO_GATEWAY_URL": base, "SSO_PROVIDER": provider}), "saml")
	if err != nil {
		t.Fatal(err)
	}
	return NewClient(cfg, nil)
}

func TestClientMockFlow(t *testing.T) {
	srv := fakeGateway(t)
	c := newTestClient(t, srv.URL, "mock")
	ctx := context.Background()
	if err := c.Health(ctx); err != nil {
		t.Fatal(err)
	}
	ids, err := c.Providers(ctx)
	if err != nil || len(ids) != 1 || ids[0] != "mock" {
		t.Fatalf("providers: %v %v", ids, err)
	}
	l, err := c.StartLogin(ctx)
	if err != nil || l.State != "s1" {
		t.Fatalf("start: %+v %v", l, err)
	}
	p, err := c.FollowLocal(ctx, l)
	if err != nil || p.User.Email != "a@example.com" {
		t.Fatalf("follow: %+v %v", p, err)
	}
}

func TestClientErrors(t *testing.T) {
	srv := fakeGateway(t)
	_, err := newTestClient(t, srv.URL, "saml").StartLogin(context.Background())
	var api *APIError
	if !errors.As(err, &api) || api.Code != "PROVIDER_NOT_FOUND" || api.Status != 404 {
		t.Fatalf("expected PROVIDER_NOT_FOUND, got %v", err)
	}
	// External redirect: allowed to start, but FollowLocal must refuse to leave the gateway.
	c := newTestClient(t, srv.URL, "ext")
	l, err := c.StartLogin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.FollowLocal(context.Background(), l); !errors.Is(err, ErrLeavesGateway) {
		t.Fatalf("expected ErrLeavesGateway, got %v", err)
	}
	// Unreachable gateway.
	dead := httptest.NewServer(http.NotFoundHandler())
	base := dead.URL
	dead.Close()
	if err := newTestClient(t, base, "mock").Health(context.Background()); err == nil {
		t.Fatal("expected error for unreachable gateway")
	}
}

func TestHealthRejectsBadBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"status":"down"}`)) }))
	defer srv.Close()
	if err := newTestClient(t, srv.URL, "mock").Health(context.Background()); err == nil {
		t.Fatal("expected unhealthy error")
	}
}
