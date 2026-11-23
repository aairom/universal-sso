package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/universal-sso/universal-sso/pkg/sso/oauth2/oauth2test"
)

func oauth2Env(base string, extra map[string]string) map[string]string {
	m := map[string]string{
		"SSO_PROVIDERS_OAUTH2_CLIENT_ID": "o2-id", "SSO_PROVIDERS_OAUTH2_CLIENT_SECRET": vendorSec,
		"SSO_PROVIDERS_OAUTH2_AUTH_URL": base + "/authorize", "SSO_PROVIDERS_OAUTH2_TOKEN_URL": base + "/token",
		"SSO_PROVIDERS_OAUTH2_USERINFO_URL": base + "/user", "SSO_PROVIDERS_OAUTH2_SCOPES": "read:user user:email",
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func TestOAuth2DisabledByDefault(t *testing.T) {
	m, err := build(vendorEnvMap(map[string]string{"SSO_PROVIDERS_OAUTH2_CLIENT_ID": "oauth2-client-id-placeholder"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(m.Providers(), ","); got != "mock" {
		t.Errorf("providers = %s", got)
	}
}

func TestOAuth2ConfigErrors(t *testing.T) {
	const base = "https://idp.example.test"
	cases := map[string]map[string]string{
		"no secret":     {"SSO_PROVIDERS_OAUTH2_CLIENT_ID": "id"},
		"no urls":       {"SSO_PROVIDERS_OAUTH2_CLIENT_ID": "id", "SSO_PROVIDERS_OAUTH2_CLIENT_SECRET": vendorSec},
		"no token url":  oauth2Env(base, map[string]string{"SSO_PROVIDERS_OAUTH2_TOKEN_URL": ""}),
		"http profile":  oauth2Env(base, map[string]string{"SSO_PROVIDERS_OAUTH2_USERINFO_URL": "http://idp.example.test/user"}),
		"bad auth type": oauth2Env(base, map[string]string{"SSO_PROVIDERS_OAUTH2_AUTH_STYLE": "digest"}),
	}
	for name, env := range cases {
		if _, err := build(vendorEnvMap(env)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// startOAuth2Gateway starts ssod's real handler with oauth2 pointed at the fake.
// The gateway address is reserved first because the redirect URI derives from it.
func startOAuth2Gateway(t *testing.T, fake *oauth2test.Fake) (*httptest.Server, *httptest.Server) {
	t.Helper()
	idp := httptest.NewServer(fake.Handler())
	t.Cleanup(idp.Close)
	gw := httptest.NewUnstartedServer(nil)
	base := "http://" + gw.Listener.Addr().String()
	m, err := build(vendorEnvMap(oauth2Env(idp.URL, map[string]string{"SSO_SERVER_BASE_URL": base})))
	if err != nil {
		gw.Close()
		t.Fatal(err)
	}
	gw.Config.Handler = newHandler(m)
	gw.Start()
	t.Cleanup(gw.Close)
	return gw, idp
}

// browser follows the IdP authorize redirect and returns the callback URL it names.
func browser(t *testing.T, authorizeURL string) *url.URL {
	t.Helper()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(authorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	back, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || back.Path != "/auth/oauth2/callback" {
		t.Fatalf("IdP redirected to %q", resp.Header.Get("Location"))
	}
	return back
}

func getJSON(t *testing.T, rawURL string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Get(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return resp.StatusCode, out
}

// TestOAuth2EndToEnd drives login -> provider authorize -> callback through the
// real handler against the in-process OAuth 2.0 fake.
func TestOAuth2EndToEnd(t *testing.T) {
	gw, _ := startOAuth2Gateway(t, oauth2test.New("o2-id", vendorSec))
	g := gateway{t, gw}

	au, status := g.login("oauth2")
	if au == nil {
		t.Fatalf("login status %d", status)
	}
	q := au.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("state") == "" || q.Has("nonce") || q.Get("scope") != "read:user user:email" {
		t.Fatalf("authorization request = %v", q)
	}
	if q.Get("redirect_uri") != gw.URL+"/auth/oauth2/callback" {
		t.Fatalf("redirect_uri = %q", q.Get("redirect_uri"))
	}

	back := browser(t, au.String())
	code, body := getJSON(t, gw.URL+back.Path+"?"+back.RawQuery)
	if code != http.StatusOK {
		t.Fatalf("callback = %d %v", code, body)
	}
	if body["provider_id"] != "oauth2" {
		t.Errorf("provider_id = %v", body["provider_id"])
	}
	if _, leaked := body["tokens"]; leaked {
		t.Error("tokens must not be echoed to the client")
	}
	user, _ := body["user"].(map[string]any)
	if user["id"] != "4242" || user["username"] != "octo" || user["email_verified"] != false {
		t.Errorf("user = %v", user)
	}

	// The state is single use: replaying the same callback must fail.
	if code, _ := getJSON(t, gw.URL+back.Path+"?"+back.RawQuery); code != http.StatusBadRequest {
		t.Errorf("replayed callback = %d, want 400", code)
	}
}

func TestOAuth2RejectsForgedAndWrongCode(t *testing.T) {
	gw, _ := startOAuth2Gateway(t, oauth2test.New("o2-id", vendorSec))
	g := gateway{t, gw}

	if status, _ := g.callback("oauth2", "forged.state"); status != http.StatusBadRequest {
		t.Errorf("forged state = %d, want 400", status)
	}
	// A code the provider never issued fails at its token endpoint.
	au, _ := g.login("oauth2")
	if status, _ := g.callback("oauth2", au.Query().Get("state")); status != http.StatusUnauthorized {
		t.Errorf("unknown code = %d, want 401", status)
	}
}
