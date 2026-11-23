package oidctest

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func challenge(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func noFollow() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// TestInteractiveFlow checks the fake enforces what a real IdP does: S256 PKCE,
// single-use codes and a nonce echoed from the authorization request.
func TestInteractiveFlow(t *testing.T) {
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.Handler().ServeHTTP(w, r)
	}))
	defer srv.Close()
	base = srv.URL
	f = NewInteractive(base, func(client, nonce string) map[string]any { return GoodClaims(base+"/p", client, nonce) })

	authz := func(params url.Values) *http.Response {
		resp, err := noFollow().Get(base + "/p/authorize?" + params.Encode())
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	good := url.Values{
		"response_type": {"code"}, "client_id": {"c1"}, "redirect_uri": {"http://127.0.0.1:1/cb"},
		"state": {"st"}, "nonce": {"n1"}, "code_challenge": {challenge("verifier-1")}, "code_challenge_method": {"S256"},
	}
	for name, mut := range map[string]func(url.Values){
		"plain PKCE":    func(v url.Values) { v.Set("code_challenge_method", "plain") },
		"no challenge":  func(v url.Values) { v.Del("code_challenge") },
		"implicit flow": func(v url.Values) { v.Set("response_type", "token") },
		"no redirect":   func(v url.Values) { v.Del("redirect_uri") },
	} {
		v := url.Values{}
		for k, x := range good {
			v[k] = x
		}
		mut(v)
		if got := authz(v).StatusCode; got != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, got)
		}
	}

	resp := authz(good)
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || loc.Query().Get("state") != "st" || loc.Query().Get("code") == "" {
		t.Fatalf("authorize: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	code := loc.Query().Get("code")

	exchange := func(code, verifier string) (int, map[string]any) {
		r, err := http.PostForm(base+"/p/token", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}})
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(r.Body).Decode(&out)
		return r.StatusCode, out
	}
	if st, _ := exchange(code, "wrong-verifier"); st != http.StatusBadRequest {
		t.Errorf("wrong verifier: %d", st)
	}
	// The failed attempt consumed the code: even the right verifier is now refused.
	if st, _ := exchange(code, "verifier-1"); st != http.StatusBadRequest {
		t.Errorf("code reuse after failure: %d", st)
	}

	loc2, _ := url.Parse(func() string { r := authz(good); return r.Header.Get("Location") }())
	st, body := exchange(loc2.Query().Get("code"), "verifier-1")
	if st != http.StatusOK || body["access_token"] == nil || !strings.Contains(body["id_token"].(string), ".") {
		t.Fatalf("exchange: %d %v", st, body)
	}
	if st, _ := exchange(loc2.Query().Get("code"), "verifier-1"); st != http.StatusBadRequest {
		t.Errorf("replayed code: %d", st)
	}
}

var f *Fake

func TestPlainFakeEndpoints(t *testing.T) {
	g := New(t)
	g.SetClaims(GoodClaims(g.URL(), "c", "n"))
	if g.URL() != g.Srv.URL {
		t.Error("URL")
	}
	for _, p := range []string{"/.well-known/openid-configuration", "/jwks"} {
		r, err := http.Get(g.URL() + p)
		if err != nil || r.StatusCode != 200 {
			t.Errorf("%s: %v", p, err)
		}
		r.Body.Close()
	}
	if r, _ := http.Get(g.URL() + "/nope"); r.StatusCode != http.StatusNotFound {
		t.Error("unknown path should 404")
	}
	g.OmitIDToken()
	g.FailToken("x")
	g.RevokeStatus(204)
	g.OmitEndSession()
	g.OmitRevocation()
	g.DiscoveryIssuer("https://x.example.test")
	if g.TokenAuthHeader() != "" || g.TokenForm() != nil || g.RevokeForm() != nil {
		t.Error("no request seen yet")
	}
}
