package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/universal-sso/universal-sso/pkg/sso"
	"github.com/universal-sso/universal-sso/pkg/sso/oidc/oidctest"
)

const (
	testClient   = "client-abc"
	testRedirect = "http://localhost:8080/auth/x/callback"
	verifier     = "v-0123456789012345678901234567890123456789012"
	nonce        = "n-1"
)

func newProv(t *testing.T, f *oidctest.Fake, mutate func(*Config)) *Provider {
	t.Helper()
	cfg := Config{
		Name: "Test", ClientID: testClient, ClientSecret: "test-value", // nosecret: fixture
		RedirectURL: testRedirect, Issuer: f.URL(),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// newStatusServer answers every request with a fixed status and body.
func newStatusServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func code(t *testing.T, err error) sso.SSOErrorCode {
	t.Helper()
	var se *sso.SSOError
	if !errors.As(err, &se) {
		t.Fatalf("want *sso.SSOError, got %T: %v", err, err)
	}
	return se.Code
}

func cb(code string) sso.CallbackRequest {
	return sso.CallbackRequest{Code: code, CodeVerifier: verifier, Nonce: nonce}
}

func TestNewValidation(t *testing.T) {
	ok := Config{Name: "T", ClientID: "c", ClientSecret: "s", RedirectURL: testRedirect, Issuer: "https://idp.example.test"} // nosecret
	cases := map[string]func(*Config){
		"no name":           func(c *Config) { c.Name = "" },
		"no client id":      func(c *Config) { c.ClientID = "" },
		"no secret":         func(c *Config) { c.ClientSecret = "" },
		"no redirect":       func(c *Config) { c.RedirectURL = "" },
		"no issuer":         func(c *Config) { c.Issuer = "" },
		"http issuer":       func(c *Config) { c.Issuer = "http://idp.example.test" },
		"relative issuer":   func(c *Config) { c.Issuer = "idp.example.test" },
		"http discovery":    func(c *Config) { c.DiscoveryURL = "http://idp.example.test/d" },
		"bad redirect":      func(c *Config) { c.RedirectURL = "/cb" },
		"bad client auth":   func(c *Config) { c.ClientAuth = "digest" },
		"remote http redir": func(c *Config) { c.RedirectURL = "http://app.example.test/cb" },
	}
	for name, mut := range cases {
		cfg := ok
		mut(&cfg)
		if _, err := New(cfg); err == nil || code(t, err) != sso.ErrCodeInvalidConfig {
			t.Errorf("%s: want invalid config, got %v", name, err)
		}
	}
	p, err := New(ok)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID() != "t" || p.Name() != "T" || p.Protocol() != sso.ProtocolOIDC {
		t.Errorf("bad identity: %s %s %s", p.ID(), p.Name(), p.Protocol())
	}
}

func TestValidateURLLoopback(t *testing.T) {
	for _, u := range []string{"http://localhost:1/x", "http://127.0.0.1/x", "http://[::1]:9/x", "https://a.example.test"} {
		if err := ValidateURL("T", "u", u); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	if err := ValidateURL("T", "u", "ftp://a.example.test"); err == nil {
		t.Error("ftp accepted")
	}
}

func TestGetAuthURL(t *testing.T) {
	f := oidctest.New(t)
	p := newProv(t, f, func(c *Config) { c.ExtraAuthParams = map[string]string{"audience": "api", "state": "evil"} })
	resp, err := p.GetAuthURL(context.Background(), sso.AuthURLRequest{
		State: "s1", Nonce: nonce, CodeVerifier: verifier, Prompt: "login", LoginHint: "a@example.test",
		ExtraParams: map[string]string{"client_id": "evil", "code_challenge_method": "plain", "x": "1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(resp.URL)
	q := u.Query()
	want := map[string]string{
		"response_type": "code", "client_id": testClient, "redirect_uri": testRedirect,
		"state": "s1", "nonce": nonce, "code_challenge_method": "S256",
		"code_challenge": sso.CodeChallengeS256(verifier), "scope": "openid email profile",
		"prompt": "login", "login_hint": "a@example.test", "audience": "api", "x": "1",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	if !strings.HasPrefix(resp.URL, f.URL()+"/authorize?") {
		t.Errorf("url = %s", resp.URL)
	}
	for _, bad := range []sso.AuthURLRequest{{Nonce: nonce, CodeVerifier: verifier}, {State: "s", CodeVerifier: verifier}, {State: "s", Nonce: nonce}} {
		if _, err := p.GetAuthURL(context.Background(), bad); err == nil || code(t, err) != sso.ErrCodeInvalidConfig {
			t.Errorf("want invalid config for %+v, got %v", bad, err)
		}
	}
	custom, err := p.GetAuthURL(context.Background(), sso.AuthURLRequest{State: "s", Nonce: nonce, CodeVerifier: verifier, Scopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(custom.URL, "scope=openid&") && !strings.HasSuffix(custom.URL, "scope=openid") && !strings.Contains(custom.URL, "scope=openid") {
		t.Errorf("scopes not applied: %s", custom.URL)
	}
}

func TestHandleCallbackSuccess(t *testing.T) {
	for _, auth := range []string{AuthPost, AuthBasic} {
		f := oidctest.New(t)
		f.SetClaims(oidctest.GoodClaims(f.URL(), testClient, nonce))
		p := newProv(t, f, func(c *Config) {
			c.ClientAuth = auth
			c.MapUser = func(raw map[string]any, u *sso.UserInfo) { u.Groups = Strings(raw, "groups") }
		})
		res, err := p.HandleCallback(context.Background(), cb("code-1"))
		if err != nil {
			t.Fatalf("%s: %v", auth, err)
		}
		if res.ProviderID != "test" || res.Protocol != sso.ProtocolOIDC || res.User.ID != "user-1" ||
			res.User.Email != "a@example.test" || !res.User.EmailVerified || res.User.DisplayName != "A B" ||
			res.User.FirstName != "A" || res.User.LastName != "B" {
			t.Errorf("%s: user = %+v", auth, res.User)
		}
		if res.Tokens.AccessToken != "at-1" || res.Tokens.RefreshToken != "rt-1" || res.Tokens.IDToken == "" || res.Tokens.ExpiresAt.Before(time.Now()) {
			t.Errorf("%s: tokens = %+v", auth, res.Tokens)
		}
		form := f.TokenForm()
		if form.Get("grant_type") != "authorization_code" || form.Get("code") != "code-1" ||
			form.Get("code_verifier") != verifier || form.Get("redirect_uri") != testRedirect || form.Get("client_id") != testClient {
			t.Errorf("%s: token form = %v", auth, form)
		}
		hdr := f.TokenAuthHeader()
		if auth == AuthPost {
			if form.Get("client_secret") != "test-value" || hdr != "" {
				t.Errorf("post auth: secret=%q header=%q", form.Get("client_secret"), hdr)
			}
		} else {
			raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(hdr, "Basic "))
			if string(raw) != testClient+":test-value" || form.Get("client_secret") != "" {
				t.Errorf("basic auth: header=%q secret=%q", raw, form.Get("client_secret"))
			}
		}
	}
}

func TestHandleCallbackRejections(t *testing.T) {
	f := oidctest.New(t)
	p := newProv(t, f, nil)
	ctx := context.Background()

	if _, err := p.HandleCallback(ctx, sso.CallbackRequest{Error: "access_denied", ErrorDesc: "no"}); code(t, err) != sso.ErrCodeIdPRejected {
		t.Errorf("idp error: %v", err)
	}
	if _, err := p.HandleCallback(ctx, sso.CallbackRequest{CodeVerifier: verifier, Nonce: nonce}); code(t, err) != sso.ErrCodeIdPRejected {
		t.Errorf("missing code: %v", err)
	}
	if _, err := p.HandleCallback(ctx, sso.CallbackRequest{Code: "c", Nonce: nonce}); code(t, err) != sso.ErrCodeStateMismatch {
		t.Errorf("missing verifier: %v", err)
	}
	if _, err := p.HandleCallback(ctx, sso.CallbackRequest{Code: "c", CodeVerifier: verifier}); code(t, err) != sso.ErrCodeStateMismatch {
		t.Errorf("missing nonce: %v", err)
	}

	f.FailToken("invalid_grant")
	if _, err := p.HandleCallback(ctx, cb("c")); err == nil || code(t, err) != sso.ErrCodeIdPRejected || !strings.Contains(err.Error(), "invalid_grant") {
		t.Errorf("token error: %v", err)
	}
	f.FailToken("")

	f.OmitIDToken()
	f.SetClaims(oidctest.GoodClaims(f.URL(), testClient, nonce))
	if _, err := p.HandleCallback(ctx, cb("c")); code(t, err) != sso.ErrCodeIdPRejected {
		t.Errorf("no id_token: %v", err)
	}
}

func TestIDTokenFailures(t *testing.T) {
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now()
	cases := []struct {
		name   string
		mutate func(c map[string]any)
		sign   func(f *oidctest.Fake, c map[string]any) string
		want   sso.SSOErrorCode
	}{
		{"wrong issuer", func(c map[string]any) { c["iss"] = "https://evil.example.test" }, nil, sso.ErrCodeInvalidToken},
		{"empty issuer", func(c map[string]any) { c["iss"] = "" }, nil, sso.ErrCodeInvalidToken},
		{"wrong audience", func(c map[string]any) { c["aud"] = "someone-else" }, nil, sso.ErrCodeInvalidToken},
		{"audience array without us", func(c map[string]any) { c["aud"] = []string{"a", "b"} }, nil, sso.ErrCodeInvalidToken},
		{"expired", func(c map[string]any) { c["exp"] = now.Add(-2 * time.Hour).Unix() }, nil, sso.ErrCodeTokenExpired},
		{"no exp", func(c map[string]any) { delete(c, "exp") }, nil, sso.ErrCodeTokenExpired},
		{"not yet valid", func(c map[string]any) { c["nbf"] = now.Add(time.Hour).Unix() }, nil, sso.ErrCodeInvalidToken},
		{"no subject", func(c map[string]any) { c["sub"] = "" }, nil, sso.ErrCodeInvalidToken},
		{"alg none", nil, func(f *oidctest.Fake, c map[string]any) string { return f.SignWith(f.Key, f.Kid, "none", c) }, sso.ErrCodeInvalidToken},
		{"alg HS256", nil, func(f *oidctest.Fake, c map[string]any) string { return f.SignWith(f.Key, f.Kid, "HS256", c) }, sso.ErrCodeInvalidToken},
		{"foreign key same kid", nil, func(f *oidctest.Fake, c map[string]any) string { return f.SignWith(other, f.Kid, "RS256", c) }, sso.ErrCodeSignatureInvalid},
		{"unknown kid", nil, func(f *oidctest.Fake, c map[string]any) string { return f.SignWith(f.Key, "nope", "RS256", c) }, sso.ErrCodeSignatureInvalid},
		{"malformed", nil, func(*oidctest.Fake, map[string]any) string { return "a.b" }, sso.ErrCodeInvalidToken},
		{"bad base64", nil, func(*oidctest.Fake, map[string]any) string { return "!.!.!" }, sso.ErrCodeInvalidToken},
	}
	for _, tc := range cases {
		f := oidctest.New(t)
		p := newProv(t, f, nil)
		c := oidctest.GoodClaims(f.URL(), testClient, nonce)
		if tc.mutate != nil {
			tc.mutate(c)
		}
		tok := f.Sign(c)
		if tc.sign != nil {
			tok = tc.sign(f, c)
		}
		if _, err := p.ValidateToken(context.Background(), tok); err == nil || code(t, err) != tc.want {
			t.Errorf("%s: want %s, got %v", tc.name, tc.want, err)
		}
	}
}

func TestNonceMismatch(t *testing.T) {
	f := oidctest.New(t)
	f.SetClaims(oidctest.GoodClaims(f.URL(), testClient, "other-nonce"))
	p := newProv(t, f, nil)
	if _, err := p.HandleCallback(context.Background(), cb("c")); code(t, err) != sso.ErrCodeStateMismatch {
		t.Errorf("nonce mismatch: %v", err)
	}
}

func TestAudienceArrayAccepted(t *testing.T) {
	f := oidctest.New(t)
	p := newProv(t, f, nil)
	c := oidctest.GoodClaims(f.URL(), testClient, nonce)
	c["aud"] = []string{"other", testClient}
	cl, err := p.ValidateToken(context.Background(), f.Sign(c))
	if err != nil {
		t.Fatal(err)
	}
	if cl.Subject != "user-1" || len(cl.Audience) != 2 || cl.Issuer != f.URL() {
		t.Errorf("claims = %+v", cl)
	}
}

func TestClockSkewAndHooks(t *testing.T) {
	f := oidctest.New(t)
	p := newProv(t, f, func(c *Config) {
		c.CheckClaims = func(m map[string]any) error {
			if String(m, "deny") != "" {
				return sso.ErrUnauthorizedAccess("denied")
			}
			return nil
		}
	})
	c := oidctest.GoodClaims(f.URL(), testClient, nonce)
	c["exp"] = time.Now().Add(-30 * time.Second).Unix() // inside the 60s skew
	if _, err := p.ValidateToken(context.Background(), f.Sign(c)); err != nil {
		t.Errorf("within skew: %v", err)
	}
	c["deny"] = "yes"
	if _, err := p.ValidateToken(context.Background(), f.Sign(c)); err == nil || code(t, err) != sso.ErrCodeUnauthorized {
		t.Errorf("CheckClaims not applied: %v", err)
	}
}

func TestAcceptIssuerHook(t *testing.T) {
	f := oidctest.New(t)
	p := newProv(t, f, func(c *Config) {
		c.AcceptIssuer = func(tok, disc string, _ map[string]any) bool {
			return tok == "https://alt.example.test" && disc == f.URL()
		}
	})
	c := oidctest.GoodClaims("https://alt.example.test", testClient, nonce)
	if _, err := p.ValidateToken(context.Background(), f.Sign(c)); err != nil {
		t.Errorf("custom issuer: %v", err)
	}
}

func TestDiscoveryIssuerMismatch(t *testing.T) {
	f := oidctest.New(t)
	f.DiscoveryIssuer("https://evil.example.test")
	p := newProv(t, f, nil)
	_, err := p.GetAuthURL(context.Background(), sso.AuthURLRequest{State: "s", Nonce: nonce, CodeVerifier: verifier})
	if err == nil || code(t, err) != sso.ErrCodeIdPRejected {
		t.Errorf("want idp rejected, got %v", err)
	}
	p2 := newProv(t, f, func(c *Config) {
		c.AcceptDiscoveryIssuer = func(s string) bool { return s == "https://evil.example.test" }
	})
	if _, err := p2.GetAuthURL(context.Background(), sso.AuthURLRequest{State: "s", Nonce: nonce, CodeVerifier: verifier}); err != nil {
		t.Errorf("hook should accept: %v", err)
	}
}

func TestDiscoveryTrailingSlashTolerated(t *testing.T) {
	f := oidctest.New(t)
	f.DiscoveryIssuer(f.URL() + "/")
	p := newProv(t, f, nil)
	if _, err := p.GetAuthURL(context.Background(), sso.AuthURLRequest{State: "s", Nonce: nonce, CodeVerifier: verifier}); err != nil {
		t.Error(err)
	}
}

func TestDiscoveryFailures(t *testing.T) {
	srv := newStatusServer(t, http.StatusInternalServerError, "")
	p, _ := New(Config{Name: "T", ClientID: "c", ClientSecret: "s", RedirectURL: testRedirect, Issuer: srv.URL}) // nosecret
	if _, err := p.GetAuthURL(context.Background(), sso.AuthURLRequest{State: "s", Nonce: nonce, CodeVerifier: verifier}); code(t, err) != sso.ErrCodeNetworkFailure {
		t.Errorf("500: %v", err)
	}
	bad := newStatusServer(t, 200, "{not json")
	p, _ = New(Config{Name: "T", ClientID: "c", ClientSecret: "s", RedirectURL: testRedirect, Issuer: bad.URL}) // nosecret
	if _, err := p.GetAuthURL(context.Background(), sso.AuthURLRequest{State: "s", Nonce: nonce, CodeVerifier: verifier}); code(t, err) != sso.ErrCodeNetworkFailure {
		t.Errorf("bad json: %v", err)
	}
	inc := newStatusServer(t, 200, `{"issuer":"x"}`)
	p, _ = New(Config{Name: "T", ClientID: "c", ClientSecret: "s", RedirectURL: testRedirect, Issuer: inc.URL}) // nosecret
	if _, err := p.GetAuthURL(context.Background(), sso.AuthURLRequest{State: "s", Nonce: nonce, CodeVerifier: verifier}); code(t, err) != sso.ErrCodeNetworkFailure {
		t.Errorf("incomplete: %v", err)
	}
	dead := newStatusServer(t, 200, "{}")
	url := dead.URL
	dead.Close()
	p, _ = New(Config{Name: "T", ClientID: "c", ClientSecret: "s", RedirectURL: testRedirect, Issuer: url}) // nosecret
	if _, err := p.GetAuthURL(context.Background(), sso.AuthURLRequest{State: "s", Nonce: nonce, CodeVerifier: verifier}); code(t, err) != sso.ErrCodeNetworkFailure {
		t.Errorf("down: %v", err)
	}
}

func TestDiscoveryAndJWKSCached(t *testing.T) {
	f := oidctest.New(t)
	p := newProv(t, f, nil)
	for i := 0; i < 3; i++ {
		if _, err := p.ValidateToken(context.Background(), f.Sign(oidctest.GoodClaims(f.URL(), testClient, nonce))); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.JWKSHits.Load(); n != 1 {
		t.Errorf("JWKS fetched %d times, want 1", n)
	}
}

func TestKeyRotation(t *testing.T) {
	f := oidctest.New(t)
	p := newProv(t, f, nil)
	ctx := context.Background()
	if _, err := p.ValidateToken(ctx, f.Sign(oidctest.GoodClaims(f.URL(), testClient, nonce))); err != nil {
		t.Fatal(err)
	}
	// The IdP rotates to a new key. Inside keyMinGap an unknown kid must not hammer the JWKS URI.
	nk, _ := rsa.GenerateKey(rand.Reader, 2048)
	f.Set(func(f *oidctest.Fake) { f.Key, f.Kid = nk, "kid-2" })
	tok := f.Sign(oidctest.GoodClaims(f.URL(), testClient, nonce))
	before := f.JWKSHits.Load()
	if _, err := p.ValidateToken(ctx, tok); code(t, err) != sso.ErrCodeSignatureInvalid {
		t.Errorf("inside min gap: %v", err)
	}
	if f.JWKSHits.Load() != before {
		t.Error("JWKS refetched inside min gap")
	}
	p.keyMinGap = 0 // gap elapsed
	if _, err := p.ValidateToken(ctx, tok); err != nil {
		t.Errorf("after rotation: %v", err)
	}
}

func TestStaleCachesRefresh(t *testing.T) {
	f := oidctest.New(t)
	p := newProv(t, f, nil)
	ctx := context.Background()
	if _, err := p.ValidateToken(ctx, f.Sign(oidctest.GoodClaims(f.URL(), testClient, nonce))); err != nil {
		t.Fatal(err)
	}
	p.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	c := oidctest.GoodClaims(f.URL(), testClient, nonce)
	c["exp"] = time.Now().Add(5 * time.Hour).Unix()
	if _, err := p.ValidateToken(ctx, f.Sign(c)); err != nil {
		t.Fatal(err)
	}
	if f.JWKSHits.Load() != 2 {
		t.Errorf("JWKS hits = %d, want 2 after TTL", f.JWKSHits.Load())
	}
}

func TestRefreshToken(t *testing.T) {
	f := oidctest.New(t)
	p := newProv(t, f, nil)
	ctx := context.Background()
	if _, err := p.RefreshToken(ctx, ""); code(t, err) != sso.ErrCodeInvalidToken {
		t.Errorf("empty: %v", err)
	}
	tr, err := p.RefreshToken(ctx, "rt-old")
	if err != nil {
		t.Fatal(err)
	}
	if tr.AccessToken != "at-1" || tr.RefreshToken != "rt-old" {
		t.Errorf("tokens = %+v", tr) // refresh token carried over when not rotated
	}
	if f.TokenForm().Get("grant_type") != "refresh_token" || f.TokenForm().Get("refresh_token") != "rt-old" {
		t.Errorf("form = %v", f.TokenForm())
	}
	// A returned ID token must verify.
	bad := oidctest.GoodClaims("https://evil.example.test", testClient, nonce)
	f.SetClaims(bad)
	if _, err := p.RefreshToken(ctx, "rt-old"); code(t, err) != sso.ErrCodeInvalidToken {
		t.Errorf("bad id token on refresh: %v", err)
	}
	f.SetClaims(oidctest.GoodClaims(f.URL(), testClient, nonce))
	if _, err := p.RefreshToken(ctx, "rt-old"); err != nil {
		t.Errorf("good id token on refresh: %v", err)
	}
	f.FailToken("invalid_grant")
	if _, err := p.RefreshToken(ctx, "rt-old"); code(t, err) != sso.ErrCodeIdPRejected {
		t.Errorf("rejected: %v", err)
	}
}

func TestRevokeToken(t *testing.T) {
	f := oidctest.New(t)
	p := newProv(t, f, nil)
	ctx := context.Background()
	if err := p.RevokeToken(ctx, "rt-1"); err != nil {
		t.Fatal(err)
	}
	if f.RevokeForm().Get("token") != "rt-1" || f.RevokeForm().Get("client_id") != testClient || f.RevokeForm().Get("client_secret") != "test-value" {
		t.Errorf("revoke form = %v", f.RevokeForm())
	}
	f.RevokeStatus(500)
	if err := p.RevokeToken(ctx, "rt-1"); code(t, err) != sso.ErrCodeIdPRejected {
		t.Errorf("500: %v", err)
	}
	f2 := oidctest.New(t)
	f2.OmitRevocation()
	if err := newProv(t, f2, nil).RevokeToken(ctx, "x"); code(t, err) != sso.ErrCodeUnsupportedMethod {
		t.Errorf("unsupported: %v", err)
	}
	f3 := oidctest.New(t)
	pb := newProv(t, f3, func(c *Config) { c.ClientAuth = AuthBasic })
	if err := pb.RevokeToken(ctx, "x"); err != nil {
		t.Fatal(err)
	}
	if f3.RevokeForm().Get("client_secret") != "" {
		t.Error("basic auth must not also send the secret in the body")
	}
}

func TestGetLogoutURL(t *testing.T) {
	f := oidctest.New(t)
	p := newProv(t, f, nil)
	ctx := context.Background()
	r, err := p.GetLogoutURL(ctx, sso.LogoutRequest{IDTokenHint: "tok", PostLogoutURL: "https://app.example.test/bye", State: "s"})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(r.URL)
	q := u.Query()
	if u.Path != "/logout" || q.Get("id_token_hint") != "tok" || q.Get("post_logout_redirect_uri") != "https://app.example.test/bye" || q.Get("state") != "s" {
		t.Errorf("logout url = %s", r.URL)
	}
	if _, err := p.GetLogoutURL(ctx, sso.LogoutRequest{PostLogoutURL: "javascript:alert(1)"}); code(t, err) != sso.ErrCodeInvalidConfig {
		t.Errorf("bad post logout url: %v", err)
	}
	f2 := oidctest.New(t)
	f2.OmitEndSession()
	if _, err := newProv(t, f2, nil).GetLogoutURL(ctx, sso.LogoutRequest{}); code(t, err) != sso.ErrCodeUnsupportedMethod {
		t.Errorf("unsupported: %v", err)
	}
	custom := newProv(t, f, func(c *Config) {
		c.LogoutURL = func(sso.LogoutRequest) (string, error) { return "https://idp.example.test/out", nil }
	})
	if r, err := custom.GetLogoutURL(ctx, sso.LogoutRequest{}); err != nil || r.URL != "https://idp.example.test/out" {
		t.Errorf("custom: %v %v", r, err)
	}
	failing := newProv(t, f, func(c *Config) {
		c.LogoutURL = func(sso.LogoutRequest) (string, error) { return "", errors.New("boom") }
	})
	if _, err := failing.GetLogoutURL(ctx, sso.LogoutRequest{}); err == nil {
		t.Error("custom error swallowed")
	}
}

func TestFetchUserInfo(t *testing.T) {
	f := oidctest.New(t)
	p := newProv(t, f, func(c *Config) {
		c.MapUser = func(raw map[string]any, u *sso.UserInfo) { u.Groups = Strings(raw, "groups") }
	})
	ctx := context.Background()
	u, err := p.FetchUserInfo(ctx, "at-1")
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != "user-1" || u.Email != "a@example.test" || !u.EmailVerified || len(u.Groups) != 1 {
		t.Errorf("user = %+v", u)
	}
	if _, err := p.FetchUserInfo(ctx, ""); code(t, err) != sso.ErrCodeInvalidToken {
		t.Errorf("empty: %v", err)
	}
	if _, err := p.FetchUserInfo(ctx, "wrong"); code(t, err) != sso.ErrCodeInvalidToken {
		t.Errorf("rejected: %v", err)
	}
}

func TestClaimHelpers(t *testing.T) {
	raw := map[string]any{"a": "x", "b": []any{"p", "", 3, "q"}, "c": "", "d": 5}
	if got := Strings(raw, "a"); len(got) != 1 || got[0] != "x" {
		t.Errorf("a = %v", got)
	}
	if got := Strings(raw, "b"); len(got) != 2 || got[1] != "q" {
		t.Errorf("b = %v", got)
	}
	if Strings(raw, "c") != nil || Strings(raw, "d") != nil || Strings(raw, "zz") != nil {
		t.Error("expected nil")
	}
	if String(raw, "a") != "x" || String(raw, "d") != "" {
		t.Error("String")
	}
}

func TestJWKRejectsBadKeys(t *testing.T) {
	for name, k := range map[string]jwk{
		"ec":      {Kty: "EC"},
		"enc use": {Kty: "RSA", Use: "enc", N: "AQAB", E: "AQAB"},
		"bad n":   {Kty: "RSA", N: "!", E: "AQAB"},
		"bad e":   {Kty: "RSA", N: "AQAB", E: "!"},
		"tiny e":  {Kty: "RSA", N: "AQAB", E: "AQ"},
		"huge e":  {Kty: "RSA", N: "AQAB", E: "AAAAAAAAAAE"},
	} {
		if _, err := k.publicKey(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := (jwk{Kty: "RSA", Use: "sig", N: "AQAB", E: "AQAB"}).publicKey(); err != nil {
		t.Error(err)
	}
}

func TestOversizedResponseRejected(t *testing.T) {
	big := `{"issuer":"x","pad":"` + strings.Repeat("a", maxBody+10) + `"}`
	srv := newStatusServer(t, 200, big)
	p, _ := New(Config{Name: "T", ClientID: "c", ClientSecret: "s", RedirectURL: testRedirect, Issuer: srv.URL}) // nosecret
	if _, err := p.GetAuthURL(context.Background(), sso.AuthURLRequest{State: "s", Nonce: nonce, CodeVerifier: verifier}); code(t, err) != sso.ErrCodeNetworkFailure {
		t.Errorf("oversized: %v", err)
	}
}
