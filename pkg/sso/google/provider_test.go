package google

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/universal-sso/universal-sso/pkg/sso"
)

const (
	testClientID = "1234567890" + "12-test" + ".apps.googleusercontent" + ".com"
	testRedirect = "http://localhost:8080/auth/google/callback"
	testKid      = "kid-1"
	testEmail    = "a@example.test" // nosecret: synthetic fixture
)

// fakeGoogle is an in-process OIDC server.
type fakeGoogle struct {
	srv      *httptest.Server
	key      *rsa.PrivateKey
	kid      string
	claims   map[string]any // claims for the next id_token
	tokenErr string         // when set, /token returns this OAuth error
	noID     bool           // omit id_token from /token
	jwksHits atomic.Int32
	gotForm  url.Values
	revoke   int // status for /revoke
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func newFake(t *testing.T) *fakeGoogle {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeGoogle{key: key, kid: testKid, revoke: 200}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 f.srv.URL,
			"authorization_endpoint": f.srv.URL + "/auth",
			"token_endpoint":         f.srv.URL + "/token",
			"jwks_uri":               f.srv.URL + "/jwks",
			"userinfo_endpoint":      f.srv.URL + "/userinfo",
			"revocation_endpoint":    f.srv.URL + "/revoke",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		f.jwksHits.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": f.kid, "alg": "RS256", "use": "sig",
			"n": b64(f.key.N.Bytes()), "e": b64(big.NewInt(int64(f.key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.gotForm = r.PostForm
		if f.tokenErr != "" {
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": f.tokenErr, "error_description": "bad"})
			return
		}
		out := map[string]any{"access_token": "at-1", "token_type": "Bearer", "expires_in": 3600, "scope": "openid email profile"}
		if r.PostForm.Get("grant_type") == "authorization_code" {
			out["refresh_token"] = "rt-1"
		}
		if !f.noID {
			out["id_token"] = f.sign(t, f.claims)
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at-1" {
			w.WriteHeader(401)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": "u1", "email": testEmail, "email_verified": true, "name": "A B", "hd": "example.test"})
	})
	mux.HandleFunc("/revoke", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(f.revoke) })
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGoogle) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	return f.signWith(t, f.key, f.kid, "RS256", claims)
}

func (f *fakeGoogle) signWith(t *testing.T, key *rsa.PrivateKey, kid, alg string, claims map[string]any) string {
	t.Helper()
	hb, _ := json.Marshal(map[string]string{"alg": alg, "kid": kid, "typ": "JWT"})
	pb, _ := json.Marshal(claims)
	signing := b64(hb) + "." + b64(pb)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + b64(sig)
}

func (f *fakeGoogle) goodClaims(nonce string) map[string]any {
	return map[string]any{
		"iss": f.srv.URL, "aud": testClientID, "sub": "u1", "exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(), "nonce": nonce, "email": testEmail, "email_verified": true,
		"name": "A B", "given_name": "A", "family_name": "B", "picture": "https://example.test/p.png", "hd": "example.test",
	}
}

func (f *fakeGoogle) provider(t *testing.T, mutate func(*Config)) *Provider {
	t.Helper()
	cfg := Config{ClientID: testClientID, ClientSecret: "test-value", RedirectURL: testRedirect, DiscoveryURL: f.srv.URL + "/.well-known/openid-configuration"} // nosecret: test fixture
	if mutate != nil {
		mutate(&cfg)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func code(t *testing.T, err error) sso.SSOErrorCode {
	t.Helper()
	var se *sso.SSOError
	if !errors.As(err, &se) {
		t.Fatalf("want SSOError, got %v", err)
	}
	return se.Code
}

func cb(verifier, nonce string) sso.CallbackRequest {
	return sso.CallbackRequest{Code: "code-1", State: "s", CodeVerifier: verifier, Nonce: nonce}
}

func TestNewValidation(t *testing.T) {
	ok := Config{ClientID: testClientID, ClientSecret: "x", RedirectURL: testRedirect}
	cases := map[string]func(*Config){
		"missing id":     func(c *Config) { c.ClientID = "" },
		"missing secret": func(c *Config) { c.ClientSecret = "" },
		"missing redir":  func(c *Config) { c.RedirectURL = "" },
		"secret as id":   func(c *Config) { c.ClientID = "GOCSPX-abc.apps.googleusercontent.com" },
		"relative redir": func(c *Config) { c.RedirectURL = "/cb" },
	}
	for name, mut := range cases {
		c := ok
		mut(&c)
		if _, err := New(c); err == nil || code(t, err) != sso.ErrCodeInvalidConfig {
			t.Errorf("%s: expected INVALID_CONFIG, got %v", name, err)
		}
	}
	p, err := New(ok)
	if err != nil || p.ID() != "google" || p.Name() != "Google" || p.Protocol() != sso.ProtocolOIDC {
		t.Fatalf("defaults wrong: %v", err)
	}
}

func TestDriverRegistered(t *testing.T) {
	p, err := sso.NewProvider(DriverName, map[string]string{"client_id": testClientID, "client_secret": "x", "redirect_url": testRedirect, "id": "g2"})
	if err != nil || p.ID() != "g2" {
		t.Fatalf("driver: %v", err)
	}
	if _, err := sso.NewProvider(DriverName, map[string]string{}); err == nil {
		t.Fatal("expected config error")
	}
}

func TestGetAuthURL(t *testing.T) {
	f := newFake(t)
	p := f.provider(t, func(c *Config) { c.HostedDomain = "example.test" })
	resp, err := p.GetAuthURL(context.Background(), sso.AuthURLRequest{
		State: "st", Nonce: "no", CodeVerifier: "ver", Prompt: "consent", LoginHint: "h",
		ExtraParams: map[string]string{"state": "evil", "x": "y"},
	})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(resp.URL)
	q := u.Query()
	want := map[string]string{
		"response_type": "code", "client_id": testClientID, "redirect_uri": testRedirect,
		"scope": "openid email profile", "state": "st", "nonce": "no", "code_challenge_method": "S256",
		"code_challenge": sso.CodeChallengeS256("ver"), "prompt": "consent", "login_hint": "h", "hd": "example.test", "x": "y",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	if !strings.HasPrefix(resp.URL, f.srv.URL+"/auth?") {
		t.Errorf("unexpected base: %s", resp.URL)
	}
	if _, err := p.GetAuthURL(context.Background(), sso.AuthURLRequest{State: "st"}); err == nil {
		t.Fatal("missing nonce/verifier must fail")
	}
	if _, err := p.GetAuthURL(context.Background(), sso.AuthURLRequest{State: "s", Nonce: "n", CodeVerifier: "v", Scopes: []string{"openid"}}); err != nil {
		t.Fatal(err)
	}
}

func TestHandleCallbackSuccess(t *testing.T) {
	f := newFake(t)
	f.claims = f.goodClaims("n1")
	p := f.provider(t, func(c *Config) { c.HostedDomain = "Example.Test" })
	res, err := p.HandleCallback(context.Background(), cb("verifier", "n1"))
	if err != nil {
		t.Fatal(err)
	}
	if res.User.ID != "u1" || res.User.Email != testEmail || !res.User.EmailVerified || res.User.TenantID != "example.test" {
		t.Fatalf("user: %+v", res.User)
	}
	if res.Tokens.AccessToken != "at-1" || res.Tokens.RefreshToken != "rt-1" || res.Protocol != sso.ProtocolOIDC {
		t.Fatalf("tokens: %+v", res.Tokens)
	}
	g := f.gotForm
	if g.Get("code") != "code-1" || g.Get("code_verifier") != "verifier" || g.Get("redirect_uri") != testRedirect ||
		g.Get("grant_type") != "authorization_code" || g.Get("client_id") != testClientID || g.Get("client_secret") == "" {
		t.Fatalf("token form: %v", g)
	}
	// Second call reuses cached discovery and JWKS.
	if _, err := p.HandleCallback(context.Background(), cb("verifier", "n1")); err != nil || f.jwksHits.Load() != 1 {
		t.Fatalf("jwks hits %d err %v", f.jwksHits.Load(), err)
	}
}

func TestHandleCallbackRejections(t *testing.T) {
	type tc struct {
		name   string
		tweak  func(f *fakeGoogle, c map[string]any)
		req    sso.CallbackRequest
		domain string
		want   sso.SSOErrorCode
	}
	good := cb("v", "n1")
	cases := []tc{
		{"nonce mismatch", nil, cb("v", "other"), "", sso.ErrCodeStateMismatch},
		{"wrong audience", func(_ *fakeGoogle, c map[string]any) { c["aud"] = "someone-else" }, good, "", sso.ErrCodeInvalidToken},
		{"wrong issuer", func(_ *fakeGoogle, c map[string]any) { c["iss"] = "https://evil.test" }, good, "", sso.ErrCodeInvalidToken},
		{"expired", func(_ *fakeGoogle, c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }, good, "", sso.ErrCodeTokenExpired},
		{"missing exp", func(_ *fakeGoogle, c map[string]any) { delete(c, "exp") }, good, "", sso.ErrCodeTokenExpired},
		{"not yet valid", func(_ *fakeGoogle, c map[string]any) { c["nbf"] = time.Now().Add(time.Hour).Unix() }, good, "", sso.ErrCodeInvalidToken},
		{"no subject", func(_ *fakeGoogle, c map[string]any) { delete(c, "sub") }, good, "", sso.ErrCodeInvalidToken},
		{"wrong domain", nil, good, "other.test", sso.ErrCodeUnauthorized},
		{"missing hd", func(_ *fakeGoogle, c map[string]any) { delete(c, "hd") }, good, "example.test", sso.ErrCodeUnauthorized},
		{"idp error", nil, sso.CallbackRequest{Error: "access_denied"}, "", sso.ErrCodeIdPRejected},
		{"no code", nil, sso.CallbackRequest{CodeVerifier: "v", Nonce: "n1"}, "", sso.ErrCodeIdPRejected},
		{"no verifier", nil, sso.CallbackRequest{Code: "c"}, "", sso.ErrCodeStateMismatch},
		{"no id token", func(f *fakeGoogle, _ map[string]any) { f.noID = true }, good, "", sso.ErrCodeIdPRejected},
		{"token endpoint error", func(f *fakeGoogle, _ map[string]any) { f.tokenErr = "invalid_grant" }, good, "", sso.ErrCodeIdPRejected},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake(t)
			claims := f.goodClaims("n1")
			if c.tweak != nil {
				c.tweak(f, claims)
			}
			f.claims = claims
			p := f.provider(t, func(cfg *Config) { cfg.HostedDomain = c.domain })
			_, err := p.HandleCallback(context.Background(), c.req)
			if err == nil {
				t.Fatal("expected error")
			}
			if got := code(t, err); got != c.want {
				t.Fatalf("code %s, want %s (%v)", got, c.want, err)
			}
		})
	}
}

func TestBadSignatureAndAlgorithms(t *testing.T) {
	f := newFake(t)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	p := f.provider(t, nil)
	ctx := context.Background()

	forged := f.signWith(t, other, testKid, "RS256", f.goodClaims("n"))
	if _, err := p.ValidateToken(ctx, forged); err == nil || code(t, err) != sso.ErrCodeSignatureInvalid {
		t.Fatalf("forged: %v", err)
	}
	for _, alg := range []string{"none", "HS256"} {
		tok := f.signWith(t, f.key, testKid, alg, f.goodClaims("n"))
		if _, err := p.ValidateToken(ctx, tok); err == nil || code(t, err) != sso.ErrCodeInvalidToken {
			t.Fatalf("alg %s accepted: %v", alg, err)
		}
	}
	hdr := b64([]byte(`{"alg":"RS256"}`))
	for _, bad := range []string{
		"", "a.b", "!!.!!.!!",
		b64([]byte("{}")) + ".!!.x",
		b64([]byte("{")) + "." + b64([]byte("{}")) + "." + b64([]byte("s")),
		hdr + "." + b64([]byte("[")) + "." + b64([]byte("s")),
		hdr + "." + b64([]byte("{}")) + ".!!",
	} {
		if _, err := p.ValidateToken(ctx, bad); err == nil || code(t, err) != sso.ErrCodeInvalidToken {
			t.Fatalf("malformed %q: %v", bad, err)
		}
	}
}

func TestValidateToken(t *testing.T) {
	f := newFake(t)
	p := f.provider(t, nil)
	cl := f.goodClaims("n")
	cl["aud"] = []string{"x", testClientID} // array audience
	c, err := p.ValidateToken(context.Background(), f.sign(t, cl))
	if err != nil || c.Subject != "u1" || c.Email != testEmail || c.TenantID != "example.test" {
		t.Fatalf("claims %+v err %v", c, err)
	}
	cl["aud"] = 5 // invalid type
	if _, err := p.ValidateToken(context.Background(), f.sign(t, cl)); err == nil {
		t.Fatal("invalid aud type must fail")
	}
	p2 := f.provider(t, func(c *Config) { c.HostedDomain = "nope.test" })
	if _, err := p2.ValidateToken(context.Background(), f.sign(t, f.goodClaims("n"))); err == nil || code(t, err) != sso.ErrCodeUnauthorized {
		t.Fatalf("domain: %v", err)
	}
}

func TestIssuerAlternateForm(t *testing.T) {
	d := &discovery{Issuer: googleIssuer}
	if !d.issuerAccepted("accounts.google.com") || !d.issuerAccepted(googleIssuer) || d.issuerAccepted("x") {
		t.Fatal("issuer rules wrong")
	}
	if (&discovery{Issuer: "https://other"}).issuerAccepted("accounts.google.com") {
		t.Fatal("alt form must only apply to Google")
	}
}

func TestJWKRotationAndRateLimit(t *testing.T) {
	f := newFake(t)
	p := f.provider(t, nil)
	now := time.Now()
	p.now = func() time.Time { return now }
	ctx := context.Background()
	if _, err := p.ValidateToken(ctx, f.sign(t, f.goodClaims("n"))); err != nil {
		t.Fatal(err)
	}
	// Token signed by a key the cached JWKS does not know. The server rotates
	// afterwards, so only a refetch can succeed.
	newKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	tok := f.signWith(t, newKey, "kid-2", "RS256", f.goodClaims("n"))
	f.key, f.kid = newKey, "kid-2"

	if _, err := p.ValidateToken(ctx, tok); err == nil {
		t.Fatal("unknown kid within gap should fail")
	}
	if f.jwksHits.Load() != 1 {
		t.Fatalf("jwks refetched too early: %d", f.jwksHits.Load())
	}
	now = now.Add(2 * time.Minute) // past keyMinGap, before cache TTL
	if _, err := p.ValidateToken(ctx, tok); err != nil {
		t.Fatalf("rotated key not picked up: %v", err)
	}
	if f.jwksHits.Load() != 2 {
		t.Fatalf("jwks hits %d", f.jwksHits.Load())
	}
	// A kid that still does not exist after a refetch is rejected.
	now = now.Add(2 * time.Minute)
	unknown := f.signWith(t, newKey, "kid-3", "RS256", f.goodClaims("n"))
	if _, err := p.ValidateToken(ctx, unknown); err == nil || code(t, err) != sso.ErrCodeSignatureInvalid {
		t.Fatalf("unknown kid after refetch: %v", err)
	}
	// After the cache TTL, discovery and JWKS are fetched again.
	now = now.Add(2 * time.Hour)
	cl := f.goodClaims("n")
	cl["exp"] = now.Add(time.Hour).Unix()
	if _, err := p.ValidateToken(ctx, f.sign(t, cl)); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshToken(t *testing.T) {
	f := newFake(t)
	f.claims = f.goodClaims("n")
	p := f.provider(t, nil)
	tr, err := p.RefreshToken(context.Background(), "rt-1")
	if err != nil || tr.AccessToken != "at-1" || tr.RefreshToken != "rt-1" {
		t.Fatalf("refresh: %+v %v", tr, err)
	}
	if f.gotForm.Get("grant_type") != "refresh_token" || f.gotForm.Get("refresh_token") != "rt-1" {
		t.Fatalf("form %v", f.gotForm)
	}
	if _, err := p.RefreshToken(context.Background(), ""); err == nil {
		t.Fatal("empty refresh token must fail")
	}
	f.claims = map[string]any{"iss": "https://evil.test", "aud": testClientID, "sub": "u", "exp": time.Now().Add(time.Hour).Unix()}
	if _, err := p.RefreshToken(context.Background(), "rt-1"); err == nil {
		t.Fatal("bad id token in refresh must fail")
	}
	f.tokenErr = "invalid_grant"
	if _, err := p.RefreshToken(context.Background(), "rt-1"); err == nil || code(t, err) != sso.ErrCodeIdPRejected {
		t.Fatalf("rejected refresh: %v", err)
	}
}

func TestRevokeLogoutUserInfo(t *testing.T) {
	f := newFake(t)
	p := f.provider(t, nil)
	ctx := context.Background()

	if err := p.RevokeToken(ctx, "at-1"); err != nil {
		t.Fatal(err)
	}
	f.revoke = 400
	if err := p.RevokeToken(ctx, "at-1"); err == nil || code(t, err) != sso.ErrCodeIdPRejected {
		t.Fatalf("revoke failure: %v", err)
	}
	if _, err := p.GetLogoutURL(ctx, sso.LogoutRequest{}); err == nil || code(t, err) != sso.ErrCodeUnsupportedMethod {
		t.Fatalf("logout: %v", err)
	}

	u, err := p.FetchUserInfo(ctx, "at-1")
	if err != nil || u.ID != "u1" || u.Email != testEmail || !u.EmailVerified || u.TenantID != "example.test" {
		t.Fatalf("userinfo %+v %v", u, err)
	}
	if _, err := p.FetchUserInfo(ctx, "bad"); err == nil || code(t, err) != sso.ErrCodeInvalidToken {
		t.Fatalf("bad token: %v", err)
	}
	if _, err := p.FetchUserInfo(ctx, ""); err == nil {
		t.Fatal("empty token must fail")
	}
}

func TestMissingEndpointsAdvertised(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": "i", "authorization_endpoint": "a", "token_endpoint": "t", "jwks_uri": "j"})
	}))
	defer srv.Close()
	p, _ := New(Config{ClientID: testClientID, ClientSecret: "x", RedirectURL: testRedirect, DiscoveryURL: srv.URL})
	if err := p.RevokeToken(context.Background(), "t"); err == nil || code(t, err) != sso.ErrCodeUnsupportedMethod {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := p.FetchUserInfo(context.Background(), "t"); err == nil || code(t, err) != sso.ErrCodeUnsupportedMethod {
		t.Fatalf("userinfo: %v", err)
	}
}

func TestDiscoveryFailures(t *testing.T) {
	ctx := context.Background()
	mk := func(h http.HandlerFunc) *Provider {
		srv := httptest.NewServer(h)
		t.Cleanup(srv.Close)
		p, _ := New(Config{ClientID: testClientID, ClientSecret: "x", RedirectURL: testRedirect, DiscoveryURL: srv.URL})
		return p
	}
	cases := map[string]http.HandlerFunc{
		"500":        func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) },
		"bad json":   func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{")) },
		"incomplete": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"issuer":"x"}`)) },
	}
	for name, h := range cases {
		p := mk(h)
		if _, err := p.GetAuthURL(ctx, sso.AuthURLRequest{State: "s", Nonce: "n", CodeVerifier: "v"}); err == nil || code(t, err) != sso.ErrCodeNetworkFailure {
			t.Errorf("%s: %v", name, err)
		}
	}
	p, _ := New(Config{ClientID: testClientID, ClientSecret: "x", RedirectURL: testRedirect, DiscoveryURL: "http://127.0.0.1:1/x"})
	if _, err := p.RefreshToken(ctx, "r"); err == nil || code(t, err) != sso.ErrCodeNetworkFailure {
		t.Fatalf("unreachable: %v", err)
	}
}

func TestJWKPublicKeyErrors(t *testing.T) {
	bad := []jwk{
		{Kty: "EC"},
		{Kty: "RSA", N: "!!", E: "AQAB"},
		{Kty: "RSA", N: "AQAB", E: "!!"},
		{Kty: "RSA", N: "AQAB", E: b64([]byte{1})}, // exponent 1
	}
	for i, k := range bad {
		if _, err := k.publicKey(); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
	if _, err := (jwk{Kty: "RSA", N: "AQAB", E: "AQAB"}).publicKey(); err != nil {
		t.Fatal(err)
	}
}

func TestEndToEndWithManager(t *testing.T) {
	f := newFake(t)
	p := f.provider(t, nil)
	signer, _ := sso.NewStateSigner([]byte(strings.Repeat("k", 32)), time.Minute)
	m := sso.NewManager(sso.NewMemoryCache(time.Minute), signer, time.Minute)
	if err := m.Register(p); err != nil {
		t.Fatal(err)
	}
	resp, err := m.BeginLogin(context.Background(), "google", sso.AuthURLRequest{})
	if err != nil {
		t.Fatal(err)
	}
	f.claims = f.goodClaims(resp.Nonce)
	res, err := m.CompleteLogin(context.Background(), "google", sso.CallbackRequest{State: resp.State, Code: "c"})
	if err != nil || res.User.ID != "u1" {
		t.Fatalf("e2e: %+v %v", res, err)
	}
	if _, err := m.CompleteLogin(context.Background(), "google", sso.CallbackRequest{State: resp.State, Code: "c"}); err == nil {
		t.Fatal("replay must fail")
	}
}
