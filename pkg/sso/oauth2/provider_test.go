package oauth2_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/universal-sso/universal-sso/pkg/sso"
	"github.com/universal-sso/universal-sso/pkg/sso/oauth2"
	"github.com/universal-sso/universal-sso/pkg/sso/oauth2/oauth2test"
)

const (
	clientID = "client-1"
	secret   = "s3cret/with+odd:chars" // nosecret: synthetic test value
	redirect = "http://localhost:8080/auth/oauth2/callback"
)

// setup starts the fake and returns a provider wired to it.
func setup(t *testing.T, mut func(*oauth2.Config)) (*oauth2.Provider, *oauth2test.Fake, string) {
	t.Helper()
	fake := oauth2test.New(clientID, secret)
	srv := httptest.NewServer(fake.Handler())
	t.Cleanup(srv.Close)
	cfg := oauth2.Config{
		ClientID: clientID, ClientSecret: secret, RedirectURL: redirect,
		AuthURL: srv.URL + "/authorize", TokenURL: srv.URL + "/token", UserinfoURL: srv.URL + "/user",
		RevokeURL: srv.URL + "/revoke", Scopes: []string{"read:user", "user:email"},
	}
	if mut != nil {
		mut(&cfg)
	}
	p, err := oauth2.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p, fake, srv.URL
}

// login runs the authorize leg against the fake and returns the callback request.
func login(t *testing.T, p *oauth2.Provider, verifier string) sso.CallbackRequest {
	t.Helper()
	au, err := p.GetAuthURL(context.Background(), sso.AuthURLRequest{State: "st-1", CodeVerifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(au.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status %d", resp.StatusCode)
	}
	loc, _ := resp.Location()
	if loc.Query().Get("state") != "st-1" {
		t.Fatalf("state not echoed: %s", loc)
	}
	return sso.CallbackRequest{State: "st-1", Code: loc.Query().Get("code"), CodeVerifier: verifier}
}

func wantCode(t *testing.T, err error, code sso.SSOErrorCode) {
	t.Helper()
	var se *sso.SSOError
	if !errors.As(err, &se) || se.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
}

func TestMetadata(t *testing.T) {
	p, _, _ := setup(t, nil)
	if p.ID() != "oauth2" || p.Name() != "OAuth 2.0" || p.Protocol() != sso.ProtocolOAuth2 {
		t.Fatalf("unexpected identity: %s %s %s", p.ID(), p.Name(), p.Protocol())
	}
}

func TestNewValidation(t *testing.T) {
	good := oauth2.Config{
		ClientID: "a", ClientSecret: "b", RedirectURL: "https://app.example.com/cb",
		AuthURL: "https://idp.example.com/a", TokenURL: "https://idp.example.com/t", UserinfoURL: "https://idp.example.com/u",
	}
	if _, err := oauth2.New(good); err != nil {
		t.Fatalf("good config rejected: %v", err)
	}
	cases := map[string]func(*oauth2.Config){
		"no client id":     func(c *oauth2.Config) { c.ClientID = "" },
		"no secret":        func(c *oauth2.Config) { c.ClientSecret = "" },
		"no redirect":      func(c *oauth2.Config) { c.RedirectURL = "" },
		"no auth url":      func(c *oauth2.Config) { c.AuthURL = "" },
		"no token url":     func(c *oauth2.Config) { c.TokenURL = "" },
		"no userinfo url":  func(c *oauth2.Config) { c.UserinfoURL = "" },
		"http auth url":    func(c *oauth2.Config) { c.AuthURL = "http://idp.example.com/a" },
		"http token url":   func(c *oauth2.Config) { c.TokenURL = "http://idp.example.com/t" },
		"http profile url": func(c *oauth2.Config) { c.UserinfoURL = "http://idp.example.com/u" },
		"http redirect":    func(c *oauth2.Config) { c.RedirectURL = "http://app.example.com/cb" },
		"http revoke url":  func(c *oauth2.Config) { c.RevokeURL = "http://idp.example.com/r" },
		"bad auth style":   func(c *oauth2.Config) { c.AuthStyle = "digest" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			c := good
			mut(&c)
			_, err := oauth2.New(c)
			wantCode(t, err, sso.ErrCodeInvalidConfig)
		})
	}
	// Plain http is fine for loopback, so local development works.
	c := good
	c.AuthURL, c.TokenURL, c.UserinfoURL = "http://127.0.0.1:1/a", "http://localhost:1/t", "http://[::1]:1/u"
	if _, err := oauth2.New(c); err != nil {
		t.Fatalf("loopback http rejected: %v", err)
	}
}

func TestGetAuthURL(t *testing.T) {
	p, _, base := setup(t, nil)
	au, err := p.GetAuthURL(context.Background(), sso.AuthURLRequest{
		State: "st", CodeVerifier: "verifier-1",
		ExtraParams: map[string]string{"state": "evil", "client_id": "evil", "allow_signup": "false"},
	})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(au.URL)
	if !strings.HasPrefix(au.URL, base+"/authorize?") {
		t.Fatalf("unexpected url %s", au.URL)
	}
	q := u.Query()
	want := map[string]string{
		"response_type": "code", "client_id": clientID, "redirect_uri": redirect, "scope": "read:user user:email",
		"state": "st", "code_challenge": sso.CodeChallengeS256("verifier-1"), "code_challenge_method": "S256",
		"allow_signup": "false",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	if q.Has("nonce") {
		t.Error("plain OAuth 2.0 must not send a nonce")
	}
}

func TestGetAuthURLRequiresStateAndVerifier(t *testing.T) {
	p, _, _ := setup(t, nil)
	for _, req := range []sso.AuthURLRequest{{CodeVerifier: "v"}, {State: "s"}} {
		_, err := p.GetAuthURL(context.Background(), req)
		wantCode(t, err, sso.ErrCodeInvalidConfig)
	}
}

func TestGetAuthURLKeepsProviderQueryAndOverridesSecurityParams(t *testing.T) {
	p, _, _ := setup(t, func(c *oauth2.Config) { c.AuthURL += "?tenant=acme&state=old" })
	au, err := p.GetAuthURL(context.Background(), sso.AuthURLRequest{State: "new", CodeVerifier: "v", Scopes: []string{"only"}})
	if err != nil {
		t.Fatal(err)
	}
	q := mustQuery(t, au.URL)
	if q.Get("tenant") != "acme" || q.Get("state") != "new" || q.Get("scope") != "only" {
		t.Fatalf("query = %v", q)
	}
}

func mustQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

func TestNoScopes(t *testing.T) {
	p, _, _ := setup(t, func(c *oauth2.Config) { c.Scopes = nil })
	au, _ := p.GetAuthURL(context.Background(), sso.AuthURLRequest{State: "s", CodeVerifier: "v"})
	if mustQuery(t, au.URL).Has("scope") {
		t.Fatal("scope must be omitted when none is configured")
	}
}

func TestHandleCallbackSuccess(t *testing.T) {
	p, fake, _ := setup(t, nil)
	res, err := p.HandleCallback(context.Background(), login(t, p, "verifier-1"))
	if err != nil {
		t.Fatal(err)
	}
	if res.ProviderID != "oauth2" || res.Protocol != sso.ProtocolOAuth2 {
		t.Fatalf("result = %+v", res)
	}
	u := res.User
	if u.ID != "4242" {
		t.Errorf("numeric id must be kept exact, got %q", u.ID)
	}
	if u.Username != "octo" || u.DisplayName != "Octo Cat" || u.Email != "octo@example.com" {
		t.Errorf("user = %+v", u)
	}
	if u.EmailVerified {
		t.Error("plain OAuth 2.0 cannot say an email is verified")
	}
	if got := u.RawAttributes["id"]; got != int64(4242) {
		t.Errorf("raw id = %#v", got)
	}
	if res.Tokens.AccessToken != oauth2test.AccessToken || res.Tokens.RefreshToken != "rt-oauth2-1" || res.Tokens.ExpiresIn != 3600 || res.Tokens.ExpiresAt.IsZero() {
		t.Errorf("tokens = %+v", res.Tokens)
	}
	// Token request: PKCE verifier and the same redirect_uri as the authorization request.
	form := fake.TokenForm()
	if form.Get("code_verifier") != "verifier-1" || form.Get("redirect_uri") != redirect || form.Get("grant_type") != "authorization_code" {
		t.Errorf("token form = %v", form)
	}
	if form.Has("client_secret") {
		t.Error("basic auth must not also send the secret in the body")
	}
	if got := fake.UserAuthHeader(); got != "Bearer "+oauth2test.AccessToken {
		t.Errorf("profile auth header = %q", got)
	}
}

func TestBasicAuthEncodesCredentials(t *testing.T) {
	p, fake, _ := setup(t, nil)
	if _, err := p.HandleCallback(context.Background(), login(t, p, "v")); err != nil {
		t.Fatal(err)
	}
	if h := fake.TokenAuthHeader(); !strings.HasPrefix(h, "Basic ") {
		t.Fatalf("auth header = %q", h)
	}
}

func TestPostAuthStyle(t *testing.T) {
	p, fake, _ := setup(t, func(c *oauth2.Config) { c.AuthStyle = oauth2.AuthPost })
	fake.Set(func(f *oauth2test.Fake) { f.Style = "post" })
	if _, err := p.HandleCallback(context.Background(), login(t, p, "v")); err != nil {
		t.Fatal(err)
	}
	form := fake.TokenForm()
	if form.Get("client_secret") != secret || form.Get("client_id") != clientID {
		t.Errorf("form = %v", form)
	}
	if fake.TokenAuthHeader() != "" {
		t.Error("post style must not send a Basic header")
	}
}

func TestWrongStyleIsRejectedAsInvalidClient(t *testing.T) {
	p, fake, _ := setup(t, nil) // provider sends basic
	fake.Set(func(f *oauth2test.Fake) { f.Style = "post" })
	_, err := p.HandleCallback(context.Background(), login(t, p, "v"))
	wantCode(t, err, sso.ErrCodeIdPRejected)
	if !strings.Contains(err.Error(), "invalid_client") {
		t.Fatalf("error should name invalid_client: %v", err)
	}
}

func TestWrongSecret(t *testing.T) {
	p, _, _ := setup(t, func(c *oauth2.Config) { c.ClientSecret = "wrong" })
	_, err := p.HandleCallback(context.Background(), login(t, p, "v"))
	wantCode(t, err, sso.ErrCodeIdPRejected)
}

func TestCodeIsSingleUse(t *testing.T) {
	p, _, _ := setup(t, nil)
	cb := login(t, p, "v")
	if _, err := p.HandleCallback(context.Background(), cb); err != nil {
		t.Fatal(err)
	}
	_, err := p.HandleCallback(context.Background(), cb)
	wantCode(t, err, sso.ErrCodeIdPRejected)
	if !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("replay should be invalid_grant: %v", err)
	}
}

func TestWrongPKCEVerifier(t *testing.T) {
	p, _, _ := setup(t, nil)
	cb := login(t, p, "right")
	cb.CodeVerifier = "wrong"
	_, err := p.HandleCallback(context.Background(), cb)
	wantCode(t, err, sso.ErrCodeIdPRejected)
}

func TestCallbackInputErrors(t *testing.T) {
	p, _, _ := setup(t, nil)
	ctx := context.Background()
	_, err := p.HandleCallback(ctx, sso.CallbackRequest{Error: "access_denied", ErrorDesc: "user said no"})
	wantCode(t, err, sso.ErrCodeIdPRejected)
	if !strings.Contains(err.Error(), "access_denied") {
		t.Errorf("error = %v", err)
	}
	_, err = p.HandleCallback(ctx, sso.CallbackRequest{CodeVerifier: "v"})
	wantCode(t, err, sso.ErrCodeIdPRejected)
	_, err = p.HandleCallback(ctx, sso.CallbackRequest{Code: "c"})
	wantCode(t, err, sso.ErrCodeStateMismatch)
}

func TestTokenEndpointFailures(t *testing.T) {
	cases := map[string]struct {
		set  func(*oauth2test.Fake)
		code sso.SSOErrorCode
		text string
	}{
		"error with status 400": {func(f *oauth2test.Fake) { f.FailToken("invalid_scope", 400) }, sso.ErrCodeIdPRejected, "invalid_scope"},
		"error with status 200": {func(f *oauth2test.Fake) { f.FailToken("bad_verification_code", 200) }, sso.ErrCodeIdPRejected, "bad_verification_code"},
		"form encoded reply":    {func(f *oauth2test.Fake) { f.FormReply() }, sso.ErrCodeNetworkFailure, "not JSON"},
		"non bearer token type": {func(f *oauth2test.Fake) { f.TokenType("mac") }, sso.ErrCodeIdPRejected, "token type"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p, fake, _ := setup(t, nil)
			cb := login(t, p, "v")
			tc.set(fake) // the helpers lock the fake themselves
			_, err := p.HandleCallback(context.Background(), cb)
			wantCode(t, err, tc.code)
			if !strings.Contains(err.Error(), tc.text) {
				t.Fatalf("want %q in %v", tc.text, err)
			}
		})
	}
}

func TestTokenTypeIsCaseInsensitive(t *testing.T) {
	p, fake, _ := setup(t, nil)
	cb := login(t, p, "v")
	fake.TokenType("Bearer")
	if _, err := p.HandleCallback(context.Background(), cb); err != nil {
		t.Fatal(err)
	}
}

func TestMissingExpiryIsUnknownNotInvented(t *testing.T) {
	p, fake, _ := setup(t, nil)
	cb := login(t, p, "v")
	fake.OmitExpiry()
	res, err := p.HandleCallback(context.Background(), cb)
	if err != nil {
		t.Fatal(err)
	}
	if res.Tokens.ExpiresIn != 0 || !res.Tokens.ExpiresAt.IsZero() {
		t.Fatalf("expiry must stay unknown: %+v", res.Tokens)
	}
}

func TestProfileFailures(t *testing.T) {
	cases := map[string]struct {
		set  func(*oauth2test.Fake)
		code sso.SSOErrorCode
	}{
		"401": {func(f *oauth2test.Fake) { f.UserStatus(401) }, sso.ErrCodeInvalidToken},
		"403": {func(f *oauth2test.Fake) { f.UserStatus(403) }, sso.ErrCodeInvalidToken},
		"500": {func(f *oauth2test.Fake) { f.UserStatus(500) }, sso.ErrCodeNetworkFailure},
		"missing id field": {func(f *oauth2test.Fake) {
			f.Set(func(f *oauth2test.Fake) { f.Profile = map[string]any{"login": "x"} })
		}, sso.ErrCodeInvalidToken},
		"id is an object": {func(f *oauth2test.Fake) {
			f.Set(func(f *oauth2test.Fake) { f.Profile = map[string]any{"id": map[string]any{"a": 1}} })
		}, sso.ErrCodeInvalidToken},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p, fake, _ := setup(t, nil)
			cb := login(t, p, "v")
			tc.set(fake)
			_, err := p.HandleCallback(context.Background(), cb)
			wantCode(t, err, tc.code)
		})
	}
}

func TestCustomUserIDFieldAndFallbacks(t *testing.T) {
	p, fake, _ := setup(t, func(c *oauth2.Config) { c.UserIDField = "uuid" })
	cb := login(t, p, "v")
	fake.Set(func(f *oauth2test.Fake) {
		f.Profile = map[string]any{"uuid": "u-1", "email": "who@example.com", "first_name": "Who", "last_name": "Ever", "display_name": "Who Ever", "picture": "https://img.example.com/p.png"}
	})
	res, err := p.HandleCallback(context.Background(), cb)
	if err != nil {
		t.Fatal(err)
	}
	u := res.User
	if u.ID != "u-1" || u.Username != "who@example.com" || u.FirstName != "Who" || u.LastName != "Ever" ||
		u.DisplayName != "Who Ever" || u.AvatarURL != "https://img.example.com/p.png" {
		t.Fatalf("user = %+v", u)
	}
}

func TestFloatIDsKeepTheirText(t *testing.T) {
	p, fake, _ := setup(t, nil)
	cb := login(t, p, "v")
	fake.Set(func(f *oauth2test.Fake) { f.Profile = map[string]any{"id": 1.5, "n": 7} })
	res, err := p.HandleCallback(context.Background(), cb)
	if err != nil {
		t.Fatal(err)
	}
	if res.User.ID != "1.5" || res.User.RawAttributes["n"] != int64(7) || res.User.RawAttributes["id"] != 1.5 {
		t.Fatalf("user = %+v", res.User)
	}
}

func TestFetchUserInfoAndValidateToken(t *testing.T) {
	p, _, _ := setup(t, nil)
	ctx := context.Background()
	u, err := p.FetchUserInfo(ctx, oauth2test.AccessToken)
	if err != nil || u.ID != "4242" {
		t.Fatalf("FetchUserInfo = %+v, %v", u, err)
	}
	c, err := p.ValidateToken(ctx, oauth2test.AccessToken)
	if err != nil || c.Subject != "4242" || c.Email != "octo@example.com" {
		t.Fatalf("ValidateToken = %+v, %v", c, err)
	}
	for _, fn := range []func() error{
		func() error { _, e := p.FetchUserInfo(ctx, ""); return e },
		func() error { _, e := p.ValidateToken(ctx, ""); return e },
		func() error { _, e := p.FetchUserInfo(ctx, "bad-token"); return e },
		func() error { _, e := p.ValidateToken(ctx, "bad-token"); return e },
	} {
		wantCode(t, fn(), sso.ErrCodeInvalidToken)
	}
}

func TestRefreshToken(t *testing.T) {
	p, fake, _ := setup(t, nil)
	ctx := context.Background()
	tr, err := p.RefreshToken(ctx, "rt-oauth2-1")
	if err != nil {
		t.Fatal(err)
	}
	if tr.AccessToken != oauth2test.AccessToken || tr.RefreshToken != "rt-oauth2-1" {
		t.Fatalf("tokens = %+v", tr) // the refresh token is carried over when not rotated
	}
	if fake.TokenForm().Get("grant_type") != "refresh_token" {
		t.Fatalf("form = %v", fake.TokenForm())
	}
	_, err = p.RefreshToken(ctx, "")
	wantCode(t, err, sso.ErrCodeInvalidToken)
	_, err = p.RefreshToken(ctx, "unknown")
	wantCode(t, err, sso.ErrCodeIdPRejected)
}

func TestRevokeToken(t *testing.T) {
	p, fake, _ := setup(t, nil)
	ctx := context.Background()
	if err := p.RevokeToken(ctx, "tok"); err != nil {
		t.Fatal(err)
	}
	if fake.RevokeForm().Get("token") != "tok" {
		t.Fatalf("form = %v", fake.RevokeForm())
	}
	fake.RevokeStatus(500)
	wantCode(t, p.RevokeToken(ctx, "tok"), sso.ErrCodeIdPRejected)

	noRevoke, _, _ := setup(t, func(c *oauth2.Config) { c.RevokeURL = "" })
	wantCode(t, noRevoke.RevokeToken(ctx, "tok"), sso.ErrCodeUnsupportedMethod)
}

func TestRevokeTokenPostStyle(t *testing.T) {
	p, fake, _ := setup(t, func(c *oauth2.Config) { c.AuthStyle = oauth2.AuthPost })
	if err := p.RevokeToken(context.Background(), "tok"); err != nil {
		t.Fatal(err)
	}
	if fake.RevokeForm().Get("client_secret") != secret {
		t.Fatalf("form = %v", fake.RevokeForm())
	}
}

func TestLogoutIsUnsupported(t *testing.T) {
	p, _, _ := setup(t, nil)
	_, err := p.GetLogoutURL(context.Background(), sso.LogoutRequest{})
	wantCode(t, err, sso.ErrCodeUnsupportedMethod)
}

func TestNetworkFailure(t *testing.T) {
	p, _, _ := setup(t, func(c *oauth2.Config) {
		c.TokenURL = "http://127.0.0.1:1/token" // nothing listens on port 1
		c.UserinfoURL = "http://127.0.0.1:1/user"
	})
	cb := login(t, p, "v")
	_, err := p.HandleCallback(context.Background(), cb)
	wantCode(t, err, sso.ErrCodeNetworkFailure)
	_, err = p.FetchUserInfo(context.Background(), "t")
	wantCode(t, err, sso.ErrCodeNetworkFailure)
}

func TestProfileNotJSONObject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) }))
	defer srv.Close()
	p, _, _ := setup(t, func(c *oauth2.Config) { c.UserinfoURL = srv.URL })
	_, err := p.FetchUserInfo(context.Background(), "t")
	wantCode(t, err, sso.ErrCodeNetworkFailure)
}

func TestTokenReplyWithoutAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token_type":"bearer"}`))
	}))
	defer srv.Close()
	p, _, _ := setup(t, func(c *oauth2.Config) { c.TokenURL = srv.URL })
	_, err := p.HandleCallback(context.Background(), sso.CallbackRequest{Code: "c", CodeVerifier: "v"})
	wantCode(t, err, sso.ErrCodeIdPRejected)
}

func TestTokenEndpointNonJSONError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("upstream down"))
	}))
	defer srv.Close()
	p, _, _ := setup(t, func(c *oauth2.Config) { c.TokenURL = srv.URL })
	_, err := p.HandleCallback(context.Background(), sso.CallbackRequest{Code: "c", CodeVerifier: "v"})
	wantCode(t, err, sso.ErrCodeIdPRejected)
}

func TestDriverRegistered(t *testing.T) {
	found := false
	for _, d := range sso.Drivers() {
		found = found || d == "oauth2"
	}
	if !found {
		t.Fatal("oauth2 driver not registered")
	}
	cfg := map[string]string{
		"client_id": "a", "client_secret": "b", "redirect_url": "https://app.example.com/cb",
		"auth_url": "https://idp.example.com/a", "token_url": "https://idp.example.com/t", "userinfo_url": "https://idp.example.com/u",
		"scopes": "x y", "user_id_field": "sub", "auth_style": "post",
	}
	p, err := sso.NewProvider("oauth2", cfg)
	if err != nil || p.ID() != "oauth2" {
		t.Fatalf("NewProvider = %v, %v", p, err)
	}
	delete(cfg, "token_url")
	if _, err := sso.NewProvider("oauth2", cfg); err == nil {
		t.Fatal("incomplete config must fail")
	}
}
