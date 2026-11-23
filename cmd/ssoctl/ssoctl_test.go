package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/universal-sso/universal-sso/pkg/sso"
)

const goodID = "1234567890" + "12-abcdef0123456789" + ".apps.googleusercontent" + ".com"

func goodEnv() map[string]string {
	return map[string]string{
		envClientID:    goodID,
		envSecret:      "GOCSPX-" + strings.Repeat("a", 28),
		envRedirect:    "http://localhost:8080/auth/google/callback",
		envBaseURL:     "http://localhost:8080",
		envStateSecret: strings.Repeat("k", 40),
	}
}

func levels(fs []Finding) (fail, warn int) {
	for _, f := range fs {
		switch f.Level {
		case Fail:
			fail++
		case Warn:
			warn++
		}
	}
	return
}

func TestParseEnv(t *testing.T) {
	env, err := parseEnv(strings.NewReader("# c\n\nA=1\nexport B=\"two words\"\nC='x'\nD=a=b\r\nnoequals\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"A": "1", "B": "two words", "C": "x", "D": "a=b"}
	for k, v := range want {
		if env[k] != v {
			t.Fatalf("%s=%q want %q", k, env[k], v)
		}
	}
}

func TestGoodConfigPasses(t *testing.T) {
	fail, warn := levels(checkGoogleEnv(goodEnv()))
	if fail != 0 || warn != 0 {
		t.Fatalf("fail=%d warn=%d: %+v", fail, warn, checkGoogleEnv(goodEnv()))
	}
}

// The real-world mistake: the secret pasted into the Client ID field.
func TestClientIDHoldingASecretIsDiagnosed(t *testing.T) {
	f := checkClientID("GOCSPX-abc123" + clientIDSuffix)
	if f.Level != Fail || !strings.Contains(f.Msg, "SECRET") {
		t.Fatalf("%+v", f)
	}
}

func TestClientIDCases(t *testing.T) {
	for in, want := range map[string]Level{
		"":                               Fail,
		"google-client-id-placeholder":   Fail,
		"12345-abc":                      Fail,
		"abc.apps.googleusercontent.com": Fail,
		goodID:                           OK,
	} {
		if got := checkClientID(in).Level; got != want {
			t.Fatalf("%q: got %s want %s", in, got, want)
		}
	}
}

func TestSecretCases(t *testing.T) {
	for in, want := range map[string]Level{
		"":                                  Fail,
		"google-client-secret-placeholder":  Fail,
		goodID:                              Fail,
		"legacysecretvalue":                 Warn,
		"GOCSPX-has space":                  Fail,
		"GOCSPX-" + strings.Repeat("b", 28): OK,
	} {
		if got := checkSecret(in).Level; got != want {
			t.Fatalf("%q: got %s want %s", in, got, want)
		}
	}
}

func TestRedirectRules(t *testing.T) {
	cases := map[string]Level{
		"http://localhost:8080/auth/google/callback":   OK,
		"http://127.0.0.1:8080/auth/google/callback":   Warn, // differs from base URL
		"https://sso.example.com/auth/google/callback": Warn, // differs from base URL
		"http://sso.example.com/auth/google/callback":  Fail, // http not localhost
		"https://203.0.113.5/auth/google/callback":     Fail, // raw IP
		"https://user:pw@sso.example.com/cb":           Fail, // userinfo // nosecret
		"https://sso.example.com/cb#frag":              Fail,
		"https://*.example.com/cb":                     Fail,
		"https://sso.example.com/a/../cb":              Fail,
		"not a url":                                    Fail,
		"":                                             Fail,
	}
	for in, want := range cases {
		fs := checkRedirect(in, "http://localhost:8080")
		fail, warn := levels(fs)
		got := OK
		if fail > 0 {
			got = Fail
		} else if warn > 0 {
			got = Warn
		}
		if got != want {
			t.Fatalf("%q: got %s want %s (%+v)", in, got, want, fs)
		}
	}
	if fail, warn := levels(checkRedirect("http://localhost:8080/auth/google/callback/", "")); fail != 0 || warn == 0 {
		t.Fatal("trailing slash should warn")
	}
}

func TestStateSecretCases(t *testing.T) {
	if checkStateSecret("short").Level != Fail {
		t.Fatal("short must fail")
	}
	if checkStateSecret("change-this-super-secret-key-32bytes-min!").Level != Warn {
		t.Fatal("placeholder must warn")
	}
	if checkStateSecret(strings.Repeat("k", 40)).Level != OK {
		t.Fatal("good must pass")
	}
}

func TestBuildAuthURL(t *testing.T) {
	s := &pkceSession{State: "st", Nonce: "nn", Verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}
	u, err := url.Parse(buildAuthURL(goodEnv(), s))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("code_challenge") != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" || q.Get("code_challenge_method") != "S256" ||
		q.Get("client_id") != goodID || q.Get("redirect_uri") != goodEnv()[envRedirect] ||
		q.Get("scope") != "openid email profile" || q.Get("response_type") != "code" || q.Get("state") != "st" {
		t.Fatalf("unexpected query: %v", q)
	}
}

func TestExtractCode(t *testing.T) {
	c, s, err := extractCode("http://localhost:8080/auth/google/callback?state=S1&code=4%2FabC&scope=openid")
	if err != nil || c != "4/abC" || s != "S1" {
		t.Fatalf("%q %q %v", c, s, err)
	}
	if c, s, _ := extractCode("4/rawcode"); c != "4/rawcode" || s != "" {
		t.Fatal("bare code")
	}
	if _, _, err := extractCode("http://x/cb?error=access_denied"); err == nil || !strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("error param: %v", err)
	}
	if _, _, err := extractCode("  "); err == nil {
		t.Fatal("empty must error")
	}
}

func jwt(claims map[string]any) string {
	b, _ := json.Marshal(claims)
	return "e30." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
}

func fakeGoogle(t *testing.T, claims map[string]any, wantVerifier string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.PostForm.Get("code") == "used":
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Bad Request"}`))
		case r.PostForm.Get("client_secret") == "" || r.PostForm.Get("code_verifier") != wantVerifier ||
			r.PostForm.Get("grant_type") != "authorization_code":
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"invalid_request"}`))
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"id_token": jwt(claims), "scope": "openid email", "expires_in": 3599, "access_token": "x"})
		}
	}))
	t.Cleanup(srv.Close)
	old := googleTokenURL
	googleTokenURL = srv.URL
	t.Cleanup(func() { googleTokenURL = old })
	return srv
}

func TestExchangeAndVerifyClaims(t *testing.T) {
	claims := map[string]any{"iss": "https://accounts.google.com", "aud": goodID, "sub": "1077",
		"exp": float64(time.Now().Add(time.Hour).Unix()), "nonce": "nn", "email_verified": true}
	fakeGoogle(t, claims, "ver")

	res, err := exchangeCode(t.Context(), http.DefaultClient, goodEnv(), "4/code", "ver")
	if err != nil {
		t.Fatal(err)
	}
	if fail, _ := levels(verifyClaims(res.Claims, goodID, "nn", time.Now())); fail != 0 {
		t.Fatalf("good claims failed: %+v", verifyClaims(res.Claims, goodID, "nn", time.Now()))
	}
	// Each tampered property must be caught.
	for name, tc := range map[string]struct{ aud, nonce string }{
		"wrong audience": {"other-client", "nn"},
		"wrong nonce":    {goodID, "different"},
	} {
		if fail, _ := levels(verifyClaims(res.Claims, tc.aud, tc.nonce, time.Now())); fail == 0 {
			t.Fatalf("%s not detected", name)
		}
	}
	if fail, _ := levels(verifyClaims(res.Claims, goodID, "nn", time.Now().Add(2*time.Hour))); fail == 0 {
		t.Fatal("expiry not detected")
	}
	bad := map[string]any{"iss": "https://evil.example", "aud": goodID, "exp": float64(time.Now().Add(time.Hour).Unix()), "nonce": "nn"}
	if fail, _ := levels(verifyClaims(bad, goodID, "nn", time.Now())); fail < 2 {
		t.Fatal("bad issuer and missing sub must both fail")
	}
}

func TestExchangeErrors(t *testing.T) {
	fakeGoogle(t, map[string]any{}, "ver")
	_, err := exchangeCode(t.Context(), http.DefaultClient, goodEnv(), "used", "ver")
	if err == nil || !strings.HasPrefix(err.Error(), "invalid_grant") {
		t.Fatalf("%v", err)
	}
	if !strings.Contains(hintFor(err), "7.4") {
		t.Fatal("hint should reference troubleshooting 7.4")
	}
	if _, err := exchangeCode(t.Context(), http.DefaultClient, goodEnv(), "4/code", "wrong-verifier"); err == nil {
		t.Fatal("verifier mismatch must fail")
	}
	if _, err := decodeJWTClaims("not-a-jwt"); err == nil {
		t.Fatal("bad jwt must fail")
	}
}

func TestDiscovery(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"https://accounts.google.com"}`))
	}))
	defer ok.Close()
	old := googleDiscoveryURL
	defer func() { googleDiscoveryURL = old }()
	googleDiscoveryURL = ok.URL
	if f := checkDiscovery(t.Context(), http.DefaultClient); f.Level != OK {
		t.Fatalf("%+v", f)
	}
	googleDiscoveryURL = "http://127.0.0.1:1/unreachable"
	if f := checkDiscovery(t.Context(), http.DefaultClient); f.Level != Warn {
		t.Fatalf("%+v", f)
	}
}

// End-to-end through run(): check -> url -> exchange, in a temp dir.
func TestCLIFlow(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	envFile := filepath.Join(dir, ".env")
	var sb strings.Builder
	for k, v := range goodEnv() {
		sb.WriteString(k + "=" + v + "\n")
	}
	if err := os.WriteFile(envFile, []byte(sb.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errb bytes.Buffer
	if rc := run([]string{"google", "check", "--env", envFile, "--offline"}, &out, &errb, http.DefaultClient); rc != 0 {
		t.Fatalf("check rc=%d\n%s%s", rc, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), goodEnv()[envRedirect]) {
		t.Fatal("check must print the redirect URI to register")
	}
	if strings.Contains(out.String(), goodEnv()[envSecret]) {
		t.Fatal("secret leaked to output")
	}

	out.Reset()
	if rc := run([]string{"google", "url", "--env", envFile}, &out, &errb, http.DefaultClient); rc != 0 {
		t.Fatalf("url rc=%d %s", rc, errb.String())
	}
	var s pkceSession
	raw, err := os.ReadFile(pkceFile)
	if err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(raw, &s)
	if st, _ := os.Stat(pkceFile); st.Mode().Perm() != 0o600 {
		t.Fatalf("pkce file mode %o", st.Mode().Perm())
	}

	claims := map[string]any{"iss": "accounts.google.com", "aud": goodID, "sub": "9",
		"exp": float64(time.Now().Add(time.Hour).Unix()), "nonce": s.Nonce}
	fakeGoogle(t, claims, s.Verifier)

	// wrong state is rejected before any network call
	out.Reset()
	errb.Reset()
	if rc := run([]string{"google", "exchange", "--env", envFile, "http://x/cb?code=c&state=forged"}, &out, &errb, http.DefaultClient); rc == 0 ||
		!strings.Contains(errb.String(), "STATE_MISMATCH") {
		t.Fatalf("forged state accepted: rc=%d %s", rc, errb.String())
	}

	out.Reset()
	errb.Reset()
	arg := "http://localhost:8080/auth/google/callback?state=" + url.QueryEscape(s.State) + "&code=4%2Fgood"
	if rc := run([]string{"google", "exchange", "--env", envFile, arg}, &out, &errb, http.DefaultClient); rc != 0 {
		t.Fatalf("exchange rc=%d\n%s%s", rc, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "configured correctly") {
		t.Fatal(out.String())
	}
	if _, err := os.Stat(pkceFile); err == nil {
		t.Fatal("pending login must be consumed after a successful exchange")
	}
	// a second attempt has no pending login
	if rc := run([]string{"google", "exchange", "--env", envFile, arg}, &out, &errb, http.DefaultClient); rc == 0 {
		t.Fatal("replay must fail")
	}
}

func TestCLIRejectsBadConfigAndUsage(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	envFile := filepath.Join(dir, ".env")
	// the real-world mistake: secret in the client-id field, placeholder secret
	_ = os.WriteFile(envFile, []byte("SSO_PROVIDERS_GOOGLE_CLIENT_ID=GOCSPX-abc.apps.googleusercontent.com\n"+
		"SSO_PROVIDERS_GOOGLE_CLIENT_SECRET=google-client-secret-placeholder\n"+
		"SSO_PROVIDERS_GOOGLE_REDIRECT_URL=http://localhost:8080/auth/google/callback\n"+
		"SSO_STATE_SECRET=change-this-super-secret-key-32bytes-min!\n"), 0o644)
	var out, errb bytes.Buffer
	if rc := run([]string{"google", "check", "--env", envFile, "--offline"}, &out, &errb, http.DefaultClient); rc != 1 {
		t.Fatalf("rc=%d", rc)
	}
	if !strings.Contains(out.String(), "SECRET, not a Client ID") || !strings.Contains(out.String(), "chmod 600") {
		t.Fatalf("missing diagnosis:\n%s", out.String())
	}
	if rc := run([]string{"google", "url", "--env", envFile}, &out, &errb, http.DefaultClient); rc != 1 {
		t.Fatal("url must refuse a bad config")
	}
	if rc := run([]string{"google", "check", "--env", filepath.Join(dir, "missing")}, &out, &errb, http.DefaultClient); rc != 1 {
		t.Fatal("missing env file must fail")
	}
	if rc := run(nil, &out, &errb, http.DefaultClient); rc != 2 {
		t.Fatal("usage rc")
	}
	if rc := run([]string{"google", "bogus", "--env", envFile}, &out, &errb, http.DefaultClient); rc != 2 {
		t.Fatal("unknown subcommand rc")
	}
}

var _ = sso.MinStateSecretLen
