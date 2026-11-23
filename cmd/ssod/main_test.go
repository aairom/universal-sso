package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func testServer(t *testing.T) *httptest.Server {
	t.Helper()
	secret := strings.Repeat("s", 32)
	m, err := build(func(k string) string {
		if k == "SSO_STATE_SECRET" {
			return secret
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(newHandler(m))
	t.Cleanup(srv.Close)
	return srv
}

func TestBuildRequiresSecret(t *testing.T) {
	if _, err := build(func(string) string { return "short" }); err == nil {
		t.Fatal("expected error for short secret")
	}
}

func TestEnvOr(t *testing.T) {
	t.Setenv("SSOD_TEST_X", "")
	if envOr("SSOD_TEST_X", "d") != "d" {
		t.Fatal("default expected")
	}
	t.Setenv("SSOD_TEST_X", "v")
	if envOr("SSOD_TEST_X", "d") != "v" {
		t.Fatal("env value expected")
	}
}

func TestHealthAndProviders(t *testing.T) {
	srv := testServer(t)
	for path, want := range map[string]string{"/healthz": `"ok"`, "/providers": `"mock"`} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		raw, _ := json.Marshal(body)
		if resp.StatusCode != 200 || !strings.Contains(string(raw), want) {
			t.Fatalf("%s: %d %s", path, resp.StatusCode, raw)
		}
	}
}

func TestLoginCallbackFlow(t *testing.T) {
	srv := testServer(t)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	resp, err := client.Get(srv.URL + "/auth/mock/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login status %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatal("no state in redirect")
	}

	cb := srv.URL + "/auth/mock/callback?code=abc&state=" + url.QueryEscape(state)
	resp, err = client.Get(cb)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	body := string(raw)
	resp.Body.Close()
	if resp.StatusCode != 200 || strings.Contains(body, "access_token") {
		t.Fatalf("callback %d %s", resp.StatusCode, body)
	}

	resp, _ = client.Get(cb) // replay
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("replay should be 400, got %d", resp.StatusCode)
	}
}

func TestErrorMapping(t *testing.T) {
	srv := testServer(t)
	for path, want := range map[string]int{
		"/auth/nope/login":                        http.StatusNotFound,
		"/auth/mock/callback?state=forged":        http.StatusBadRequest,
		"/auth/mock/callback?error=access_denied": http.StatusUnauthorized,
	} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("%s: got %d want %d", path, resp.StatusCode, want)
		}
	}
}

func envMap(m map[string]string) func(string) string {
	m["SSO_STATE_SECRET"] = strings.Repeat("s", 32)
	return func(k string) string { return m[k] }
}

func TestGoogleFromEnv(t *testing.T) {
	const idKey, secKey = "SSO_PROVIDERS_GOOGLE_CLIENT_ID", "SSO_PROVIDERS_GOOGLE_CLIENT_SECRET" // nosecret: env var names
	realID := "1234567890" + "12-abc" + ".apps.googleusercontent" + ".com"

	t.Run("not configured", func(t *testing.T) {
		for _, id := range []string{"", "google-client-id-placeholder"} {
			m, err := build(envMap(map[string]string{idKey: id}))
			if err != nil || len(m.Providers()) != 1 {
				t.Fatalf("id %q: %v %v", id, err, m)
			}
		}
	})
	t.Run("registered with default redirect", func(t *testing.T) {
		m, err := build(envMap(map[string]string{idKey: realID, secKey: "x", "SSO_SERVER_BASE_URL": "http://localhost:8080/"}))
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(m.Providers(), ","); got != "google,mock" {
			t.Fatalf("providers %s", got)
		}
		srv := httptest.NewServer(newHandler(m))
		defer srv.Close()
		// Discovery is unreachable in tests, so login must surface a gateway error, not 404.
		resp, err := http.Get(srv.URL + "/auth/google/login")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			t.Fatal("google provider not routed")
		}
	})
	t.Run("errors", func(t *testing.T) {
		cases := map[string]map[string]string{
			"placeholder secret": {idKey: realID, secKey: "google-client-secret-placeholder", "SSO_SERVER_BASE_URL": "http://localhost:8080"},
			"no redirect":        {idKey: realID, secKey: "x"},
			"secret as id":       {idKey: "GOCSPX-abc.apps.googleusercontent.com", secKey: "google-client-secret-placeholder", "SSO_SERVER_BASE_URL": "http://localhost:8080"},
		}
		for name, env := range cases {
			_, err := build(envMap(env))
			if err == nil {
				t.Errorf("%s: expected error", name)
			} else if name == "secret as id" && !strings.Contains(err.Error(), "holds a client secret") {
				t.Errorf("%s: message should name the real problem, got %v", name, err)
			}
		}
	})
	t.Run("explicit redirect and domain", func(t *testing.T) {
		if _, err := build(envMap(map[string]string{
			idKey: realID, secKey: "x", "SSO_PROVIDERS_GOOGLE_REDIRECT_URL": "https://sso.example.test/auth/google/callback",
			"SSO_PROVIDERS_GOOGLE_HOSTED_DOMAIN": "example.test",
		})); err != nil {
			t.Fatal(err)
		}
	})
}

func TestLandingPage(t *testing.T) {
	srv := testServer(t)
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(raw), `href="/auth/mock/login"`) {
		t.Fatalf("landing: %d %s", resp.StatusCode, raw)
	}
	resp, _ = http.Get(srv.URL + "/does-not-exist")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown path should stay 404, got %d", resp.StatusCode)
	}
}

// TestMockBrowserFlow follows every redirect like a browser: login -> mock IdP -> callback.
func TestMockBrowserFlow(t *testing.T) {
	srv := testServer(t)
	resp, err := http.Get(srv.URL + "/auth/mock/login")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(raw), `"user"`) || strings.Contains(string(raw), "access_token") {
		t.Fatalf("browser flow: %d %s", resp.StatusCode, raw)
	}
	resp, _ = http.Get(srv.URL + "/mock/authorize")
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("authorize without state: %d", resp.StatusCode)
	}
}

func TestLandingPageRendering(t *testing.T) {
	page, err := renderLanding([]string{"google", "mock", `we"ird<x>`})
	if err != nil {
		t.Fatal(err)
	}
	body := string(page)
	for _, want := range []string{"Continue with Google", "Continue with Mock", `href="/auth/google/login"`, `href="/auth/mock/login"`, "Server online"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(body, "<x>") || strings.Contains(body, `we"ird`) {
		t.Error("provider id must be escaped")
	}
	if strings.Contains(body, "<script") || strings.Contains(body, "http://") || strings.Contains(body, "https://") {
		t.Error("page must not load scripts or external resources")
	}
	empty, _ := renderLanding(nil)
	if !strings.Contains(string(empty), "No identity providers") {
		t.Error("empty state missing")
	}
}

func TestLandingHeaders(t *testing.T) {
	srv := testServer(t)
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	h := resp.Header
	if !strings.Contains(h.Get("Content-Security-Policy"), "default-src 'none'") || h.Get("X-Content-Type-Options") != "nosniff" ||
		!strings.HasPrefix(h.Get("Content-Type"), "text/html") {
		t.Fatalf("headers: %v", h)
	}
}
