package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func gw(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"status":"ok"}`)) })
	mux.HandleFunc("/providers", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"providers":["mock"]}`)) })
	mux.HandleFunc("/auth/mock/login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/auth/mock/callback?state=s", http.StatusFound)
	})
	mux.HandleFunc("/auth/mock/callback", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"provider_id":"mock","user":{"id":"u","email":"a@example.com","display_name":"Mock User"}}`))
	})
	mux.HandleFunc("/auth/saml/login", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"code":"PROVIDER_NOT_FOUND","message":"saml"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func runCmd(t *testing.T, base, provider string, args ...string) (int, string, string) {
	t.Helper()
	env := map[string]string{"SSO_GATEWAY_URL": base, "SSO_PROVIDER": provider}
	var out, errb bytes.Buffer
	code := run(context.Background(), args, func(k string) string { return env[k] }, &out, &errb)
	return code, out.String(), errb.String()
}

func TestRunUsageAndConfig(t *testing.T) {
	if code, _, _ := runCmd(t, "http://localhost:1", "mock"); code != 2 {
		t.Errorf("no args: %d", code)
	}
	if code, _, _ := runCmd(t, "http://localhost:1", "mock", "bogus"); code != 2 {
		t.Errorf("unknown command: %d", code)
	}
	if code, _, e := runCmd(t, "ftp://x", "mock", "check"); code != 2 || !strings.Contains(e, "configuration error") {
		t.Errorf("bad config: %d %s", code, e)
	}
	if code, _, _ := runCmd(t, "http://localhost:1", "mock", "login", "-nope"); code != 2 {
		t.Errorf("bad flag: %d", code)
	}
}

func TestRunCheck(t *testing.T) {
	srv := gw(t)
	if code, out, _ := runCmd(t, srv.URL, "mock", "check"); code != 0 || !strings.Contains(out, "providers: mock") {
		t.Errorf("check ok: %d %s", code, out)
	}
	if code, _, e := runCmd(t, srv.URL, "saml", "check"); code != 1 || !strings.Contains(e, "not registered") {
		t.Errorf("check missing provider: %d %s", code, e)
	}
	if code, _, _ := runCmd(t, "http://localhost:1", "mock", "check"); code != 1 {
		t.Errorf("check unreachable: %d", code)
	}
}

func TestRunLogin(t *testing.T) {
	srv := gw(t)
	code, out, _ := runCmd(t, srv.URL, "mock", "login")
	// The fake redirect carries no PKCE parameters, so the policy refuses it.
	if code != 1 {
		t.Errorf("policy should refuse: %d %s", code, out)
	}
	if code, _, e := runCmd(t, srv.URL, "saml", "login"); code != 1 || !strings.Contains(e, "no such provider") {
		t.Errorf("missing provider: %d %s", code, e)
	}
}
