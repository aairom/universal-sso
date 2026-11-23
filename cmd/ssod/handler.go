package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/universal-sso/universal-sso/pkg/sso"
)

// newHandler exposes the Manager over HTTP:
//
//	GET /                             landing page with a login link per provider
//	GET /mock/authorize               stand-in IdP for the mock provider: approves and redirects back
//	GET /healthz                      liveness probe
//	GET /providers                    registered provider IDs
//	GET /auth/{provider}/login        redirect to the IdP authorization URL
//	GET /auth/{provider}/callback     complete login, return the user profile
func newHandler(m *sso.Manager) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", landingHandler(m.Providers))

	// The mock provider has no real IdP, so ssod plays that role: it approves
	// the request and sends the browser back to the callback with a code.
	mux.HandleFunc("GET /mock/authorize", func(w http.ResponseWriter, r *http.Request) {
		state := r.URL.Query().Get("state")
		if state == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"code": string(sso.ErrCodeStateMismatch), "message": "state is required"})
			return
		}
		cb := url.Values{"code": {"mock-code"}, "state": {state}}
		http.Redirect(w, r, "/auth/mock/callback?"+cb.Encode(), http.StatusFound)
	})

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("GET /providers", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string][]string{"providers": m.Providers()})
	})

	mux.HandleFunc("GET /auth/{provider}/login", func(w http.ResponseWriter, r *http.Request) {
		resp, err := m.BeginLogin(r.Context(), r.PathValue("provider"), sso.AuthURLRequest{})
		if err != nil {
			writeError(w, err)
			return
		}
		http.Redirect(w, r, resp.URL, http.StatusFound)
	})

	mux.HandleFunc("GET /auth/{provider}/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		res, err := m.CompleteLogin(r.Context(), r.PathValue("provider"), sso.CallbackRequest{
			State:     q.Get("state"),
			Code:      q.Get("code"),
			Error:     q.Get("error"),
			ErrorDesc: q.Get("error_description"),
		})
		if err != nil {
			writeError(w, err)
			return
		}
		// Tokens are deliberately not echoed back to the browser.
		writeJSON(w, http.StatusOK, map[string]any{"provider_id": res.ProviderID, "user": res.User})
	})

	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, err error) {
	var se *sso.SSOError
	if errors.As(err, &se) {
		writeJSON(w, se.HTTPStatus, map[string]string{"code": string(se.Code), "message": se.Message})
		return
	}
	writeJSON(w, http.StatusInternalServerError, map[string]string{"code": string(sso.ErrCodeInternal), "message": "internal error"})
}
