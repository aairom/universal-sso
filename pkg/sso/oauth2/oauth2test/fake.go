// Package oauth2test provides an in-process OAuth 2.0 authorization server
// for tests and the end-to-end harness.
//
// It serves /authorize, /token, /user and /revoke. It exists so the oauth2
// adapter can be tested without a real provider. It approves every request and
// never asks a person to sign in, so it is not a substitute for one.
package oauth2test

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// AccessToken is the access token every successful exchange returns.
const AccessToken = "at-oauth2-1" // nosecret: fixed fake-server test value

// Fake is an in-process OAuth 2.0 server. Configure it before the code under
// test runs. Fields that handlers read are guarded by the embedded mutex.
type Fake struct {
	// ClientID and ClientSecret are what the token endpoint accepts.
	ClientID, ClientSecret string
	// Style is the client authentication the token endpoint requires:
	// "basic" (default) or "post".
	Style string
	// Profile is returned by /user. Default: a GitHub-like profile with a
	// numeric id.
	Profile map[string]any

	mu          sync.Mutex
	codes       map[string]grant
	tokenErr    string
	errStatus   int
	formReply   bool
	tokenType   string
	noExpires   bool
	userStatus  int
	revokeCode  int
	gotToken    url.Values
	gotAuthHdr  string
	gotRevoke   url.Values
	gotUserAuth string
}

type grant struct{ redirectURI, challenge string }

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// New returns a fake that accepts the given client credentials.
func New(clientID, clientSecret string) *Fake {
	return &Fake{
		ClientID: clientID, ClientSecret: clientSecret, Style: "basic",
		codes: map[string]grant{}, tokenType: "bearer", userStatus: http.StatusOK, revokeCode: http.StatusOK,
		Profile: map[string]any{
			"id": 4242, "login": "octo", "name": "Octo Cat", "email": "octo@example.com",
			"avatar_url": "https://img.example.com/octo.png",
		},
	}
}

// Handler serves the fake. Paths are matched by suffix, so it works under any prefix.
func (f *Fake) Handler() http.Handler { return http.HandlerFunc(f.serve) }

// Set mutates the fake under its lock.
func (f *Fake) Set(fn func(*Fake)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

// FailToken makes the token endpoint answer with this OAuth error code and
// status (use 200 to mimic providers that report errors with status 200).
func (f *Fake) FailToken(code string, status int) {
	f.Set(func(f *Fake) { f.tokenErr, f.errStatus = code, status })
}

// FormReply makes the token endpoint answer form-encoded, ignoring Accept.
func (f *Fake) FormReply() { f.Set(func(f *Fake) { f.formReply = true }) }

// TokenType overrides the token_type of the reply.
func (f *Fake) TokenType(t string) { f.Set(func(f *Fake) { f.tokenType = t }) }

// OmitExpiry drops expires_in from the token reply.
func (f *Fake) OmitExpiry() { f.Set(func(f *Fake) { f.noExpires = true }) }

// UserStatus sets the HTTP status of /user.
func (f *Fake) UserStatus(s int) { f.Set(func(f *Fake) { f.userStatus = s }) }

// RevokeStatus sets the HTTP status of /revoke.
func (f *Fake) RevokeStatus(s int) { f.Set(func(f *Fake) { f.revokeCode = s }) }

// TokenForm returns the last form posted to /token.
func (f *Fake) TokenForm() url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gotToken
}

// TokenAuthHeader returns the Authorization header of the last /token request.
func (f *Fake) TokenAuthHeader() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gotAuthHdr
}

// RevokeForm returns the last form posted to /revoke.
func (f *Fake) RevokeForm() url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gotRevoke
}

// UserAuthHeader returns the Authorization header of the last /user request.
func (f *Fake) UserAuthHeader() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gotUserAuth
}

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	switch p := r.URL.Path; {
	case strings.HasSuffix(p, "/authorize"):
		f.authorize(w, r)
	case strings.HasSuffix(p, "/token"):
		f.token(w, r)
	case strings.HasSuffix(p, "/user"):
		f.user(w, r)
	case strings.HasSuffix(p, "/revoke"):
		_ = r.ParseForm()
		f.mu.Lock()
		f.gotRevoke = r.PostForm
		st := f.revokeCode
		f.mu.Unlock()
		w.WriteHeader(st)
	default:
		http.NotFound(w, r)
	}
}

// authorize approves the request and redirects back with a one-time code, as a
// signed-in browser session would.
func (f *Fake) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect, err := url.Parse(q.Get("redirect_uri"))
	if err != nil || redirect.Host == "" || q.Get("response_type") != "code" || q.Get("client_id") != f.ClientID ||
		q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("state") == "" {
		http.Error(w, "invalid authorization request", http.StatusBadRequest)
		return
	}
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	code := b64(buf)
	f.mu.Lock()
	f.codes[code] = grant{redirectURI: q.Get("redirect_uri"), challenge: q.Get("code_challenge")}
	f.mu.Unlock()
	rq := redirect.Query()
	rq.Set("code", code)
	rq.Set("state", q.Get("state"))
	redirect.RawQuery = rq.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (f *Fake) clientOK(r *http.Request) bool {
	id, secret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	if f.Style == "basic" {
		u, p, ok := r.BasicAuth()
		if !ok {
			return false
		}
		id, secret = u, p
		if uu, err := url.QueryUnescape(u); err == nil {
			id = uu
		}
		if pp, err := url.QueryUnescape(p); err == nil {
			secret = pp
		}
	}
	return subtle.ConstantTimeCompare([]byte(id), []byte(f.ClientID)) == 1 &&
		subtle.ConstantTimeCompare([]byte(secret), []byte(f.ClientSecret)) == 1
}

func writeErr(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}

func (f *Fake) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	f.gotToken = r.PostForm
	f.gotAuthHdr = r.Header.Get("Authorization")
	terr, estatus, form, ttype, noExp := f.tokenErr, f.errStatus, f.formReply, f.tokenType, f.noExpires
	var g grant
	granted := false
	if r.PostForm.Get("grant_type") == "authorization_code" {
		g, granted = f.codes[r.PostForm.Get("code")]
		delete(f.codes, r.PostForm.Get("code")) // authorization codes are single use
	}
	f.mu.Unlock()

	if !f.clientOK(r) {
		writeErr(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	if terr != "" {
		writeErr(w, estatus, terr, "rejected")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !granted || b64(sum[:]) != g.challenge || r.PostForm.Get("redirect_uri") != g.redirectURI {
			writeErr(w, http.StatusBadRequest, "invalid_grant", "unknown code, redirect_uri or PKCE mismatch")
			return
		}
	case "refresh_token":
		if r.PostForm.Get("refresh_token") != "rt-oauth2-1" {
			writeErr(w, http.StatusBadRequest, "invalid_grant", "unknown refresh token")
			return
		}
	default:
		writeErr(w, http.StatusBadRequest, "unsupported_grant_type", "")
		return
	}
	out := map[string]any{"access_token": AccessToken, "token_type": ttype, "scope": "read:user user:email", "expires_in": 3600}
	if noExp {
		delete(out, "expires_in")
	}
	if r.PostForm.Get("grant_type") == "authorization_code" {
		out["refresh_token"] = "rt-oauth2-1"
	}
	if form { // like providers that default to form encoding
		v := url.Values{}
		for k, val := range out {
			v.Set(k, strings.TrimSpace(toString(val)))
		}
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		_, _ = w.Write([]byte(v.Encode()))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func toString(v any) string {
	b, _ := json.Marshal(v)
	return strings.Trim(string(b), `"`)
}

func (f *Fake) user(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.gotUserAuth = r.Header.Get("Authorization")
	st, profile := f.userStatus, f.Profile
	f.mu.Unlock()
	if st != http.StatusOK {
		w.WriteHeader(st)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+AccessToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(profile)
}
