// Package oidctest provides an in-process OpenID Connect server for tests.
//
// It serves discovery, JWKS, token, userinfo and revocation endpoints and
// signs ID tokens with a throw-away RSA key. It exists so adapters can be
// tested without a real identity provider. It is not a substitute for one.
package oidctest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Fake is an in-process OIDC server. Set fields before the code under test
// runs. Fields that handlers read are guarded by the embedded mutex via Set.
type Fake struct {
	Srv *httptest.Server
	Key *rsa.PrivateKey
	Kid string

	mu           sync.Mutex
	claims       map[string]any
	tokenErr     string
	noIDToken    bool
	discIssuer   string
	noEndSession bool
	noRevoke     bool
	revokeStatus int
	gotForm      url.Values
	gotTokenAuth string
	gotRevoke    url.Values

	// Interactive mode (see NewInteractive): /authorize issues codes and
	// /token verifies PKCE and mints tokens through Mint.
	base     string
	mint     func(clientID, nonce string) map[string]any
	codes    map[string]authGrant
	JWKSHits atomic.Int32
	t        *testing.T
}

type authGrant struct{ clientID, nonce, challenge string }

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// New starts a fake server that is stopped when the test ends.
func New(t *testing.T) *Fake {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &Fake{Key: key, Kid: "kid-1", revokeStatus: http.StatusOK, t: t}
	f.Srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Srv.Close)
	return f
}

// NewInteractive returns a fake that is mounted by the caller (Handler) at the
// public base URL base (scheme, host and any path prefix, no trailing slash).
// Unlike New it needs no *testing.T. /authorize redirects straight back to the
// redirect_uri with a code and the state, /token verifies the PKCE verifier,
// and the ID token is produced by mint(clientID, nonce). It exists for the
// end-to-end harness and is a stand-in for a real identity provider only.
func NewInteractive(base string, mint func(clientID, nonce string) map[string]any) *Fake {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return &Fake{Key: key, Kid: "kid-1", revokeStatus: http.StatusOK, base: strings.TrimRight(base, "/"), mint: mint, codes: map[string]authGrant{}}
}

// Handler serves the fake. Paths are matched by suffix, so it works under any prefix.
func (f *Fake) Handler() http.Handler { return http.HandlerFunc(f.serve) }

// URL is the server base URL (no trailing slash).
func (f *Fake) URL() string {
	if f.base != "" {
		return f.base
	}
	return f.Srv.URL
}

// Set mutates the fake under its lock.
func (f *Fake) Set(fn func(*Fake)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

// SetClaims sets the claims signed into the next ID token.
func (f *Fake) SetClaims(c map[string]any) { f.Set(func(f *Fake) { f.claims = c }) }

// FailToken makes the token endpoint answer 400 with this OAuth error code.
func (f *Fake) FailToken(code string) { f.Set(func(f *Fake) { f.tokenErr = code }) }

// OmitIDToken drops id_token from token responses.
func (f *Fake) OmitIDToken() { f.Set(func(f *Fake) { f.noIDToken = true }) }

// DiscoveryIssuer overrides the issuer announced by discovery.
func (f *Fake) DiscoveryIssuer(iss string) { f.Set(func(f *Fake) { f.discIssuer = iss }) }

// OmitEndSession removes end_session_endpoint from discovery.
func (f *Fake) OmitEndSession() { f.Set(func(f *Fake) { f.noEndSession = true }) }

// OmitRevocation removes revocation_endpoint from discovery.
func (f *Fake) OmitRevocation() { f.Set(func(f *Fake) { f.noRevoke = true }) }

// RevokeStatus sets the HTTP status of the revocation endpoint.
func (f *Fake) RevokeStatus(s int) { f.Set(func(f *Fake) { f.revokeStatus = s }) }

// TokenForm returns the last form posted to the token endpoint.
func (f *Fake) TokenForm() url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gotForm
}

// TokenAuthHeader returns the Authorization header of the last token request.
func (f *Fake) TokenAuthHeader() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gotTokenAuth
}

// RevokeForm returns the last form posted to the revocation endpoint.
func (f *Fake) RevokeForm() url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gotRevoke
}

// Sign signs claims with the server's key using RS256.
func (f *Fake) Sign(claims map[string]any) string {
	f.mu.Lock()
	key, kid := f.Key, f.Kid
	f.mu.Unlock()
	return f.SignWith(key, kid, "RS256", claims)
}

// SignWith signs claims with an arbitrary key, kid and alg label. The
// signature is always RSA PKCS#1 v1.5 over SHA-256, so alg "HS256" or "none"
// produces a token whose header lies about its algorithm.
func (f *Fake) SignWith(key *rsa.PrivateKey, kid, alg string, claims map[string]any) string {
	hb, _ := json.Marshal(map[string]string{"alg": alg, "kid": kid, "typ": "JWT"})
	pb, _ := json.Marshal(claims)
	signing := b64(hb) + "." + b64(pb)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		if f.t != nil {
			f.t.Fatal(err)
		}
		panic(err)
	}
	return signing + "." + b64(sig)
}

// GoodClaims returns valid claims for issuer and audience.
func GoodClaims(issuer, audience, nonce string) map[string]any {
	return map[string]any{
		"iss": issuer, "aud": audience, "sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		"nonce": nonce, "email": "a@example.test", "email_verified": true,
		"name": "A B", "given_name": "A", "family_name": "B",
	}
}

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	case strings.HasSuffix(path, "/.well-known/openid-configuration"):
		f.discovery(w, path)
	case strings.HasSuffix(path, "/jwks"):
		f.JWKSHits.Add(1)
		f.mu.Lock()
		key, kid := f.Key, f.Kid
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
			"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()),
		}}})
	case strings.HasSuffix(path, "/authorize"):
		f.authorize(w, r)
	case strings.HasSuffix(path, "/token"):
		f.token(w, r)
	case strings.HasSuffix(path, "/userinfo"):
		if r.Header.Get("Authorization") != "Bearer at-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub": "user-1", "email": "a@example.test", "email_verified": true, "name": "A B",
			"preferred_username": "ab", "groups": []string{"g1"},
		})
	case strings.HasSuffix(path, "/revoke"):
		_ = r.ParseForm()
		f.mu.Lock()
		f.gotRevoke = r.PostForm
		st := f.revokeStatus
		f.mu.Unlock()
		w.WriteHeader(st)
	default:
		http.NotFound(w, r)
	}
}

// discovery serves a document whose endpoints live next to the requested
// discovery path, so issuers with a path (Okta, Entra) work.
func (f *Fake) discovery(w http.ResponseWriter, path string) {
	base := f.URL() + strings.TrimSuffix(path, "/.well-known/openid-configuration")
	f.mu.Lock()
	iss, noES, noRev := f.discIssuer, f.noEndSession, f.noRevoke
	f.mu.Unlock()
	if iss == "" {
		iss = base
	}
	doc := map[string]string{
		"issuer": iss, "authorization_endpoint": base + "/authorize", "token_endpoint": base + "/token",
		"jwks_uri": base + "/jwks", "userinfo_endpoint": base + "/userinfo",
	}
	if !noRev {
		doc["revocation_endpoint"] = base + "/revoke"
	}
	if !noES {
		doc["end_session_endpoint"] = base + "/logout"
	}
	_ = json.NewEncoder(w).Encode(doc)
}

func (f *Fake) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	f.gotForm = r.PostForm
	f.gotTokenAuth = r.Header.Get("Authorization")
	terr, noID, claims := f.tokenErr, f.noIDToken, f.claims
	var grant authGrant
	granted := false
	if f.mint != nil && r.PostForm.Get("grant_type") == "authorization_code" {
		grant, granted = f.codes[r.PostForm.Get("code")]
		delete(f.codes, r.PostForm.Get("code")) // authorization codes are single use
	}
	f.mu.Unlock()
	if f.mint != nil && r.PostForm.Get("grant_type") == "authorization_code" {
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !granted || b64(sum[:]) != grant.challenge {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "unknown code or PKCE mismatch"})
			return
		}
		claims = f.mint(grant.clientID, grant.nonce)
	}
	if terr != "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": terr, "error_description": "rejected"})
		return
	}
	out := map[string]any{"access_token": "at-1", "token_type": "Bearer", "expires_in": 3600, "scope": "openid email profile"}
	if r.PostForm.Get("grant_type") == "authorization_code" {
		out["refresh_token"] = "rt-1"
	}
	if !noID && claims != nil {
		out["id_token"] = f.Sign(claims)
	}
	_ = json.NewEncoder(w).Encode(out)
}

// authorize records the request and redirects back with a one-time code, as a
// signed-in browser session would.
func (f *Fake) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect, err := url.Parse(q.Get("redirect_uri"))
	if f.mint == nil || err != nil || redirect.Host == "" || q.Get("response_type") != "code" ||
		q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "invalid authorization request", http.StatusBadRequest)
		return
	}
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	code := b64(buf)
	f.mu.Lock()
	f.codes[code] = authGrant{clientID: q.Get("client_id"), nonce: q.Get("nonce"), challenge: q.Get("code_challenge")}
	f.mu.Unlock()
	rq := redirect.Query()
	rq.Set("code", code)
	rq.Set("state", q.Get("state"))
	redirect.RawQuery = rq.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}
