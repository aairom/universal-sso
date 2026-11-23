package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/universal-sso/universal-sso/pkg/sso"
)

// Google endpoints; package vars so tests can point them at a local server.
var (
	googleAuthURL      = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL     = "https://oauth2.googleapis.com/token"
	googleDiscoveryURL = "https://accounts.google.com/.well-known/openid-configuration"
)

const (
	callbackPath   = "/auth/google/callback"
	envClientID    = "SSO_PROVIDERS_GOOGLE_CLIENT_ID"
	envSecret      = "SSO_PROVIDERS_GOOGLE_CLIENT_SECRET" // nosecret
	envRedirect    = "SSO_PROVIDERS_GOOGLE_REDIRECT_URL"
	envBaseURL     = "SSO_SERVER_BASE_URL"
	envStateSecret = "SSO_STATE_SECRET" // nosecret
	clientIDSuffix = ".apps.googleusercontent.com"
)

var clientIDRe = regexp.MustCompile(`^[0-9]+-[A-Za-z0-9_]+\.apps\.googleusercontent\.com$`)

// Level is the severity of a finding.
type Level string

const (
	OK   Level = "OK"
	Warn Level = "WARN"
	Fail Level = "FAIL"
)

// Finding is one check result with an actionable hint.
type Finding struct {
	Level Level
	Msg   string
	Fix   string
}

// parseEnv reads KEY=VALUE lines (optional `export`, optional matching quotes, # comments).
// It never executes the file.
func parseEnv(r io.Reader) (map[string]string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	env := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		env[strings.TrimSpace(k)] = v
	}
	return env, nil
}

func loadEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseEnv(f)
}

func isPlaceholder(v string) bool {
	l := strings.ToLower(v)
	return v == "" || strings.Contains(l, "placeholder") || strings.Contains(l, "change-this") ||
		strings.Contains(l, "your-") || strings.Contains(l, "<")
}

func isLocalhost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func checkClientID(v string) Finding {
	switch {
	case isPlaceholder(v):
		return Finding{Fail, envClientID + " is empty or still a placeholder",
			"Copy the Client ID from Google Cloud Console > Google Auth Platform > Clients > your client (section 3.1)."}
	case strings.HasPrefix(v, "GOCSPX-"):
		return Finding{Fail, envClientID + " starts with GOCSPX-, which is the prefix of a client SECRET, not a Client ID",
			"A Client ID is <project-number>-<random>" + clientIDSuffix + ". Put the GOCSPX-... value in " + envSecret + " and paste the real Client ID here."}
	case !strings.HasSuffix(v, clientIDSuffix):
		return Finding{Fail, envClientID + " does not end with " + clientIDSuffix,
			"Copy the full Client ID including the suffix; do not trim it."}
	case !clientIDRe.MatchString(v):
		return Finding{Fail, envClientID + " has an unexpected format",
			"Expected <digits>-<letters/digits>" + clientIDSuffix + ". Check for stray spaces, quotes or line breaks."}
	}
	return Finding{OK, envClientID + " has the expected format", ""}
}

func checkSecret(v string) Finding {
	switch {
	case isPlaceholder(v):
		return Finding{Fail, envSecret + " is empty or still the .env.example placeholder",
			"Google shows the secret only once, at client creation. If you did not save it, open the client and add a new secret (section 3.1)."}
	case strings.HasSuffix(v, clientIDSuffix):
		return Finding{Fail, envSecret + " looks like a Client ID, not a secret",
			"The secret usually starts with GOCSPX-. You may have swapped the two values."}
	case !strings.HasPrefix(v, "GOCSPX-"):
		return Finding{Warn, envSecret + " does not start with GOCSPX-",
			"Older clients can use another format. If the token exchange later fails with invalid_client, re-copy the secret."}
	case strings.ContainsAny(v, " \t"):
		return Finding{Fail, envSecret + " contains whitespace", "Re-copy the value without spaces."}
	}
	return Finding{OK, envSecret + " has the expected format", ""}
}

func checkRedirect(redirect, base string) []Finding {
	var out []Finding
	if isPlaceholder(redirect) {
		return []Finding{{Fail, envRedirect + " is empty or a placeholder",
			"Set it to " + "<SSO_SERVER_BASE_URL>" + callbackPath + " and register the same string in Google (section 3.2)."}}
	}
	u, err := url.Parse(redirect)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return []Finding{{Fail, envRedirect + " is not a valid absolute URL", "Example: http://localhost:8080" + callbackPath}}
	}
	host := u.Hostname()
	bad := func(msg, fix string) { out = append(out, Finding{Fail, envRedirect + ": " + msg, fix}) }

	if u.Scheme != "https" && !(u.Scheme == "http" && isLocalhost(host)) {
		bad("Google requires https (http is allowed only for localhost)", "Use https://... for any non-local host.")
	}
	if net.ParseIP(host) != nil && !isLocalhost(host) {
		bad("raw IP addresses are not allowed", "Use a domain name.")
	}
	if u.User != nil {
		bad("userinfo (user:pass@) is not allowed", "Remove it.")
	}
	if u.Fragment != "" || strings.Contains(redirect, "#") {
		bad("fragments (#...) are not allowed", "Remove the fragment.")
	}
	if strings.Contains(redirect, "*") {
		bad("wildcards are not allowed", "Register each callback URL separately.")
	}
	if strings.Contains(u.Path, "/..") || strings.Contains(strings.ToLower(redirect), "%2e%2e") {
		bad("path traversal is not allowed", "Remove '..' segments.")
	}
	if len(out) > 0 {
		return out
	}
	if strings.HasSuffix(u.Path, "/") {
		out = append(out, Finding{Warn, envRedirect + " ends with a slash",
			"Google matches exactly; the server route is " + callbackPath + " without a trailing slash."})
	}
	if u.Path != callbackPath {
		out = append(out, Finding{Warn, fmt.Sprintf("%s path is %q, but ssod serves %s", envRedirect, u.Path, callbackPath),
			"Keep them identical unless a reverse proxy rewrites the path."})
	}
	if base != "" {
		want := strings.TrimRight(base, "/") + callbackPath
		if redirect != want {
			out = append(out, Finding{Warn, fmt.Sprintf("%s differs from %s + %s", envRedirect, envBaseURL, callbackPath),
				"Expected " + want + ". A mismatch is fine behind a proxy, but then register the value from " + envRedirect + " in Google."})
		}
	}
	if len(out) == 0 {
		out = append(out, Finding{OK, envRedirect + " is valid and consistent with " + envBaseURL, ""})
	}
	return out
}

func checkStateSecret(v string) Finding {
	switch {
	case len(v) < sso.MinStateSecretLen:
		return Finding{Fail, fmt.Sprintf("%s is shorter than %d bytes", envStateSecret, sso.MinStateSecretLen),
			"Generate one: openssl rand -base64 48"}
	case isPlaceholder(v):
		return Finding{Warn, envStateSecret + " is still the .env.example placeholder",
			"Anyone who has read the example file can forge state values. Generate one: openssl rand -base64 48"}
	}
	return Finding{OK, envStateSecret + " is set", ""}
}

// checkGoogleEnv validates the Google configuration without any network access.
func checkGoogleEnv(env map[string]string) []Finding {
	out := []Finding{checkClientID(env[envClientID]), checkSecret(env[envSecret])}
	out = append(out, checkRedirect(env[envRedirect], env[envBaseURL])...)
	out = append(out, checkStateSecret(env[envStateSecret]))
	return out
}

func checkDiscovery(ctx context.Context, c *http.Client) Finding {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, googleDiscoveryURL, nil)
	resp, err := c.Do(req)
	if err != nil {
		return Finding{Warn, "could not reach Google's discovery document: " + err.Error(),
			"Check your network or proxy. This is not a Google configuration problem."}
	}
	defer resp.Body.Close()
	var d struct {
		Issuer string `json:"issuer"`
		Auth   string `json:"authorization_endpoint"`
		Token  string `json:"token_endpoint"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&d) != nil || d.Issuer == "" {
		return Finding{Warn, fmt.Sprintf("discovery document returned HTTP %d or invalid JSON", resp.StatusCode), ""}
	}
	return Finding{OK, "Google discovery document reachable (issuer " + d.Issuer + ")", ""}
}

// pkceSession is what `url` stores so `exchange` can complete the same login.
type pkceSession struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
}

func newPKCESession() (*pkceSession, error) {
	st, err := sso.RandomString(16)
	if err != nil {
		return nil, err
	}
	nc, err := sso.RandomString(16)
	if err != nil {
		return nil, err
	}
	v, err := sso.NewCodeVerifier()
	if err != nil {
		return nil, err
	}
	return &pkceSession{State: st, Nonce: nc, Verifier: v}, nil
}

func buildAuthURL(env map[string]string, s *pkceSession) string {
	q := url.Values{}
	q.Set("client_id", env[envClientID])
	q.Set("redirect_uri", env[envRedirect])
	q.Set("response_type", "code")
	q.Set("scope", "openid email profile")
	q.Set("state", s.State)
	q.Set("nonce", s.Nonce)
	q.Set("code_challenge", sso.CodeChallengeS256(s.Verifier))
	q.Set("code_challenge_method", "S256")
	return googleAuthURL + "?" + q.Encode()
}

// extractCode accepts either a bare authorization code or the full redirected URL
// (what the browser address bar shows after sign-in) and returns code and state.
func extractCode(input string) (code, state string, err error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", "", errors.New("empty input")
	}
	if strings.Contains(input, "code=") || strings.Contains(input, "error=") {
		raw := input
		if i := strings.Index(raw, "?"); i >= 0 {
			raw = raw[i+1:]
		}
		q, perr := url.ParseQuery(raw)
		if perr != nil {
			return "", "", perr
		}
		if e := q.Get("error"); e != "" {
			return "", "", fmt.Errorf("Google returned error=%s (%s)", e, q.Get("error_description"))
		}
		return q.Get("code"), q.Get("state"), nil
	}
	return input, "", nil // bare code, already decoded by the caller or pasted from the URL
}

// tokenResult carries only the non-secret parts the CLI prints.
type tokenResult struct {
	Scope     string
	ExpiresIn int64
	Claims    map[string]any
}

// exchangeCode performs the authorization-code exchange with PKCE.
func exchangeCode(ctx context.Context, c *http.Client, env map[string]string, code, verifier string) (*tokenResult, error) {
	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", env[envClientID])
	form.Set("client_secret", env[envSecret])
	form.Set("redirect_uri", env[envRedirect])
	form.Set("grant_type", "authorization_code")
	form.Set("code_verifier", verifier)

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, googleTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	var body struct {
		IDToken   string `json:"id_token"`
		Scope     string `json:"scope"`
		ExpiresIn int64  `json:"expires_in"`
		Error     string `json:"error"`
		ErrorDesc string `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return nil, fmt.Errorf("token endpoint returned HTTP %d with an unreadable body", resp.StatusCode)
	}
	if body.Error != "" {
		return nil, fmt.Errorf("%s: %s", body.Error, body.ErrorDesc)
	}
	claims, err := decodeJWTClaims(body.IDToken)
	if err != nil {
		return nil, err
	}
	return &tokenResult{Scope: body.Scope, ExpiresIn: body.ExpiresIn, Claims: claims}, nil
}

// decodeJWTClaims reads the payload WITHOUT verifying the signature. It is for
// diagnostics only; the Google adapter must verify against Google's JWKS.
func decodeJWTClaims(tok string) (map[string]any, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, errors.New("response did not contain a valid id_token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil, fmt.Errorf("id_token payload is not base64url: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, fmt.Errorf("id_token payload is not JSON: %w", err)
	}
	return claims, nil
}

// verifyClaims applies the checks Google documents for ID tokens (except signature).
func verifyClaims(claims map[string]any, clientID, nonce string, now time.Time) []Finding {
	var out []Finding
	add := func(ok bool, good, bad, fix string) {
		if ok {
			out = append(out, Finding{OK, good, ""})
		} else {
			out = append(out, Finding{Fail, bad, fix})
		}
	}
	iss, _ := claims["iss"].(string)
	add(iss == "https://accounts.google.com" || iss == "accounts.google.com",
		"iss is Google", fmt.Sprintf("iss is %q", iss), "The token was not issued by Google.")

	aud, _ := claims["aud"].(string)
	add(aud == clientID, "aud matches your Client ID", fmt.Sprintf("aud is %q, not your Client ID", aud),
		"The code was issued to a different client; check "+envClientID+".")

	exp, _ := claims["exp"].(float64)
	add(int64(exp) > now.Unix(), "token is not expired", "token is expired", "Repeat the login and exchange quickly.")

	n, _ := claims["nonce"].(string)
	add(n == nonce, "nonce matches", "nonce does not match", "The URL and the exchange must come from the same `url` run.")

	sub, _ := claims["sub"].(string)
	add(sub != "", "sub present (use it as the stable user key)", "sub missing", "")
	return out
}
