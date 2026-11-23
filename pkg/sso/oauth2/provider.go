// Package oauth2 is a generic OAuth 2.0 provider for identity providers that
// are not OpenID Connect: you configure the authorization, token and profile
// URLs yourself.
//
// It implements the authorization code flow with PKCE (S256) and identifies
// the user through the profile endpoint. Plain OAuth 2.0 has no ID token, so
// the trust anchor is the access token received over HTTPS from the configured
// token URL, used against the configured profile URL. Neither URL ever comes
// from request data.
//
// Importing the package registers the "oauth2" driver with the sso registry.
package oauth2

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/universal-sso/universal-sso/pkg/sso"
	"github.com/universal-sso/universal-sso/pkg/sso/oidc"
)

// DriverName is the name under which the provider is registered.
const DriverName = "oauth2"

const (
	maxBody       = 1 << 20 // 1 MiB cap on IdP responses
	defaultUserID = "id"
)

// Client authentication methods for the token endpoint (RFC 6749 section 2.3.1).
const (
	AuthBasic = "basic" // client_secret_basic, the default
	AuthPost  = "post"  // client_secret_post
)

func init() {
	sso.RegisterDriver(DriverName, func(cfg map[string]string) (sso.Provider, error) {
		p, err := New(Config{
			ID:           cfg["id"],
			ClientID:     cfg["client_id"],
			ClientSecret: cfg["client_secret"],
			RedirectURL:  cfg["redirect_url"],
			AuthURL:      cfg["auth_url"],
			TokenURL:     cfg["token_url"],
			UserinfoURL:  cfg["userinfo_url"],
			RevokeURL:    cfg["revoke_url"],
			Scopes:       strings.Fields(cfg["scopes"]),
			UserIDField:  cfg["user_id_field"],
			AuthStyle:    cfg["auth_style"],
		})
		if err != nil {
			return nil, err // never wrap a nil *Provider in the interface
		}
		return p, nil
	})
}

// Config configures a Provider. ClientID, ClientSecret, RedirectURL, AuthURL,
// TokenURL and UserinfoURL are required.
type Config struct {
	ID           string // provider ID used in URLs (default "oauth2")
	Name         string // human-readable name (default "OAuth 2.0")
	ClientID     string
	ClientSecret string
	RedirectURL  string
	AuthURL      string
	TokenURL     string
	UserinfoURL  string
	RevokeURL    string   // optional, RFC 7009
	Scopes       []string // optional, sent space separated
	UserIDField  string   // profile field holding the stable user id (default "id")
	AuthStyle    string   // AuthBasic (default) or AuthPost
	HTTPClient   *http.Client
}

// Provider is a generic OAuth 2.0 provider.
type Provider struct {
	cfg  Config
	http *http.Client
	now  func() time.Time
}

// New validates cfg and creates the provider. No network access happens here.
func New(cfg Config) (*Provider, error) {
	if cfg.ID == "" {
		cfg.ID = DriverName
	}
	if cfg.Name == "" {
		cfg.Name = "OAuth 2.0"
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.RedirectURL == "" ||
		cfg.AuthURL == "" || cfg.TokenURL == "" || cfg.UserinfoURL == "" {
		return nil, sso.ErrInvalidConfig(cfg.Name+": client_id, client_secret, redirect_url, auth_url, token_url and userinfo_url are required", nil)
	}
	for _, f := range []struct{ field, v string }{
		{"redirect_url", cfg.RedirectURL}, {"auth_url", cfg.AuthURL},
		{"token_url", cfg.TokenURL}, {"userinfo_url", cfg.UserinfoURL},
	} {
		if err := oidc.ValidateURL(cfg.Name, f.field, f.v); err != nil {
			return nil, err
		}
	}
	if cfg.RevokeURL != "" {
		if err := oidc.ValidateURL(cfg.Name, "revoke_url", cfg.RevokeURL); err != nil {
			return nil, err
		}
	}
	switch cfg.AuthStyle {
	case "":
		cfg.AuthStyle = AuthBasic
	case AuthBasic, AuthPost:
	default:
		return nil, sso.ErrInvalidConfig(cfg.Name+": auth_style must be \""+AuthBasic+"\" or \""+AuthPost+"\"", nil)
	}
	if cfg.UserIDField == "" {
		cfg.UserIDField = defaultUserID
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &Provider{cfg: cfg, http: hc, now: time.Now}, nil
}

func (p *Provider) ID() string                 { return p.cfg.ID }
func (p *Provider) Name() string               { return p.cfg.Name }
func (p *Provider) Protocol() sso.ProtocolType { return sso.ProtocolOAuth2 }

func (p *Provider) errf(format string, a ...any) string {
	return p.cfg.Name + ": " + fmt.Sprintf(format, a...)
}

func (p *Provider) netErr(msg string, err error) *sso.SSOError {
	return sso.NewError(sso.ErrCodeNetworkFailure, p.cfg.Name+": "+msg, http.StatusBadGateway, err)
}

// GetAuthURL builds the authorization URL with state and PKCE. Plain OAuth 2.0
// has no nonce, so none is sent.
func (p *Provider) GetAuthURL(_ context.Context, req sso.AuthURLRequest) (*sso.AuthURLResponse, error) {
	if req.State == "" || req.CodeVerifier == "" {
		return nil, sso.ErrInvalidConfig(p.errf("state and code verifier are required"), nil)
	}
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = p.cfg.Scopes
	}
	q := url.Values{}
	for k, v := range req.ExtraParams { // extras first so they cannot override security parameters
		q.Set(k, v)
	}
	q.Set("response_type", "code")
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", p.cfg.RedirectURL)
	if len(scopes) > 0 {
		q.Set("scope", strings.Join(scopes, " "))
	}
	q.Set("state", req.State)
	q.Set("code_challenge", sso.CodeChallengeS256(req.CodeVerifier))
	q.Set("code_challenge_method", "S256")
	if req.LoginHint != "" {
		q.Set("login_hint", req.LoginHint)
	}
	u, err := url.Parse(p.cfg.AuthURL)
	if err != nil {
		return nil, p.netErr("bad authorization url", err)
	}
	// Keep query parameters the provider put in its own URL.
	merged := u.Query()
	for k, vs := range q {
		merged[k] = vs
	}
	u.RawQuery = merged.Encode()
	return &sso.AuthURLResponse{URL: u.String(), State: req.State, CodeVerifier: req.CodeVerifier}, nil
}

// tokenReply is the JSON body of a token endpoint response.
type tokenReply struct {
	AccessToken  string      `json:"access_token"`
	TokenType    string      `json:"token_type"`
	RefreshToken string      `json:"refresh_token"`
	ExpiresIn    json.Number `json:"expires_in"`
	Scope        string      `json:"scope"`
	Error        string      `json:"error"`
	ErrorDesc    string      `json:"error_description"`
}

// do sends req and returns the status and the size-capped body.
func (p *Provider) do(req *http.Request) (int, []byte, error) {
	resp, err := p.http.Do(req)
	if err != nil {
		return 0, nil, p.netErr("request failed", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return resp.StatusCode, nil, p.netErr("read response", err)
	}
	return resp.StatusCode, body, nil
}

// tokenRequest posts a grant to the token URL. The reply must be JSON (the
// request asks for it). Some providers answer errors with status 200, so the
// error key is checked before the access token.
func (p *Provider) tokenRequest(ctx context.Context, form url.Values) (*tokenReply, error) {
	form.Set("client_id", p.cfg.ClientID)
	if p.cfg.AuthStyle == AuthPost {
		form.Set("client_secret", p.cfg.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, p.netErr("build request", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if p.cfg.AuthStyle == AuthBasic {
		// RFC 6749 2.3.1: id and secret are form-urlencoded before base64.
		cred := url.QueryEscape(p.cfg.ClientID) + ":" + url.QueryEscape(p.cfg.ClientSecret)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(cred)))
	}
	status, body, err := p.do(req)
	if err != nil {
		return nil, err
	}
	var tr tokenReply
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&tr); err != nil {
		if status == http.StatusOK {
			return nil, p.netErr("token response is not JSON", err)
		}
		return nil, sso.NewError(sso.ErrCodeIdPRejected, p.errf("token request rejected (status %d)", status), http.StatusUnauthorized, nil)
	}
	if status != http.StatusOK || tr.Error != "" {
		msg := p.errf("token request rejected")
		if tr.Error != "" {
			msg += ": " + tr.Error
			if tr.ErrorDesc != "" {
				msg += " (" + tr.ErrorDesc + ")"
			}
		}
		return nil, sso.NewError(sso.ErrCodeIdPRejected, msg, http.StatusUnauthorized, nil)
	}
	if tr.AccessToken == "" {
		return nil, sso.NewError(sso.ErrCodeIdPRejected, p.errf("token response has no access token"), http.StatusBadGateway, nil)
	}
	if !strings.EqualFold(tr.TokenType, "bearer") {
		return nil, sso.NewError(sso.ErrCodeIdPRejected, p.errf("unsupported token type %q", tr.TokenType), http.StatusBadGateway, nil)
	}
	return &tr, nil
}

func (p *Provider) toTokens(tr *tokenReply) *sso.TokenResponse {
	// A missing or malformed expires_in means "unknown": do not invent a lifetime.
	secs, _ := strconv.ParseInt(tr.ExpiresIn.String(), 10, 64)
	t := &sso.TokenResponse{
		AccessToken: tr.AccessToken, TokenType: tr.TokenType,
		RefreshToken: tr.RefreshToken, ExpiresIn: secs, Scope: tr.Scope,
	}
	if secs > 0 {
		t.ExpiresAt = p.now().Add(time.Duration(secs) * time.Second)
	}
	return t
}

// profile calls the configured profile URL with the access token.
func (p *Provider) profile(ctx context.Context, accessToken string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.UserinfoURL, nil)
	if err != nil {
		return nil, p.netErr("build request", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	status, body, err := p.do(req)
	if err != nil {
		return nil, err
	}
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return nil, sso.ErrTokenValidation(p.errf("access token rejected by the profile endpoint"), nil)
	case status != http.StatusOK:
		return nil, p.netErr(fmt.Sprintf("profile endpoint returned status %d", status), nil)
	}
	var raw map[string]any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber() // keep numeric ids exact
	if err := dec.Decode(&raw); err != nil {
		return nil, p.netErr("profile response is not a JSON object", err)
	}
	return raw, nil
}

// scalar renders a string or number profile field. Other types yield "".
func scalar(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	}
	return ""
}

func first(raw map[string]any, keys ...string) string {
	for _, k := range keys {
		if s := scalar(raw[k]); s != "" {
			return s
		}
	}
	return ""
}

// userFromProfile maps a profile to the normalized user. The email is never
// marked verified: plain OAuth 2.0 does not say whether it is.
func (p *Provider) userFromProfile(raw map[string]any) (*sso.UserInfo, error) {
	id := scalar(raw[p.cfg.UserIDField])
	if id == "" {
		return nil, sso.ErrTokenValidation(p.errf("profile has no %q field (check the user id field setting)", p.cfg.UserIDField), nil)
	}
	email := first(raw, "email")
	username := first(raw, "login", "username", "preferred_username")
	if username == "" {
		username = email
	}
	return &sso.UserInfo{
		ID: id, Email: email, EmailVerified: false, Username: username,
		FirstName: first(raw, "given_name", "first_name"), LastName: first(raw, "family_name", "last_name"),
		DisplayName: first(raw, "name", "display_name"), AvatarURL: first(raw, "avatar_url", "picture"),
		RawAttributes: toAny(raw),
	}, nil
}

// toAny converts json.Number values so RawAttributes marshals as plain numbers.
func toAny(raw map[string]any) map[string]any {
	out := make(map[string]any, len(raw))
	for k, v := range raw {
		if n, ok := v.(json.Number); ok {
			if i, err := n.Int64(); err == nil {
				out[k] = i
				continue
			}
			if f, err := n.Float64(); err == nil {
				out[k] = f
				continue
			}
		}
		out[k] = v
	}
	return out
}

// HandleCallback exchanges the code (with the PKCE verifier) and reads the profile.
func (p *Provider) HandleCallback(ctx context.Context, req sso.CallbackRequest) (*sso.IdentityResult, error) {
	if req.Error != "" {
		return nil, sso.NewError(sso.ErrCodeIdPRejected, req.Error+": "+req.ErrorDesc, http.StatusUnauthorized, nil)
	}
	if req.Code == "" {
		return nil, sso.NewError(sso.ErrCodeIdPRejected, "missing authorization code", http.StatusBadRequest, nil)
	}
	if req.CodeVerifier == "" {
		return nil, sso.ErrStateInvalid("missing pkce verifier")
	}
	tr, err := p.tokenRequest(ctx, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {req.Code},
		"redirect_uri":  {p.cfg.RedirectURL},
		"code_verifier": {req.CodeVerifier},
	})
	if err != nil {
		return nil, err
	}
	raw, err := p.profile(ctx, tr.AccessToken)
	if err != nil {
		return nil, err
	}
	user, err := p.userFromProfile(raw)
	if err != nil {
		return nil, err
	}
	return &sso.IdentityResult{ProviderID: p.cfg.ID, Protocol: sso.ProtocolOAuth2, User: user, Tokens: p.toTokens(tr)}, nil
}

// ValidateToken treats tokenString as an access token and validates it by
// calling the profile endpoint, because plain OAuth 2.0 has no signed token.
func (p *Provider) ValidateToken(ctx context.Context, tokenString string) (*sso.Claims, error) {
	if tokenString == "" {
		return nil, sso.ErrTokenValidation(p.errf("access token is empty"), nil)
	}
	raw, err := p.profile(ctx, tokenString)
	if err != nil {
		return nil, err
	}
	u, err := p.userFromProfile(raw)
	if err != nil {
		return nil, err
	}
	return &sso.Claims{
		Subject: u.ID, Email: u.Email, Name: u.DisplayName, PreferredName: u.Username,
		Custom: u.RawAttributes,
	}, nil
}

// RefreshToken exchanges a refresh token. When the IdP does not rotate it, the
// original is carried over.
func (p *Provider) RefreshToken(ctx context.Context, refreshToken string) (*sso.TokenResponse, error) {
	if refreshToken == "" {
		return nil, sso.ErrTokenValidation(p.errf("refresh token is empty"), nil)
	}
	tr, err := p.tokenRequest(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}})
	if err != nil {
		return nil, err
	}
	if tr.RefreshToken == "" {
		tr.RefreshToken = refreshToken
	}
	return p.toTokens(tr), nil
}

// RevokeToken revokes a token (RFC 7009) when a revoke URL is configured.
func (p *Provider) RevokeToken(ctx context.Context, tokenString string) error {
	if p.cfg.RevokeURL == "" {
		return sso.NewError(sso.ErrCodeUnsupportedMethod, p.errf("no revoke_url configured"), http.StatusNotImplemented, nil)
	}
	form := url.Values{"token": {tokenString}, "client_id": {p.cfg.ClientID}}
	if p.cfg.AuthStyle == AuthPost {
		form.Set("client_secret", p.cfg.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.RevokeURL, strings.NewReader(form.Encode()))
	if err != nil {
		return p.netErr("build request", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if p.cfg.AuthStyle == AuthBasic {
		cred := url.QueryEscape(p.cfg.ClientID) + ":" + url.QueryEscape(p.cfg.ClientSecret)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(cred)))
	}
	status, _, err := p.do(req)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return sso.NewError(sso.ErrCodeIdPRejected, p.errf("revoke failed (status %d)", status), http.StatusBadGateway, nil)
	}
	return nil
}

// GetLogoutURL is not supported: plain OAuth 2.0 defines no sign-out endpoint.
func (p *Provider) GetLogoutURL(context.Context, sso.LogoutRequest) (*sso.LogoutURLResponse, error) {
	return nil, sso.NewError(sso.ErrCodeUnsupportedMethod, p.errf("OAuth 2.0 defines no logout endpoint"), http.StatusNotImplemented, nil)
}

// FetchUserInfo reads the profile with an access token.
func (p *Provider) FetchUserInfo(ctx context.Context, accessToken string) (*sso.UserInfo, error) {
	if accessToken == "" {
		return nil, sso.ErrTokenValidation(p.errf("access token is empty"), nil)
	}
	raw, err := p.profile(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	return p.userFromProfile(raw)
}

var _ sso.Provider = (*Provider)(nil)
