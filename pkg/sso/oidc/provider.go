// Package oidc is a generic OpenID Connect relying-party provider.
//
// It implements the authorization code flow with PKCE (S256) and verifies ID
// tokens (RS256 signature against the IdP's JWKS, iss, aud, exp, nbf, sub and
// nonce). Vendor adapters (okta, auth0, entra) configure it through Config
// hooks instead of re-implementing the protocol.
//
// Only RS256 is accepted. "none", HMAC and every other algorithm are rejected
// before any key is looked up, which closes algorithm-confusion attacks.
package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/universal-sso/universal-sso/pkg/sso"
)

const (
	clockSkew = time.Minute
	cacheTTL  = time.Hour
	maxBody   = 1 << 20 // 1 MiB cap on IdP responses
)

// Client authentication methods for the token endpoint (RFC 6749 section 2.3.1).
const (
	AuthPost  = "post"  // client_secret_post
	AuthBasic = "basic" // client_secret_basic
)

// Config configures a Provider. Name, ClientID, ClientSecret, RedirectURL and
// Issuer are required.
type Config struct {
	ID           string // provider ID used in URLs
	Name         string // human-readable name, also the error-message prefix
	ClientID     string
	ClientSecret string
	RedirectURL  string
	// Issuer is the expected issuer. Discovery is read from
	// <Issuer>/.well-known/openid-configuration unless DiscoveryURL is set.
	Issuer       string
	DiscoveryURL string
	Scopes       []string // default: openid email profile
	ClientAuth   string   // AuthPost (default) or AuthBasic
	HTTPClient   *http.Client

	// ExtraAuthParams are added to the authorization request. They can never
	// override the security parameters (state, nonce, PKCE, client_id ...).
	ExtraAuthParams map[string]string

	// AcceptIssuer decides whether a token's iss is acceptable. Default: it
	// must equal the discovery document's issuer.
	AcceptIssuer func(tokenIssuer, discoveryIssuer string, claims map[string]any) bool
	// AcceptDiscoveryIssuer vets the issuer announced by the discovery
	// document. Default: it must equal Issuer (ignoring a trailing slash).
	AcceptDiscoveryIssuer func(discoveryIssuer string) bool
	// CheckClaims runs after signature, issuer and audience checks.
	CheckClaims func(claims map[string]any) error
	// MapUser adjusts the normalized profile using the raw claims.
	MapUser func(raw map[string]any, u *sso.UserInfo)
	// LogoutURL overrides the RP-initiated logout URL construction.
	LogoutURL func(req sso.LogoutRequest) (string, error)
}

type discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// Provider is a generic OIDC provider.
type Provider struct {
	cfg  Config
	http *http.Client

	mu        sync.Mutex
	disc      *discovery
	discAt    time.Time
	keys      map[string]*rsa.PublicKey
	keysAt    time.Time
	now       func() time.Time
	keyMinGap time.Duration // minimum interval between forced JWKS refreshes
}

// ValidateURL requires an absolute https URL. Plain http is allowed only for
// loopback hosts so local tests and development stay possible.
func ValidateURL(name, field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return sso.ErrInvalidConfig(name+": "+field+" must be an absolute URL", err)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if h := u.Hostname(); h == "localhost" || net.ParseIP(h).IsLoopback() {
			return nil
		}
	}
	return sso.ErrInvalidConfig(name+": "+field+" must use https", nil)
}

// New validates cfg and creates the provider. No network access happens here.
func New(cfg Config) (*Provider, error) {
	if cfg.Name == "" {
		return nil, sso.ErrInvalidConfig("oidc: provider name is required", nil)
	}
	if cfg.ID == "" {
		cfg.ID = strings.ToLower(cfg.Name)
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.RedirectURL == "" || cfg.Issuer == "" {
		return nil, sso.ErrInvalidConfig(cfg.Name+": client_id, client_secret, redirect_url and issuer are required", nil)
	}
	if err := ValidateURL(cfg.Name, "redirect_url", cfg.RedirectURL); err != nil {
		return nil, err
	}
	if err := ValidateURL(cfg.Name, "issuer", cfg.Issuer); err != nil {
		return nil, err
	}
	if cfg.DiscoveryURL == "" {
		cfg.DiscoveryURL = strings.TrimRight(cfg.Issuer, "/") + "/.well-known/openid-configuration"
	} else if err := ValidateURL(cfg.Name, "discovery_url", cfg.DiscoveryURL); err != nil {
		return nil, err
	}
	switch cfg.ClientAuth {
	case "":
		cfg.ClientAuth = AuthPost
	case AuthPost, AuthBasic:
	default:
		return nil, sso.ErrInvalidConfig(cfg.Name+": client_auth must be \""+AuthPost+"\" or \""+AuthBasic+"\"", nil)
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "email", "profile"}
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &Provider{cfg: cfg, http: hc, now: time.Now, keyMinGap: time.Minute}, nil
}

func (p *Provider) ID() string                 { return p.cfg.ID }
func (p *Provider) Name() string               { return p.cfg.Name }
func (p *Provider) Protocol() sso.ProtocolType { return sso.ProtocolOIDC }

func (p *Provider) errf(format string, a ...any) string {
	return p.cfg.Name + ": " + fmt.Sprintf(format, a...)
}

func (p *Provider) netErr(msg string, err error) *sso.SSOError {
	return sso.NewError(sso.ErrCodeNetworkFailure, p.cfg.Name+": "+msg, http.StatusBadGateway, err)
}

// getJSON performs a GET and decodes a JSON body.
func (p *Provider) getJSON(ctx context.Context, rawURL, bearer string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return p.netErr("build request", err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := p.http.Do(req)
	if err != nil {
		return p.netErr("request failed", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return p.netErr("read response", err)
	}
	if resp.StatusCode != http.StatusOK {
		if bearer != "" && resp.StatusCode == http.StatusUnauthorized {
			return sso.ErrTokenValidation(p.errf("access token rejected"), nil)
		}
		return p.netErr(fmt.Sprintf("unexpected status %d", resp.StatusCode), nil)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return p.netErr("invalid json response", err)
	}
	return nil
}

// endpoints returns the cached discovery document, refreshing it when stale.
func (p *Provider) endpoints(ctx context.Context) (*discovery, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.disc != nil && p.now().Sub(p.discAt) < cacheTTL {
		return p.disc, nil
	}
	var d discovery
	if err := p.getJSON(ctx, p.cfg.DiscoveryURL, "", &d); err != nil {
		return nil, err
	}
	if d.Issuer == "" || d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.JWKSURI == "" {
		return nil, p.netErr("incomplete discovery document", nil)
	}
	// Guard against a discovery document that belongs to another issuer.
	ok := strings.TrimRight(d.Issuer, "/") == strings.TrimRight(p.cfg.Issuer, "/")
	if p.cfg.AcceptDiscoveryIssuer != nil {
		ok = p.cfg.AcceptDiscoveryIssuer(d.Issuer)
	}
	if !ok {
		return nil, sso.NewError(sso.ErrCodeIdPRejected, p.errf("discovery issuer does not match the configured issuer"), http.StatusBadGateway, nil)
	}
	p.disc, p.discAt = &d, p.now()
	return p.disc, nil
}

// key returns the signing key for kid, refreshing the JWKS at most once per
// keyMinGap when the kid is unknown (supports key rotation).
func (p *Provider) key(ctx context.Context, d *discovery, kid string) (*rsa.PublicKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	unknown := sso.NewError(sso.ErrCodeSignatureInvalid, p.errf("unknown signing key"), http.StatusUnauthorized, nil)
	stale := p.keys == nil || p.now().Sub(p.keysAt) >= cacheTTL
	if k, ok := p.keys[kid]; ok && !stale {
		return k, nil
	}
	if p.keys != nil && !stale && p.now().Sub(p.keysAt) < p.keyMinGap {
		return nil, unknown
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := p.getJSON(ctx, d.JWKSURI, "", &set); err != nil {
		return nil, err
	}
	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if pub, err := k.publicKey(); err == nil {
			keys[k.Kid] = pub
		}
	}
	p.keys, p.keysAt = keys, p.now()
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, unknown
}

func (p *Provider) issuerOK(tokenIss string, d *discovery, claims map[string]any) bool {
	if p.cfg.AcceptIssuer != nil {
		return p.cfg.AcceptIssuer(tokenIss, d.Issuer, claims)
	}
	return tokenIss != "" && tokenIss == d.Issuer
}

// verifyIDToken checks signature, issuer, audience, expiry and not-before.
// The nonce is checked by the caller because only the code flow has one.
func (p *Provider) verifyIDToken(ctx context.Context, token string) (*parsedJWT, error) {
	d, err := p.endpoints(ctx)
	if err != nil {
		return nil, err
	}
	j, err := parseJWT(token)
	if err != nil {
		return nil, sso.ErrTokenValidation(p.errf("invalid id token"), err)
	}
	pub, err := p.key(ctx, d, j.header.Kid)
	if err != nil {
		return nil, err
	}
	if err := j.verify(pub); err != nil {
		return nil, sso.NewError(sso.ErrCodeSignatureInvalid, p.errf("id token signature invalid"), http.StatusUnauthorized, nil)
	}
	c, now := j.claims, p.now()
	switch {
	case !p.issuerOK(c.Issuer, d, j.raw):
		return nil, sso.ErrTokenValidation(p.errf("unexpected issuer"), nil)
	case !c.Audience.contains(p.cfg.ClientID):
		return nil, sso.ErrTokenValidation(p.errf("audience mismatch"), nil)
	case c.ExpiresAt == 0 || now.After(time.Unix(c.ExpiresAt, 0).Add(clockSkew)):
		return nil, sso.NewError(sso.ErrCodeTokenExpired, p.errf("id token expired"), http.StatusUnauthorized, nil)
	case c.NotBefore != 0 && now.Add(clockSkew).Before(time.Unix(c.NotBefore, 0)):
		return nil, sso.ErrTokenValidation(p.errf("id token not yet valid"), nil)
	case c.Subject == "":
		return nil, sso.ErrTokenValidation(p.errf("id token has no subject"), nil)
	}
	if p.cfg.CheckClaims != nil {
		if err := p.cfg.CheckClaims(j.raw); err != nil {
			return nil, err
		}
	}
	return j, nil
}

// GetAuthURL builds the authorization URL with state, nonce and PKCE.
func (p *Provider) GetAuthURL(ctx context.Context, req sso.AuthURLRequest) (*sso.AuthURLResponse, error) {
	if req.State == "" || req.Nonce == "" || req.CodeVerifier == "" {
		return nil, sso.ErrInvalidConfig(p.errf("state, nonce and code verifier are required"), nil)
	}
	d, err := p.endpoints(ctx)
	if err != nil {
		return nil, err
	}
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = p.cfg.Scopes
	}
	q := url.Values{}
	for k, v := range p.cfg.ExtraAuthParams {
		q.Set(k, v)
	}
	for k, v := range req.ExtraParams { // extras first so they cannot override security parameters
		q.Set(k, v)
	}
	q.Set("response_type", "code")
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", p.cfg.RedirectURL)
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("state", req.State)
	q.Set("nonce", req.Nonce)
	q.Set("code_challenge", sso.CodeChallengeS256(req.CodeVerifier))
	q.Set("code_challenge_method", "S256")
	if req.Prompt != "" {
		q.Set("prompt", req.Prompt)
	}
	if req.LoginHint != "" {
		q.Set("login_hint", req.LoginHint)
	}
	u, err := url.Parse(d.AuthorizationEndpoint)
	if err != nil {
		return nil, p.netErr("bad authorization endpoint", err)
	}
	u.RawQuery = q.Encode()
	return &sso.AuthURLResponse{URL: u.String(), State: req.State, Nonce: req.Nonce, CodeVerifier: req.CodeVerifier}, nil
}

type tokenReply struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

// postForm posts a form and decodes the JSON reply into out.
func (p *Provider) postForm(ctx context.Context, endpoint string, form url.Values, basic bool, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, p.netErr("build request", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if basic {
		// RFC 6749 2.3.1: id and secret are form-urlencoded before base64.
		cred := url.QueryEscape(p.cfg.ClientID) + ":" + url.QueryEscape(p.cfg.ClientSecret)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(cred)))
	}
	resp, err := p.http.Do(req)
	if err != nil {
		return 0, p.netErr("request failed", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return resp.StatusCode, p.netErr("read response", err)
	}
	if out != nil && len(body) > 0 {
		if err := json.Unmarshal(body, out); err != nil && resp.StatusCode == http.StatusOK {
			return resp.StatusCode, p.netErr("invalid json response", err)
		}
	}
	return resp.StatusCode, nil
}

// clientAuth adds the client credentials to form and reports whether the
// request must carry an HTTP Basic header.
func (p *Provider) clientAuth(form url.Values) (basic bool) {
	form.Set("client_id", p.cfg.ClientID)
	if p.cfg.ClientAuth == AuthBasic {
		return true
	}
	form.Set("client_secret", p.cfg.ClientSecret)
	return false
}

func (p *Provider) tokenRequest(ctx context.Context, form url.Values) (*tokenReply, error) {
	d, err := p.endpoints(ctx)
	if err != nil {
		return nil, err
	}
	basic := p.clientAuth(form)
	var tr tokenReply
	status, err := p.postForm(ctx, d.TokenEndpoint, form, basic, &tr)
	if err != nil {
		return nil, err
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
	return &tr, nil
}

func (p *Provider) toTokens(tr *tokenReply) *sso.TokenResponse {
	return &sso.TokenResponse{
		AccessToken: tr.AccessToken, TokenType: tr.TokenType, RefreshToken: tr.RefreshToken,
		IDToken: tr.IDToken, ExpiresIn: tr.ExpiresIn, Scope: tr.Scope,
		ExpiresAt: p.now().Add(time.Duration(tr.ExpiresIn) * time.Second),
	}
}

func (p *Provider) userFromClaims(j *parsedJWT) *sso.UserInfo {
	c := j.claims
	u := &sso.UserInfo{
		ID: c.Subject, Email: c.Email, EmailVerified: c.EmailVerified,
		Username: c.Email, FirstName: c.GivenName, LastName: c.FamilyName,
		DisplayName: c.Name, AvatarURL: c.Picture, RawAttributes: j.raw,
	}
	if p.cfg.MapUser != nil {
		p.cfg.MapUser(j.raw, u)
	}
	return u
}

// HandleCallback exchanges the code (with the PKCE verifier) and verifies the ID token.
func (p *Provider) HandleCallback(ctx context.Context, req sso.CallbackRequest) (*sso.IdentityResult, error) {
	if req.Error != "" {
		return nil, sso.NewError(sso.ErrCodeIdPRejected, req.Error+": "+req.ErrorDesc, http.StatusUnauthorized, nil)
	}
	if req.Code == "" {
		return nil, sso.NewError(sso.ErrCodeIdPRejected, "missing authorization code", http.StatusBadRequest, nil)
	}
	if req.CodeVerifier == "" || req.Nonce == "" {
		return nil, sso.ErrStateInvalid("missing pkce verifier or nonce")
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
	if tr.IDToken == "" {
		return nil, sso.NewError(sso.ErrCodeIdPRejected, p.errf("response has no id_token"), http.StatusBadGateway, nil)
	}
	j, err := p.verifyIDToken(ctx, tr.IDToken)
	if err != nil {
		return nil, err
	}
	if j.claims.Nonce != req.Nonce {
		return nil, sso.ErrStateInvalid("id token nonce mismatch")
	}
	return &sso.IdentityResult{
		ProviderID: p.cfg.ID, Protocol: sso.ProtocolOIDC,
		User: p.userFromClaims(j), Tokens: p.toTokens(tr),
	}, nil
}

// ValidateToken verifies an ID token's signature, issuer, audience and expiry.
func (p *Provider) ValidateToken(ctx context.Context, token string) (*sso.Claims, error) {
	j, err := p.verifyIDToken(ctx, token)
	if err != nil {
		return nil, err
	}
	c := j.claims
	u := p.userFromClaims(j)
	return &sso.Claims{
		Subject: c.Subject, Issuer: c.Issuer, Audience: []string(c.Audience),
		ExpiresAt: c.ExpiresAt, IssuedAt: c.IssuedAt, NotBefore: c.NotBefore,
		Email: c.Email, EmailVerified: c.EmailVerified, Name: c.Name,
		Roles: u.Roles, Groups: u.Groups, TenantID: u.TenantID, Custom: j.raw,
	}, nil
}

// RefreshToken exchanges a refresh token. When the IdP does not rotate it, the
// original is carried over. A returned ID token is verified.
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
	if tr.IDToken != "" {
		if _, err := p.verifyIDToken(ctx, tr.IDToken); err != nil {
			return nil, err
		}
	}
	return p.toTokens(tr), nil
}

// RevokeToken revokes an access or refresh token (RFC 7009) when the IdP
// advertises a revocation endpoint.
func (p *Provider) RevokeToken(ctx context.Context, token string) error {
	d, err := p.endpoints(ctx)
	if err != nil {
		return err
	}
	if d.RevocationEndpoint == "" {
		return sso.NewError(sso.ErrCodeUnsupportedMethod, p.errf("revocation not advertised"), http.StatusNotImplemented, nil)
	}
	form := url.Values{"token": {token}}
	basic := p.clientAuth(form)
	status, err := p.postForm(ctx, d.RevocationEndpoint, form, basic, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return sso.NewError(sso.ErrCodeIdPRejected, p.errf("revoke failed (status %d)", status), http.StatusBadGateway, nil)
	}
	return nil
}

// GetLogoutURL builds an RP-initiated logout URL from end_session_endpoint,
// or uses the vendor override.
func (p *Provider) GetLogoutURL(ctx context.Context, req sso.LogoutRequest) (*sso.LogoutURLResponse, error) {
	if req.PostLogoutURL != "" {
		if err := ValidateURL(p.cfg.Name, "post_logout_url", req.PostLogoutURL); err != nil {
			return nil, err
		}
	}
	if p.cfg.LogoutURL != nil {
		raw, err := p.cfg.LogoutURL(req)
		if err != nil {
			return nil, err
		}
		return &sso.LogoutURLResponse{URL: raw}, nil
	}
	d, err := p.endpoints(ctx)
	if err != nil {
		return nil, err
	}
	if d.EndSessionEndpoint == "" {
		return nil, sso.NewError(sso.ErrCodeUnsupportedMethod, p.errf("logout endpoint not advertised"), http.StatusNotImplemented, nil)
	}
	u, err := url.Parse(d.EndSessionEndpoint)
	if err != nil {
		return nil, p.netErr("bad end_session_endpoint", err)
	}
	q := u.Query()
	if req.IDTokenHint != "" {
		q.Set("id_token_hint", req.IDTokenHint)
	}
	if req.PostLogoutURL != "" {
		q.Set("post_logout_redirect_uri", req.PostLogoutURL)
	}
	if req.State != "" {
		q.Set("state", req.State)
	}
	u.RawQuery = q.Encode()
	return &sso.LogoutURLResponse{URL: u.String()}, nil
}

// FetchUserInfo calls the userinfo endpoint with an access token.
func (p *Provider) FetchUserInfo(ctx context.Context, accessToken string) (*sso.UserInfo, error) {
	if accessToken == "" {
		return nil, sso.ErrTokenValidation(p.errf("access token is empty"), nil)
	}
	d, err := p.endpoints(ctx)
	if err != nil {
		return nil, err
	}
	if d.UserinfoEndpoint == "" {
		return nil, sso.NewError(sso.ErrCodeUnsupportedMethod, p.errf("userinfo not advertised"), http.StatusNotImplemented, nil)
	}
	var raw map[string]any
	if err := p.getJSON(ctx, d.UserinfoEndpoint, accessToken, &raw); err != nil {
		return nil, err
	}
	str := func(k string) string { s, _ := raw[k].(string); return s }
	verified, _ := raw["email_verified"].(bool)
	u := &sso.UserInfo{
		ID: str("sub"), Email: str("email"), EmailVerified: verified, Username: str("email"),
		FirstName: str("given_name"), LastName: str("family_name"), DisplayName: str("name"),
		AvatarURL: str("picture"), RawAttributes: raw,
	}
	if p.cfg.MapUser != nil {
		p.cfg.MapUser(raw, u)
	}
	return u, nil
}

// Strings reads a claim that is either a string or an array of strings.
func Strings(raw map[string]any, key string) []string {
	switch v := raw[key].(type) {
	case string:
		if v != "" {
			return []string{v}
		}
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// String reads a string claim.
func String(raw map[string]any, key string) string {
	s, _ := raw[key].(string)
	return s
}

var _ sso.Provider = (*Provider)(nil)
