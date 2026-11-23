// Package google implements an OpenID Connect provider for Google sign-in.
//
// It uses OIDC discovery, the authorization code flow with PKCE (S256), and
// verifies ID tokens (RS256 signature against Google's JWKS, iss, aud, exp,
// nbf and nonce). An optional hosted-domain restriction limits sign-in to one
// Google Workspace domain.
//
// Importing the package registers the "google" driver with the sso registry.
package google

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/universal-sso/universal-sso/pkg/sso"
)

// DriverName is the name under which the provider is registered.
const DriverName = "google"

// DefaultDiscoveryURL is Google's OIDC discovery document.
const DefaultDiscoveryURL = "https://accounts.google.com/.well-known/openid-configuration"

const (
	googleIssuer    = "https://accounts.google.com"
	googleIssuerAlt = "accounts.google.com"
	clockSkew       = time.Minute
	cacheTTL        = time.Hour
	maxBody         = 1 << 20 // 1 MiB cap on IdP responses
)

var defaultScopes = []string{"openid", "email", "profile"}

func init() {
	sso.RegisterDriver(DriverName, func(cfg map[string]string) (sso.Provider, error) {
		return New(Config{
			ID:           cfg["id"],
			ClientID:     cfg["client_id"],
			ClientSecret: cfg["client_secret"],
			RedirectURL:  cfg["redirect_url"],
			HostedDomain: cfg["hosted_domain"],
			DiscoveryURL: cfg["discovery_url"],
		})
	})
}

// Config configures the provider.
type Config struct {
	ID           string // provider ID used in URLs (default "google")
	ClientID     string
	ClientSecret string
	RedirectURL  string
	HostedDomain string       // optional: only accept this Workspace domain
	DiscoveryURL string       // optional: override, used by tests
	HTTPClient   *http.Client // optional
}

type discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
}

// Provider is the Google OIDC provider.
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

// New validates cfg and creates the provider. No network access happens here.
func New(cfg Config) (*Provider, error) {
	if cfg.ID == "" {
		cfg.ID = DriverName
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.RedirectURL == "" {
		return nil, sso.ErrInvalidConfig("google: client_id, client_secret and redirect_url are required", nil)
	}
	if strings.HasPrefix(cfg.ClientID, "GOCSPX-") {
		return nil, sso.ErrInvalidConfig("google: client_id looks like a client secret (GOCSPX-...)", nil)
	}
	if u, err := url.Parse(cfg.RedirectURL); err != nil || u.Scheme == "" || u.Host == "" {
		return nil, sso.ErrInvalidConfig("google: redirect_url must be an absolute URL", err)
	}
	if cfg.DiscoveryURL == "" {
		cfg.DiscoveryURL = DefaultDiscoveryURL
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &Provider{cfg: cfg, http: hc, now: time.Now, keyMinGap: time.Minute}, nil
}

func (p *Provider) ID() string                 { return p.cfg.ID }
func (p *Provider) Name() string               { return "Google" }
func (p *Provider) Protocol() sso.ProtocolType { return sso.ProtocolOIDC }

func netErr(msg string, err error) *sso.SSOError {
	return sso.NewError(sso.ErrCodeNetworkFailure, msg, http.StatusBadGateway, err)
}

// getJSON performs a GET and decodes a JSON body.
func (p *Provider) getJSON(ctx context.Context, rawURL, bearer string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return netErr("google: build request", err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := p.http.Do(req)
	if err != nil {
		return netErr("google: request failed", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return netErr("google: read response", err)
	}
	if resp.StatusCode != http.StatusOK {
		if bearer != "" && resp.StatusCode == http.StatusUnauthorized {
			return sso.ErrTokenValidation("google: access token rejected", nil)
		}
		return netErr(fmt.Sprintf("google: unexpected status %d", resp.StatusCode), nil)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return netErr("google: invalid json response", err)
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
		return nil, netErr("google: incomplete discovery document", nil)
	}
	p.disc, p.discAt = &d, p.now()
	return p.disc, nil
}

func (d *discovery) issuerAccepted(iss string) bool {
	if iss == d.Issuer {
		return true
	}
	return d.Issuer == googleIssuer && iss == googleIssuerAlt
}

// key returns the signing key for kid, refreshing the JWKS at most once per
// keyMinGap when the kid is unknown (supports key rotation).
func (p *Provider) key(ctx context.Context, d *discovery, kid string) (*rsa.PublicKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	stale := p.keys == nil || p.now().Sub(p.keysAt) >= cacheTTL
	if k, ok := p.keys[kid]; ok && !stale {
		return k, nil
	}
	if p.keys != nil && !stale && p.now().Sub(p.keysAt) < p.keyMinGap {
		return nil, sso.NewError(sso.ErrCodeSignatureInvalid, "google: unknown signing key", http.StatusUnauthorized, nil)
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
	return nil, sso.NewError(sso.ErrCodeSignatureInvalid, "google: unknown signing key", http.StatusUnauthorized, nil)
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
		return nil, sso.ErrTokenValidation("google: invalid id token", err)
	}
	pub, err := p.key(ctx, d, j.header.Kid)
	if err != nil {
		return nil, err
	}
	if err := j.verify(pub); err != nil {
		return nil, sso.NewError(sso.ErrCodeSignatureInvalid, "google: id token signature invalid", http.StatusUnauthorized, nil)
	}
	c, now := j.claims, p.now()
	switch {
	case !d.issuerAccepted(c.Issuer):
		return nil, sso.ErrTokenValidation("google: unexpected issuer", nil)
	case !c.Audience.contains(p.cfg.ClientID):
		return nil, sso.ErrTokenValidation("google: audience mismatch", nil)
	case c.ExpiresAt == 0 || now.After(time.Unix(c.ExpiresAt, 0).Add(clockSkew)):
		return nil, sso.NewError(sso.ErrCodeTokenExpired, "google: id token expired", http.StatusUnauthorized, nil)
	case c.NotBefore != 0 && now.Add(clockSkew).Before(time.Unix(c.NotBefore, 0)):
		return nil, sso.ErrTokenValidation("google: id token not yet valid", nil)
	case c.Subject == "":
		return nil, sso.ErrTokenValidation("google: id token has no subject", nil)
	}
	return j, nil
}

func (p *Provider) checkDomain(c idClaims) error {
	want := strings.TrimSpace(p.cfg.HostedDomain)
	if want == "" {
		return nil
	}
	if !strings.EqualFold(c.HostedDomain, want) {
		return sso.ErrUnauthorizedAccess("google: account is not in the allowed domain")
	}
	return nil
}

// GetAuthURL builds the Google authorization URL with state, nonce and PKCE.
func (p *Provider) GetAuthURL(ctx context.Context, req sso.AuthURLRequest) (*sso.AuthURLResponse, error) {
	if req.State == "" || req.Nonce == "" || req.CodeVerifier == "" {
		return nil, sso.ErrInvalidConfig("google: state, nonce and code verifier are required", nil)
	}
	d, err := p.endpoints(ctx)
	if err != nil {
		return nil, err
	}
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = defaultScopes
	}
	q := url.Values{}
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
	if p.cfg.HostedDomain != "" {
		q.Set("hd", p.cfg.HostedDomain) // UI hint only; enforced after sign-in
	}
	u, err := url.Parse(d.AuthorizationEndpoint)
	if err != nil {
		return nil, netErr("google: bad authorization endpoint", err)
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

func (p *Provider) postForm(ctx context.Context, endpoint string, form url.Values, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, netErr("google: build request", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.http.Do(req)
	if err != nil {
		return 0, netErr("google: request failed", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return resp.StatusCode, netErr("google: read response", err)
	}
	if out != nil && len(body) > 0 {
		if err := json.Unmarshal(body, out); err != nil && resp.StatusCode == http.StatusOK {
			return resp.StatusCode, netErr("google: invalid json response", err)
		}
	}
	return resp.StatusCode, nil
}

func (p *Provider) tokenRequest(ctx context.Context, form url.Values) (*tokenReply, error) {
	d, err := p.endpoints(ctx)
	if err != nil {
		return nil, err
	}
	form.Set("client_id", p.cfg.ClientID)
	form.Set("client_secret", p.cfg.ClientSecret)
	var tr tokenReply
	status, err := p.postForm(ctx, d.TokenEndpoint, form, &tr)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK || tr.Error != "" {
		msg := "google: token request rejected"
		if tr.Error != "" {
			msg += ": " + tr.Error
			if tr.ErrorDesc != "" {
				msg += " (" + tr.ErrorDesc + ")"
			}
		}
		return nil, sso.NewError(sso.ErrCodeIdPRejected, msg, http.StatusUnauthorized, nil)
	}
	if tr.AccessToken == "" {
		return nil, sso.NewError(sso.ErrCodeIdPRejected, "google: token response has no access token", http.StatusBadGateway, nil)
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

func userFromClaims(j *parsedJWT) *sso.UserInfo {
	c := j.claims
	return &sso.UserInfo{
		ID: c.Subject, Email: c.Email, EmailVerified: c.EmailVerified,
		Username: c.Email, FirstName: c.GivenName, LastName: c.FamilyName,
		DisplayName: c.Name, AvatarURL: c.Picture, TenantID: c.HostedDomain,
		RawAttributes: j.raw,
	}
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
		return nil, sso.NewError(sso.ErrCodeIdPRejected, "google: response has no id_token", http.StatusBadGateway, nil)
	}
	j, err := p.verifyIDToken(ctx, tr.IDToken)
	if err != nil {
		return nil, err
	}
	if j.claims.Nonce != req.Nonce {
		return nil, sso.ErrStateInvalid("id token nonce mismatch")
	}
	if err := p.checkDomain(j.claims); err != nil {
		return nil, err
	}
	return &sso.IdentityResult{
		ProviderID: p.cfg.ID, Protocol: sso.ProtocolOIDC,
		User: userFromClaims(j), Tokens: p.toTokens(tr),
	}, nil
}

// ValidateToken verifies an ID token's signature, issuer, audience and expiry.
func (p *Provider) ValidateToken(ctx context.Context, token string) (*sso.Claims, error) {
	j, err := p.verifyIDToken(ctx, token)
	if err != nil {
		return nil, err
	}
	if err := p.checkDomain(j.claims); err != nil {
		return nil, err
	}
	c := j.claims
	return &sso.Claims{
		Subject: c.Subject, Issuer: c.Issuer, Audience: []string(c.Audience),
		ExpiresAt: c.ExpiresAt, IssuedAt: c.IssuedAt, NotBefore: c.NotBefore,
		Email: c.Email, EmailVerified: c.EmailVerified, Name: c.Name, TenantID: c.HostedDomain,
		Custom: j.raw,
	}, nil
}

// RefreshToken exchanges a refresh token. Google omits the refresh token in the
// reply, so the original is carried over.
func (p *Provider) RefreshToken(ctx context.Context, refreshToken string) (*sso.TokenResponse, error) {
	if refreshToken == "" {
		return nil, sso.ErrTokenValidation("google: refresh token is empty", nil)
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

// RevokeToken revokes an access or refresh token at Google.
func (p *Provider) RevokeToken(ctx context.Context, token string) error {
	d, err := p.endpoints(ctx)
	if err != nil {
		return err
	}
	if d.RevocationEndpoint == "" {
		return sso.NewError(sso.ErrCodeUnsupportedMethod, "google: revocation not advertised", http.StatusNotImplemented, nil)
	}
	status, err := p.postForm(ctx, d.RevocationEndpoint, url.Values{"token": {token}}, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return sso.NewError(sso.ErrCodeIdPRejected, fmt.Sprintf("google: revoke failed (status %d)", status), http.StatusBadGateway, nil)
	}
	return nil
}

// GetLogoutURL is unsupported: Google offers no RP-initiated logout endpoint.
func (p *Provider) GetLogoutURL(context.Context, sso.LogoutRequest) (*sso.LogoutURLResponse, error) {
	return nil, sso.NewError(sso.ErrCodeUnsupportedMethod, "google: single logout is not supported", http.StatusNotImplemented, nil)
}

// FetchUserInfo calls Google's userinfo endpoint with an access token.
func (p *Provider) FetchUserInfo(ctx context.Context, accessToken string) (*sso.UserInfo, error) {
	if accessToken == "" {
		return nil, sso.ErrTokenValidation("google: access token is empty", nil)
	}
	d, err := p.endpoints(ctx)
	if err != nil {
		return nil, err
	}
	if d.UserinfoEndpoint == "" {
		return nil, sso.NewError(sso.ErrCodeUnsupportedMethod, "google: userinfo not advertised", http.StatusNotImplemented, nil)
	}
	var raw map[string]any
	if err := p.getJSON(ctx, d.UserinfoEndpoint, accessToken, &raw); err != nil {
		return nil, err
	}
	str := func(k string) string { s, _ := raw[k].(string); return s }
	verified, _ := raw["email_verified"].(bool)
	return &sso.UserInfo{
		ID: str("sub"), Email: str("email"), EmailVerified: verified, Username: str("email"),
		FirstName: str("given_name"), LastName: str("family_name"), DisplayName: str("name"),
		AvatarURL: str("picture"), TenantID: str("hd"), RawAttributes: raw,
	}, nil
}

var _ sso.Provider = (*Provider)(nil)
