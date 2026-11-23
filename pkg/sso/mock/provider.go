// Package mock provides an in-memory identity provider for tests and offline development.
package mock

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/universal-sso/universal-sso/pkg/sso"
)

// DriverName is the name under which the mock provider is registered.
const DriverName = "mock"

func init() {
	sso.RegisterDriver(DriverName, func(cfg map[string]string) (sso.Provider, error) {
		id := cfg["id"]
		if id == "" {
			id = DriverName
		}
		return New(id), nil
	})
}

type session struct {
	user    sso.UserInfo
	expires time.Time
}

// Provider simulates an OIDC provider with PKCE verification and opaque tokens.
type Provider struct {
	id   string
	user sso.UserInfo

	authorizeURL string // where GetAuthURL sends the browser

	mu         sync.Mutex
	challenges map[string]string  // state -> code_challenge
	access     map[string]session // access token -> session
	refresh    map[string]bool    // valid refresh tokens
}

// New creates a mock provider that always authenticates the default test user.
func New(id string) *Provider {
	return &Provider{
		id: id,
		user: sso.UserInfo{
			ID: "mock-user-1", Email: "user@example.test", EmailVerified: true, // nosecret: synthetic fixture
			Username: "mockuser", DisplayName: "Mock User", Roles: []string{"user"},
		},
		authorizeURL: "https://mock.idp.invalid/authorize",
		challenges:   map[string]string{},
		access:       map[string]session{},
		refresh:      map[string]bool{},
	}
}

// SetAuthorizeURL overrides the authorization endpoint returned by GetAuthURL.
// A relative path such as "/mock/authorize" lets a local server act as the IdP.
func (p *Provider) SetAuthorizeURL(u string) { p.authorizeURL = u }

func (p *Provider) ID() string                 { return p.id }
func (p *Provider) Name() string               { return "Mock Provider" }
func (p *Provider) Protocol() sso.ProtocolType { return sso.ProtocolMock }

// GetAuthURL records the PKCE challenge for the state and returns a synthetic URL.
func (p *Provider) GetAuthURL(_ context.Context, req sso.AuthURLRequest) (*sso.AuthURLResponse, error) {
	if req.State == "" {
		return nil, sso.ErrInvalidConfig("state is required", nil)
	}
	challenge := sso.CodeChallengeS256(req.CodeVerifier)
	p.mu.Lock()
	p.challenges[req.State] = challenge
	p.mu.Unlock()

	q := url.Values{}
	q.Set("state", req.State)
	q.Set("nonce", req.Nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	return &sso.AuthURLResponse{
		URL:          p.authorizeURL + "?" + q.Encode(),
		State:        req.State,
		Nonce:        req.Nonce,
		CodeVerifier: req.CodeVerifier,
	}, nil
}

func (p *Provider) issue(u sso.UserInfo) (*sso.TokenResponse, error) {
	at, err := sso.RandomString(24)
	if err != nil {
		return nil, sso.NewError(sso.ErrCodeInternal, "token generation failed", http.StatusInternalServerError, err)
	}
	rt, err := sso.RandomString(24)
	if err != nil {
		return nil, sso.NewError(sso.ErrCodeInternal, "token generation failed", http.StatusInternalServerError, err)
	}
	const ttl = time.Hour
	exp := time.Now().Add(ttl)
	p.mu.Lock()
	p.access[at] = session{user: u, expires: exp}
	p.refresh[rt] = true
	p.mu.Unlock()
	return &sso.TokenResponse{
		AccessToken: at, TokenType: "Bearer", RefreshToken: rt,
		ExpiresIn: int64(ttl.Seconds()), ExpiresAt: exp,
	}, nil
}

// HandleCallback verifies the PKCE verifier against the recorded challenge.
func (p *Provider) HandleCallback(_ context.Context, req sso.CallbackRequest) (*sso.IdentityResult, error) {
	if req.Code == "" {
		return nil, sso.NewError(sso.ErrCodeIdPRejected, "missing authorization code", http.StatusBadRequest, nil)
	}
	p.mu.Lock()
	want, ok := p.challenges[req.State]
	delete(p.challenges, req.State)
	p.mu.Unlock()
	if !ok || want != sso.CodeChallengeS256(req.CodeVerifier) {
		return nil, sso.NewError(sso.ErrCodeIdPRejected, "pkce verification failed", http.StatusUnauthorized, nil)
	}
	tokens, err := p.issue(p.user)
	if err != nil {
		return nil, err
	}
	u := p.user
	return &sso.IdentityResult{ProviderID: p.id, Protocol: sso.ProtocolMock, User: &u, Tokens: tokens}, nil
}

func (p *Provider) lookup(token string) (session, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.access[token]
	if !ok {
		return session{}, sso.ErrTokenValidation("unknown token", nil)
	}
	if time.Now().After(s.expires) {
		return session{}, sso.NewError(sso.ErrCodeTokenExpired, "token expired", http.StatusUnauthorized, nil)
	}
	return s, nil
}

// ValidateToken checks that the token was issued by this provider and is unexpired.
func (p *Provider) ValidateToken(_ context.Context, token string) (*sso.Claims, error) {
	s, err := p.lookup(token)
	if err != nil {
		return nil, err
	}
	return &sso.Claims{
		Subject: s.user.ID, Issuer: p.id, Audience: []string{p.id},
		ExpiresAt: s.expires.Unix(), Email: s.user.Email,
		EmailVerified: s.user.EmailVerified, Roles: s.user.Roles,
	}, nil
}

// RefreshToken rotates a refresh token (single use) and issues new tokens.
func (p *Provider) RefreshToken(_ context.Context, refreshToken string) (*sso.TokenResponse, error) {
	p.mu.Lock()
	valid := p.refresh[refreshToken]
	delete(p.refresh, refreshToken)
	p.mu.Unlock()
	if !valid {
		return nil, sso.ErrTokenValidation("invalid refresh token", nil)
	}
	return p.issue(p.user)
}

// RevokeToken invalidates an access or refresh token.
func (p *Provider) RevokeToken(_ context.Context, token string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.access, token)
	delete(p.refresh, token)
	return nil
}

// GetLogoutURL returns a synthetic single-logout URL.
func (p *Provider) GetLogoutURL(_ context.Context, req sso.LogoutRequest) (*sso.LogoutURLResponse, error) {
	q := url.Values{}
	if req.PostLogoutURL != "" {
		q.Set("post_logout_redirect_uri", req.PostLogoutURL)
	}
	if req.State != "" {
		q.Set("state", req.State)
	}
	return &sso.LogoutURLResponse{URL: "https://mock.idp.invalid/logout?" + q.Encode()}, nil
}

// FetchUserInfo returns the profile bound to an active access token.
func (p *Provider) FetchUserInfo(_ context.Context, accessToken string) (*sso.UserInfo, error) {
	s, err := p.lookup(accessToken)
	if err != nil {
		return nil, err
	}
	u := s.user
	return &u, nil
}

var _ sso.Provider = (*Provider)(nil)
