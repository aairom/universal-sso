package sso

import (
	"context"
	"time"
)

// ProtocolType identifies the authentication protocol being used.
type ProtocolType string

const (
	ProtocolOIDC   ProtocolType = "oidc"
	ProtocolOAuth2 ProtocolType = "oauth2"
	ProtocolSAML2  ProtocolType = "saml2"
	ProtocolMock   ProtocolType = "mock"
)

// UserInfo represents normalized user identity details retrieved across any SSO provider.
type UserInfo struct {
	ID            string                 `json:"id"`
	Email         string                 `json:"email"`
	EmailVerified bool                   `json:"email_verified"`
	Username      string                 `json:"username,omitempty"`
	FirstName     string                 `json:"first_name,omitempty"`
	LastName      string                 `json:"last_name,omitempty"`
	DisplayName   string                 `json:"display_name,omitempty"`
	AvatarURL     string                 `json:"avatar_url,omitempty"`
	Roles         []string               `json:"roles,omitempty"`
	Groups        []string               `json:"groups,omitempty"`
	TenantID      string                 `json:"tenant_id,omitempty"`
	RawAttributes map[string]interface{} `json:"raw_attributes,omitempty"`
}

// TokenResponse encapsulates security tokens returned after successful authentication or refresh.
type TokenResponse struct {
	AccessToken  string                 `json:"access_token"`
	TokenType    string                 `json:"token_type"`
	RefreshToken string                 `json:"refresh_token,omitempty"`
	IDToken      string                 `json:"id_token,omitempty"`
	ExpiresIn    int64                  `json:"expires_in"` // seconds
	ExpiresAt    time.Time              `json:"expires_at"`
	Scope        string                 `json:"scope,omitempty"`
	RawData      map[string]interface{} `json:"raw_data,omitempty"`
}

// IdentityResult aggregates tokens, normalized user profile, and provider metadata.
type IdentityResult struct {
	ProviderID string         `json:"provider_id"`
	Protocol   ProtocolType   `json:"protocol"`
	User       *UserInfo      `json:"user"`
	Tokens     *TokenResponse `json:"tokens"`
	SessionID  string         `json:"session_id,omitempty"`
}

// AuthURLRequest contains the options required to generate a provider authorization URL.
type AuthURLRequest struct {
	State        string            `json:"state"`
	Nonce        string            `json:"nonce,omitempty"`
	CodeVerifier string            `json:"code_verifier,omitempty"`
	Prompt       string            `json:"prompt,omitempty"`
	LoginHint    string            `json:"login_hint,omitempty"`
	Scopes       []string          `json:"scopes,omitempty"`
	ExtraParams  map[string]string `json:"extra_params,omitempty"`
}

// AuthURLResponse holds the generated authorization URL and state/PKCE context.
type AuthURLResponse struct {
	URL          string `json:"url"`
	State        string `json:"state"`
	Nonce        string `json:"nonce,omitempty"`
	CodeVerifier string `json:"code_verifier,omitempty"`
}

// CallbackRequest standardizes incoming query parameters or form posts from identity callbacks.
type CallbackRequest struct {
	State        string            `json:"state"`
	Code         string            `json:"code,omitempty"`
	SAMLResponse string            `json:"saml_response,omitempty"`
	Error        string            `json:"error,omitempty"`
	ErrorDesc    string            `json:"error_description,omitempty"`
	CodeVerifier string            `json:"code_verifier,omitempty"`
	Nonce        string            `json:"nonce,omitempty"`
	RawParams    map[string]string `json:"raw_params,omitempty"`
}

// LogoutRequest represents parameters to build a single sign-out request.
type LogoutRequest struct {
	IDTokenHint   string `json:"id_token_hint,omitempty"`
	PostLogoutURL string `json:"post_logout_url,omitempty"`
	State         string `json:"state,omitempty"`
	SessionIndex  string `json:"session_index,omitempty"`
	NameID        string `json:"name_id,omitempty"`
}

// LogoutURLResponse holds the constructed IdP signout URL.
type LogoutURLResponse struct {
	URL string `json:"url"`
}

// Claims represents normalized claims decoded from JWTs or SAML assertions.
type Claims struct {
	Subject       string                 `json:"sub"`
	Issuer        string                 `json:"iss"`
	Audience      []string               `json:"aud"`
	ExpiresAt     int64                  `json:"exp"`
	IssuedAt      int64                  `json:"iat"`
	NotBefore     int64                  `json:"nbf,omitempty"`
	Email         string                 `json:"email,omitempty"`
	EmailVerified bool                   `json:"email_verified,omitempty"`
	Name          string                 `json:"name,omitempty"`
	PreferredName string                 `json:"preferred_username,omitempty"`
	Roles         []string               `json:"roles,omitempty"`
	Groups        []string               `json:"groups,omitempty"`
	TenantID      string                 `json:"tid,omitempty"`
	Custom        map[string]interface{} `json:"custom,omitempty"`
}

// Provider is the universal interface implemented by all SSO identity adapters.
type Provider interface {
	// ID returns the unique identifier for this configured provider instance.
	ID() string
	// Name returns human-readable provider name.
	Name() string
	// Protocol returns the underlying protocol (oidc, oauth2, saml2, mock).
	Protocol() ProtocolType
	// GetAuthURL generates the login redirect URL with state and PKCE parameters.
	GetAuthURL(ctx context.Context, req AuthURLRequest) (*AuthURLResponse, error)
	// HandleCallback exchanges authorization codes or SAML assertions for tokens & user details.
	HandleCallback(ctx context.Context, req CallbackRequest) (*IdentityResult, error)
	// ValidateToken verifies token signature, expiry, issuer, and audience.
	ValidateToken(ctx context.Context, tokenString string) (*Claims, error)
	// RefreshToken exchanges a refresh token for new access/id tokens.
	RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error)
	// RevokeToken invalidates an active token on the remote IdP.
	RevokeToken(ctx context.Context, tokenString string) error
	// GetLogoutURL constructs the Single Logout (SLO) endpoint URL.
	GetLogoutURL(ctx context.Context, req LogoutRequest) (*LogoutURLResponse, error)
	// FetchUserInfo retrieves the latest profile details using an active access token.
	FetchUserInfo(ctx context.Context, accessToken string) (*UserInfo, error)
}
