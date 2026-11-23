// Package auth0 is an OpenID Connect provider for Auth0. It is a thin vendor
// layer over package oidc that adds the API audience parameter, roles and
// groups claims, and Auth0's /v2/logout URL.
//
// Importing the package registers the "auth0" driver with the sso registry.
package auth0

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/universal-sso/universal-sso/pkg/sso"
	"github.com/universal-sso/universal-sso/pkg/sso/oidc"
)

// DriverName is the name under which the provider is registered.
const DriverName = "auth0"

func init() {
	sso.RegisterDriver(DriverName, func(cfg map[string]string) (sso.Provider, error) {
		p, err := New(Config{
			ID:           cfg["id"],
			ClientID:     cfg["client_id"],
			ClientSecret: cfg["client_secret"],
			RedirectURL:  cfg["redirect_url"],
			IssuerURL:    cfg["issuer_url"],
			Audience:     cfg["audience"],
			RolesClaim:   cfg["roles_claim"],
			Scopes:       strings.Fields(cfg["scopes"]),
		})
		if err != nil {
			return nil, err // never wrap a nil *Provider in the interface
		}
		return p, nil
	})
}

// Config configures the provider.
type Config struct {
	ID           string // provider ID used in URLs (default "auth0")
	ClientID     string
	ClientSecret string
	RedirectURL  string
	// IssuerURL is https://<tenant>.<region>.auth0.com/ (or a custom domain).
	// Auth0 puts a trailing slash in the ID token's iss, which is preserved.
	IssuerURL string
	// Audience is the optional API identifier sent as the audience parameter.
	Audience string
	// RolesClaim is the (usually namespaced) claim that carries roles.
	// Default "roles".
	RolesClaim   string
	Scopes       []string // default: openid email profile
	DiscoveryURL string   // optional override, used by tests
	HTTPClient   *http.Client
}

// New validates cfg and creates the provider. No network access happens here.
func New(cfg Config) (*oidc.Provider, error) {
	if cfg.ID == "" {
		cfg.ID = DriverName
	}
	if cfg.RolesClaim == "" {
		cfg.RolesClaim = "roles"
	}
	issuer := cfg.IssuerURL
	if issuer != "" && !strings.HasSuffix(issuer, "/") {
		issuer += "/" // Auth0 issuers always end with a slash
	}
	extra := map[string]string{}
	if cfg.Audience != "" {
		extra["audience"] = cfg.Audience
	}
	return oidc.New(oidc.Config{
		ID: cfg.ID, Name: "Auth0",
		ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, RedirectURL: cfg.RedirectURL,
		Issuer: issuer, DiscoveryURL: cfg.DiscoveryURL, Scopes: cfg.Scopes,
		HTTPClient: cfg.HTTPClient, ExtraAuthParams: extra,
		MapUser: func(raw map[string]any, u *sso.UserInfo) {
			if v := oidc.String(raw, "nickname"); v != "" {
				u.Username = v
			}
			u.Roles = oidc.Strings(raw, cfg.RolesClaim)
			u.Groups = oidc.Strings(raw, "groups")
			u.TenantID = oidc.String(raw, "org_id")
		},
		// Auth0 does not use end_session_endpoint for its default tenant
		// domain: logout is <issuer>v2/logout?client_id=...&returnTo=...
		LogoutURL: func(req sso.LogoutRequest) (string, error) {
			q := url.Values{"client_id": {cfg.ClientID}}
			if req.PostLogoutURL != "" {
				q.Set("returnTo", req.PostLogoutURL)
			}
			return issuer + "v2/logout?" + q.Encode(), nil
		},
	})
}
