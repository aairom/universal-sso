// Package okta is an OpenID Connect provider for Okta (org or custom
// authorization server). It is a thin vendor layer over package oidc.
//
// Importing the package registers the "okta" driver with the sso registry.
package okta

import (
	"net/http"
	"strings"

	"github.com/universal-sso/universal-sso/pkg/sso"
	"github.com/universal-sso/universal-sso/pkg/sso/oidc"
)

// DriverName is the name under which the provider is registered.
const DriverName = "okta"

func init() {
	sso.RegisterDriver(DriverName, func(cfg map[string]string) (sso.Provider, error) {
		return New(Config{
			ID:           cfg["id"],
			ClientID:     cfg["client_id"],
			ClientSecret: cfg["client_secret"],
			RedirectURL:  cfg["redirect_url"],
			IssuerURL:    cfg["issuer_url"],
			Scopes:       strings.Fields(cfg["scopes"]),
		})
	})
}

// Config configures the provider.
type Config struct {
	ID           string // provider ID used in URLs (default "okta")
	ClientID     string
	ClientSecret string
	RedirectURL  string
	// IssuerURL is the authorization server issuer, for example
	// https://<org>.okta.com/oauth2/default (custom server) or
	// https://<org>.okta.com (org server).
	IssuerURL    string
	Scopes       []string // default: openid email profile
	DiscoveryURL string   // optional override, used by tests
	HTTPClient   *http.Client
}

// New validates cfg and creates the provider. No network access happens here.
func New(cfg Config) (*oidc.Provider, error) {
	if cfg.ID == "" {
		cfg.ID = DriverName
	}
	return oidc.New(oidc.Config{
		ID: cfg.ID, Name: "Okta",
		ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, RedirectURL: cfg.RedirectURL,
		Issuer: cfg.IssuerURL, DiscoveryURL: cfg.DiscoveryURL, Scopes: cfg.Scopes,
		HTTPClient: cfg.HTTPClient,
		MapUser: func(raw map[string]any, u *sso.UserInfo) {
			if v := oidc.String(raw, "preferred_username"); v != "" {
				u.Username = v
			}
			u.Groups = oidc.Strings(raw, "groups")
			u.TenantID = strings.TrimRight(oidc.String(raw, "iss"), "/")
		},
	})
}
