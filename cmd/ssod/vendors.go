package main

import (
	"fmt"
	"strings"

	"github.com/universal-sso/universal-sso/pkg/sso"
	"github.com/universal-sso/universal-sso/pkg/sso/auth0"
	"github.com/universal-sso/universal-sso/pkg/sso/entra"
	"github.com/universal-sso/universal-sso/pkg/sso/oauth2"
	"github.com/universal-sso/universal-sso/pkg/sso/okta"
)

// legacyOktaSampleID is the client id older copies of .env.example shipped.
const legacyOktaSampleID = "0oa123456789okta"

// vendorEnv reads the settings every OIDC vendor shares. It returns ok=false
// when the vendor is not configured (client id empty or an unedited sample),
// so a fresh copy of .env.example still starts the server. A configured client
// id with a missing secret is an error: that is a half-finished setup.
func vendorEnv(getenv func(string) string, name, prefix string) (id, secret, redirect string, ok bool, err error) {
	id, secret = getenv(prefix+"_CLIENT_ID"), getenv(prefix+"_CLIENT_SECRET") // nosecret: env var names
	if isPlaceholder(id) || id == legacyOktaSampleID {
		return "", "", "", false, nil
	}
	if isPlaceholder(secret) {
		return "", "", "", false, fmt.Errorf("%s_CLIENT_SECRET is not set (client id is configured)", prefix) // nosecret
	}
	redirect = getenv(prefix + "_REDIRECT_URL")
	if redirect == "" {
		base := strings.TrimRight(getenv("SSO_SERVER_BASE_URL"), "/")
		if base == "" {
			return "", "", "", false, fmt.Errorf("set %s_REDIRECT_URL or SSO_SERVER_BASE_URL", prefix)
		}
		redirect = base + "/auth/" + name + "/callback"
	}
	return id, secret, redirect, true, nil
}

// oktaFromEnv builds the Okta provider (id "okta") or returns (nil, nil).
func oktaFromEnv(getenv func(string) string) (sso.Provider, error) {
	const prefix = "SSO_PROVIDERS_OKTA"
	id, secret, redirect, ok, err := vendorEnv(getenv, "okta", prefix)
	if !ok || err != nil {
		return nil, err
	}
	p, err := okta.New(okta.Config{
		ID: "okta", ClientID: id, ClientSecret: secret, RedirectURL: redirect,
		IssuerURL: getenv(prefix + "_ISSUER_URL"),
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

// auth0FromEnv builds the Auth0 provider (id "auth0") or returns (nil, nil).
func auth0FromEnv(getenv func(string) string) (sso.Provider, error) {
	const prefix = "SSO_PROVIDERS_AUTH0"
	id, secret, redirect, ok, err := vendorEnv(getenv, "auth0", prefix)
	if !ok || err != nil {
		return nil, err
	}
	p, err := auth0.New(auth0.Config{
		ID: "auth0", ClientID: id, ClientSecret: secret, RedirectURL: redirect,
		IssuerURL:  getenv(prefix + "_ISSUER_URL"),
		Audience:   getenv(prefix + "_AUDIENCE"),
		RolesClaim: getenv(prefix + "_ROLES_CLAIM"),
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

// oauth2FromEnv builds the generic OAuth 2.0 provider (id "oauth2") or returns
// (nil, nil). The authorization, token and profile URLs come only from the
// environment, never from request data.
func oauth2FromEnv(getenv func(string) string) (sso.Provider, error) {
	const prefix = "SSO_PROVIDERS_OAUTH2"
	id, secret, redirect, ok, err := vendorEnv(getenv, "oauth2", prefix)
	if !ok || err != nil {
		return nil, err
	}
	p, err := oauth2.New(oauth2.Config{
		ID: "oauth2", ClientID: id, ClientSecret: secret, RedirectURL: redirect,
		AuthURL:     getenv(prefix + "_AUTH_URL"),
		TokenURL:    getenv(prefix + "_TOKEN_URL"),
		UserinfoURL: getenv(prefix + "_USERINFO_URL"),
		RevokeURL:   getenv(prefix + "_REVOKE_URL"),
		Scopes:      strings.Fields(getenv(prefix + "_SCOPES")),
		UserIDField: getenv(prefix + "_USER_ID_FIELD"),
		AuthStyle:   getenv(prefix + "_AUTH_STYLE"),
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

// azureFromEnv builds the Microsoft Entra provider (id "azure") or returns (nil, nil).
func azureFromEnv(getenv func(string) string) (sso.Provider, error) {
	const prefix = "SSO_PROVIDERS_AZURE"
	id, secret, redirect, ok, err := vendorEnv(getenv, "azure", prefix)
	if !ok || err != nil {
		return nil, err
	}
	p, err := entra.New(entra.Config{
		ID: "azure", ClientID: id, ClientSecret: secret, RedirectURL: redirect,
		TenantID:       getenv(prefix + "_TENANT_ID"),
		AllowedTenants: strings.FieldsFunc(getenv(prefix+"_ALLOWED_TENANTS"), func(r rune) bool { return r == ',' || r == ' ' }),
		Authority:      getenv(prefix + "_AUTHORITY"),
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}
