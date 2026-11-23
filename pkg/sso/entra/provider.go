// Package entra is an OpenID Connect provider for Microsoft Entra ID (Azure
// AD) using the v2.0 endpoints. It is a thin vendor layer over package oidc.
//
// Tenant handling is the security-critical part:
//   - a tenant GUID pins the issuer exactly;
//   - a tenant domain name (contoso.onmicrosoft.com) is resolved by discovery
//     and then pinned to the GUID issuer that discovery announces;
//   - common, organizations and consumers are multi-tenant. Every tenant has
//     its own issuer, so the issuer must equal
//     https://login.microsoftonline.com/<tid>/v2.0 for the token's own tid.
//     Restrict which tenants may sign in with AllowedTenants.
//
// Importing the package registers the "entra" driver with the sso registry.
package entra

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/universal-sso/universal-sso/pkg/sso"
	"github.com/universal-sso/universal-sso/pkg/sso/oidc"
)

// DriverName is the name under which the provider is registered.
const DriverName = "entra"

// LoginHost is the Microsoft identity platform host.
const LoginHost = "https://login.microsoftonline.com/"

func init() {
	sso.RegisterDriver(DriverName, func(cfg map[string]string) (sso.Provider, error) {
		p, err := New(Config{
			ID:             cfg["id"],
			ClientID:       cfg["client_id"],
			ClientSecret:   cfg["client_secret"],
			RedirectURL:    cfg["redirect_url"],
			TenantID:       cfg["tenant_id"],
			Authority:      cfg["authority"],
			AllowedTenants: strings.FieldsFunc(cfg["allowed_tenants"], func(r rune) bool { return r == ',' || r == ' ' }),
			Scopes:         strings.Fields(cfg["scopes"]),
		})
		if err != nil {
			return nil, err // never wrap a nil *Provider in the interface
		}
		return p, nil
	})
}

var (
	guidRe   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	domainRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`)
)

func multiTenant(t string) bool {
	switch strings.ToLower(t) {
	case "common", "organizations", "consumers":
		return true
	}
	return false
}

// Config configures the provider.
type Config struct {
	ID           string // provider ID used in URLs (default "entra")
	ClientID     string
	ClientSecret string
	RedirectURL  string
	// TenantID is a tenant GUID, a tenant domain, or one of common,
	// organizations, consumers.
	TenantID string
	// AllowedTenants restricts multi-tenant sign-in to these tenant GUIDs.
	// Empty means any tenant the endpoint admits. Ignored for single tenants.
	AllowedTenants []string
	// Authority is the identity platform host, default LoginHost. Set it for
	// sovereign clouds, for example https://login.microsoftonline.us/.
	Authority    string
	Scopes       []string // default: openid email profile
	DiscoveryURL string   // optional override
	HTTPClient   *http.Client
}

// New validates cfg and creates the provider. No network access happens here.
func New(cfg Config) (*oidc.Provider, error) {
	if cfg.ID == "" {
		cfg.ID = DriverName
	}
	tenant := strings.TrimSpace(cfg.TenantID)
	if tenant == "" {
		return nil, sso.ErrInvalidConfig("Entra: tenant_id is required", nil)
	}
	if !guidRe.MatchString(tenant) && !domainRe.MatchString(tenant) {
		return nil, sso.ErrInvalidConfig("Entra: tenant_id must be a GUID, a domain or common/organizations/consumers", nil)
	}
	multi, single := multiTenant(tenant), guidRe.MatchString(tenant)
	allowed := map[string]bool{}
	for _, t := range cfg.AllowedTenants {
		if !guidRe.MatchString(t) {
			return nil, sso.ErrInvalidConfig("Entra: allowed_tenants entries must be tenant GUIDs", nil)
		}
		allowed[strings.ToLower(t)] = true
	}
	host := cfg.Authority
	if host == "" {
		host = LoginHost
	}
	if err := oidc.ValidateURL("Entra", "authority", host); err != nil {
		return nil, err
	}
	host = strings.TrimRight(host, "/") + "/"
	issuer := host + strings.ToLower(tenant) + "/v2.0"
	if single {
		issuer = host + tenant + "/v2.0"
	}
	oc := oidc.Config{
		ID: cfg.ID, Name: "Entra",
		ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, RedirectURL: cfg.RedirectURL,
		Issuer: issuer, DiscoveryURL: cfg.DiscoveryURL, Scopes: cfg.Scopes,
		HTTPClient: cfg.HTTPClient,
		MapUser: func(raw map[string]any, u *sso.UserInfo) {
			if v := oidc.String(raw, "preferred_username"); v != "" {
				u.Username = v
			}
			u.Roles = oidc.Strings(raw, "roles")
			u.Groups = oidc.Strings(raw, "groups")
			u.TenantID = oidc.String(raw, "tid")
			// "email" in Entra tokens is not verified by Microsoft.
			u.EmailVerified = false
		},
	}
	switch {
	case multi:
		oc.AcceptDiscoveryIssuer = func(iss string) bool { return iss == host+"{tenantid}/v2.0" }
		oc.AcceptIssuer = func(tokenIss, _ string, claims map[string]any) bool {
			tid := oidc.String(claims, "tid")
			if !guidRe.MatchString(tid) || tokenIss != host+tid+"/v2.0" {
				return false
			}
			return len(allowed) == 0 || allowed[strings.ToLower(tid)]
		}
	case !single:
		// Tenant domain: discovery announces the GUID issuer, which then pins tokens.
		oc.AcceptDiscoveryIssuer = func(iss string) bool {
			return strings.HasPrefix(iss, host) && strings.HasSuffix(iss, "/v2.0") &&
				guidRe.MatchString(strings.TrimSuffix(strings.TrimPrefix(iss, host), "/v2.0"))
		}
	}
	return oidc.New(oc)
}
