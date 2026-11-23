// Package gateway is a small, dependency-free client for the Universal SSO
// gateway (cmd/ssod). It speaks the gateway's HTTP contract:
//
//	GET /healthz                   -> 200 {"status":"ok"}
//	GET /providers                 -> 200 {"providers":["mock","google",...]}
//	GET /auth/{provider}/login     -> 302 Location: <IdP authorization URL>
//	GET /auth/{provider}/callback  -> 200 {"provider_id":"...","user":{...}}
//	any error                      -> 4xx/5xx {"code":"...","message":"..."}
//
// The gateway keeps the signed state, PKCE verifier, client secret and tokens.
// This client never sees them; it verifies that the redirect it receives is
// safe to follow (see CheckAuthorizeURL) and reads the resulting profile.
package gateway

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DefaultGatewayURL is used when SSO_GATEWAY_URL is not set.
const DefaultGatewayURL = "http://localhost:8080"

var providerRE = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)

// Config holds the client settings, normally read from the environment.
type Config struct {
	// GatewayURL is the base URL of ssod. Plain http is only accepted for loopback hosts.
	GatewayURL *url.URL
	// Provider is the provider id registered in the gateway (for example "saml").
	Provider string
	// ExpectedIdPHost, when set, pins the identity-provider host: the login
	// redirect must go to this host or one of its subdomains.
	ExpectedIdPHost string
	// Timeout bounds every HTTP request.
	Timeout time.Duration
}

// LoadConfig reads SSO_GATEWAY_URL, SSO_PROVIDER, SSO_EXPECTED_IDP_HOST and
// SSO_HTTP_TIMEOUT_SECONDS through getenv. defaultProvider is used when
// SSO_PROVIDER is empty.
func LoadConfig(getenv func(string) string, defaultProvider string) (Config, error) {
	raw := strings.TrimSpace(getenv("SSO_GATEWAY_URL"))
	if raw == "" {
		raw = DefaultGatewayURL
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return Config{}, fmt.Errorf("SSO_GATEWAY_URL must be an http(s) URL with a host")
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		return Config{}, errors.New("SSO_GATEWAY_URL uses plain http for a non-loopback host: use https")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery, u.Fragment = "", ""

	provider := strings.TrimSpace(getenv("SSO_PROVIDER"))
	if provider == "" {
		provider = defaultProvider
	}
	if !providerRE.MatchString(provider) {
		return Config{}, fmt.Errorf("SSO_PROVIDER %q must match %s", provider, providerRE)
	}

	timeout := 10 * time.Second
	if s := strings.TrimSpace(getenv("SSO_HTTP_TIMEOUT_SECONDS")); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n <= 0 || n > 300 {
			return Config{}, errors.New("SSO_HTTP_TIMEOUT_SECONDS must be an integer from 1 to 300")
		}
		timeout = time.Duration(n) * time.Second
	}
	return Config{
		GatewayURL:      u,
		Provider:        provider,
		ExpectedIdPHost: strings.ToLower(strings.TrimSpace(getenv("SSO_EXPECTED_IDP_HOST"))),
		Timeout:         timeout,
	}, nil
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
