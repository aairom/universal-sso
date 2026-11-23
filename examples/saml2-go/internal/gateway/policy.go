package gateway

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ErrPolicy marks a login redirect that this client refuses to follow.
var ErrPolicy = errors.New("unsafe authorization redirect")

func policyErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrPolicy, fmt.Sprintf(format, a...))
}

// CheckAuthorizeURL verifies that the redirect returned by the gateway is safe
// and returns the state value it carries (the "state" query parameter, or
// "RelayState" for SAML).
//
// Rules:
//   - the scheme is http or https, and https is required unless the redirect
//     stays on the gateway's own host (the mock provider);
//   - when expectedHost is set, the host equals it or is a subdomain of it;
//   - a non-empty state is present;
//   - OAuth 2.0 / OIDC redirects use PKCE with code_challenge_method=S256;
//   - SAML redirects (SAMLRequest present) carry a well-formed AuthnRequest
//     aimed at this redirect and answered on the gateway's host.
func CheckAuthorizeURL(u, gateway *url.URL, expectedHost string) (string, error) {
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", policyErr("scheme %q is not http or https", u.Scheme)
	}
	if u.Host != gateway.Host && u.Scheme != "https" {
		return "", policyErr("external identity provider must use https")
	}
	if expectedHost != "" {
		h := strings.ToLower(u.Hostname())
		if h != expectedHost && !strings.HasSuffix(h, "."+expectedHost) {
			return "", policyErr("host %q is not %q or a subdomain", h, expectedHost)
		}
	}
	q := u.Query()
	if saml := q.Get("SAMLRequest"); saml != "" {
		state := q.Get("RelayState")
		if state == "" {
			return "", policyErr("SAML redirect has no RelayState")
		}
		if err := InspectSAMLRequest(saml, u, gateway); err != nil {
			return "", err
		}
		return state, nil
	}
	state := q.Get("state")
	if state == "" {
		return "", policyErr("redirect has no state parameter")
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		return "", policyErr("redirect does not use PKCE with S256")
	}
	return state, nil
}
