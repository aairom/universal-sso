//go:build e2e

// This file exists only in binaries built with -tags e2e (tests/e2e.sh).
// It mounts in-process fake OpenID Connect servers on the gateway's own
// listener so the example clients can complete a whole sign-in without a
// browser. They approve every request. Never ship a binary built with this tag.

package main

import (
	"log"
	"net/http"
	"strings"

	"github.com/universal-sso/universal-sso/pkg/sso/oauth2/oauth2test"
	"github.com/universal-sso/universal-sso/pkg/sso/oidc/oidctest"
)

const e2eTenant = "11111111-1111-1111-1111-111111111111"

func wrap(h http.Handler, getenv func(string) string) (http.Handler, error) {
	origin := strings.TrimRight(getenv("SSO_SERVER_BASE_URL"), "/")
	log.Printf("ssod: WARNING e2e build, fake identity providers are mounted under %s/idp/", origin)

	mint := func(iss string, extra map[string]any) func(client, nonce string) map[string]any {
		return func(client, nonce string) map[string]any {
			c := oidctest.GoodClaims(iss, client, nonce)
			for k, v := range extra {
				c[k] = v
			}
			return c
		}
	}
	oktaIss := origin + "/idp/okta/oauth2/default"
	auth0Iss := origin + "/idp/auth0/"
	azureIss := origin + "/idp/azure/" + e2eTenant + "/v2.0"

	okta := oidctest.NewInteractive(origin, mint(oktaIss, map[string]any{"preferred_username": "ab@example.com", "groups": []string{"Everyone"}}))
	auth0 := oidctest.NewInteractive(origin, mint(auth0Iss, map[string]any{"nickname": "ab", "roles": []string{"admin"}}))
	auth0.DiscoveryIssuer(auth0Iss) // Auth0 signs iss with a trailing slash
	azure := oidctest.NewInteractive(origin, mint(azureIss, map[string]any{"tid": e2eTenant, "preferred_username": "ab@example.com", "roles": []string{"Reader"}}))

	mux := http.NewServeMux()
	mux.Handle("/idp/okta/", okta.Handler())
	mux.Handle("/idp/auth0/", auth0.Handler())
	mux.Handle("/idp/azure/", azure.Handler())
	// Plain OAuth 2.0 (no ID token). Credentials match tests/e2e.sh.
	mux.Handle("/idp/oauth2/", oauth2test.New("e2e-oauth2", "e2e-value").Handler())
	mux.Handle("/", h)
	return mux, nil
}
