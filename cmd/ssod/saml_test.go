package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/universal-sso/universal-sso/pkg/sso/saml/samltest"
)

const samlSP = "urn:test:sp"

// startSAMLGateway starts ssod's real handler with the saml provider pointed at
// the fake IdP. Both addresses are reserved first because each side's
// configuration names the other.
func startSAMLGateway(t *testing.T, extra map[string]string) (*httptest.Server, *samltest.Fake) {
	t.Helper()
	gw := httptest.NewUnstartedServer(nil)
	idp := httptest.NewUnstartedServer(nil)
	gwBase, idpBase := "http://"+gw.Listener.Addr().String(), "http://"+idp.Listener.Addr().String()
	fake := samltest.New(samltest.Config{
		EntityID: idpBase + "/entity", SSOURL: idpBase + "/sso", SPEntityID: samlSP, ACSURL: gwBase + "/auth/saml/callback",
	})
	idp.Config.Handler = fake.Handler()
	idp.Start()
	t.Cleanup(idp.Close)
	env := map[string]string{
		"SSO_SERVER_BASE_URL": gwBase, "SSO_PROVIDERS_SAML_SP_ENTITY_ID": samlSP,
		"SSO_PROVIDERS_SAML_IDP_METADATA_URL": idpBase + "/metadata",
	}
	for k, v := range extra {
		env[k] = v
	}
	m, err := build(vendorEnvMap(env))
	if err != nil {
		gw.Close()
		t.Fatal(err)
	}
	gw.Config.Handler = newHandler(m)
	gw.Start()
	t.Cleanup(gw.Close)
	return gw, fake
}

var formField = regexp.MustCompile(`name="(SAMLResponse|RelayState)" value="([^"]*)"`)

// idpForm asks the fake IdP's SSO endpoint to answer the redirect and returns
// the form fields a browser would POST to the gateway.
func idpForm(t *testing.T, ssoRedirect *url.URL) url.Values {
	t.Helper()
	resp, err := http.Get(ssoRedirect.String())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("IdP SSO endpoint = %d %s", resp.StatusCode, b)
	}
	vals := url.Values{}
	for _, m := range formField.FindAllStringSubmatch(string(b), -1) {
		vals.Set(m[1], htmlUnescape(m[2]))
	}
	return vals
}

func htmlUnescape(s string) string {
	return strings.NewReplacer("&amp;", "&", "&lt;", "<", "&gt;", ">", "&#34;", `"`, "&#39;", "'").Replace(s)
}

func postForm(t *testing.T, target string, vals url.Values) (int, map[string]any) {
	t.Helper()
	resp, err := http.PostForm(target, vals)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return resp.StatusCode, out
}

func TestSAMLDisabledByDefault(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"empty":       {},
		"placeholder": {"SSO_PROVIDERS_SAML_SP_ENTITY_ID": "saml-sp-entity-id-placeholder"},
	} {
		m, err := build(vendorEnvMap(env))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := strings.Join(m.Providers(), ","); got != "mock" {
			t.Errorf("%s: providers = %s", name, got)
		}
	}
}

func TestSAMLConfigErrors(t *testing.T) {
	cases := map[string]map[string]string{
		"entity id without metadata": {"SSO_PROVIDERS_SAML_SP_ENTITY_ID": samlSP},
		"placeholder metadata only": {"SSO_PROVIDERS_SAML_SP_ENTITY_ID": samlSP,
			"SSO_PROVIDERS_SAML_IDP_METADATA_URL": "idp-metadata-url-placeholder"},
		"http metadata": {"SSO_PROVIDERS_SAML_SP_ENTITY_ID": samlSP,
			"SSO_PROVIDERS_SAML_IDP_METADATA_URL": "http://idp.example.test/m"},
		"both sources": {"SSO_PROVIDERS_SAML_SP_ENTITY_ID": samlSP,
			"SSO_PROVIDERS_SAML_IDP_METADATA_URL":  "https://idp.example.test/m",
			"SSO_PROVIDERS_SAML_IDP_METADATA_FILE": "/nonexistent"},
		"missing file": {"SSO_PROVIDERS_SAML_SP_ENTITY_ID": samlSP,
			"SSO_PROVIDERS_SAML_IDP_METADATA_FILE": "/nonexistent/idp.xml"},
		"no base url and no acs": {"SSO_PROVIDERS_SAML_SP_ENTITY_ID": samlSP,
			"SSO_PROVIDERS_SAML_IDP_METADATA_URL": "https://idp.example.test/m", "SSO_SERVER_BASE_URL": ""},
	}
	for name, env := range cases {
		getenv := vendorEnvMap(env)
		if name == "no base url and no acs" {
			getenv = func(k string) string {
				if k == "SSO_SERVER_BASE_URL" {
					return ""
				}
				return vendorEnvMap(env)(k)
			}
		}
		if _, err := build(getenv); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// TestSAMLEndToEnd drives login -> IdP SSO endpoint -> POST callback through the
// real handler against the in-process SAML fake.
func TestSAMLEndToEnd(t *testing.T) {
	gw, _ := startSAMLGateway(t, nil)
	g := gateway{t, gw}

	au, status := g.login("saml")
	if au == nil {
		t.Fatalf("login status %d", status)
	}
	q := au.Query()
	if q.Get("SAMLRequest") == "" || q.Get("RelayState") == "" || q.Has("code_challenge") {
		t.Fatalf("redirect = %v", q)
	}
	form := idpForm(t, au)
	if form.Get("RelayState") != q.Get("RelayState") {
		t.Fatalf("RelayState not echoed: %q vs %q", form.Get("RelayState"), q.Get("RelayState"))
	}

	code, body := postForm(t, gw.URL+"/auth/saml/callback", form)
	if code != http.StatusOK {
		t.Fatalf("callback = %d %v", code, body)
	}
	if body["provider_id"] != "saml" {
		t.Errorf("provider_id = %v", body["provider_id"])
	}
	if _, leaked := body["tokens"]; leaked {
		t.Error("tokens must not be echoed")
	}
	user, _ := body["user"].(map[string]any)
	if !strings.HasSuffix(asString(user["id"]), "/entity|alice@example.com") || user["email"] != "alice@example.com" || user["email_verified"] != false {
		t.Errorf("user = %v", user)
	}

	// Replaying the same POST must fail: the state is single use.
	if code, _ := postForm(t, gw.URL+"/auth/saml/callback", form); code != http.StatusBadRequest {
		t.Errorf("replayed POST = %d, want 400", code)
	}
}

func TestSAMLRefusals(t *testing.T) {
	gw, fake := startSAMLGateway(t, nil)
	g := gateway{t, gw}
	begin := func() (*url.URL, string) {
		au, status := g.login("saml")
		if au == nil {
			t.Fatalf("login status %d", status)
		}
		req, err := samltest.ParseRequest(au.Query().Get("SAMLRequest"))
		if err != nil {
			t.Fatal(err)
		}
		return au, req.ID
	}

	// A Response the gateway did not ask for (IdP-initiated), carrying a state
	// that was never issued.
	if code, _ := postForm(t, gw.URL+"/auth/saml/callback", url.Values{
		"SAMLResponse": {fake.Response(samltest.Opts{InResponseTo: "_x"})}, "RelayState": {"forged"}}); code != http.StatusBadRequest {
		t.Errorf("unsolicited = %d, want 400", code)
	}

	// A real state, but a Response signed with a key the metadata does not list.
	au, id := begin()
	code, body := postForm(t, gw.URL+"/auth/saml/callback", url.Values{
		"SAMLResponse": {fake.Response(samltest.Opts{InResponseTo: id, WrongKey: true})},
		"RelayState":   {au.Query().Get("RelayState")}})
	if code != http.StatusUnauthorized || body["code"] != "SIGNATURE_INVALID" {
		t.Errorf("wrong key = %d %v", code, body)
	}

	// An IdP error posted back is reported, not treated as a login.
	au, _ = begin()
	code, body = postForm(t, gw.URL+"/auth/saml/callback", url.Values{
		"RelayState": {au.Query().Get("RelayState")}, "error": {"access_denied"}})
	if code != http.StatusUnauthorized || body["code"] != "IDP_REJECTED" {
		t.Errorf("idp error = %d %v", code, body)
	}
}

func asString(v any) string { s, _ := v.(string); return s }
