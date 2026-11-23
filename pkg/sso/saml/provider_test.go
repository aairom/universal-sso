package saml

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"

	"github.com/universal-sso/universal-sso/pkg/sso"
	"github.com/universal-sso/universal-sso/pkg/sso/saml/samltest"
)

const (
	testIdP = "https://idp.example.com/entity"
	testSP  = "http://localhost:8080/auth/saml/metadata"
	testACS = "http://localhost:8080/auth/saml/callback"
	testSSO = "https://idp.example.com/sso"
)

var t0 = time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

// rig is a provider wired to a fake IdP with a shared, controllable clock.
type rig struct {
	t   *testing.T
	p   *Provider
	idp *samltest.Fake
	now time.Time
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, now: t0}
	r.idp = samltest.New(samltest.Config{EntityID: testIdP, SSOURL: testSSO, SPEntityID: testSP, ACSURL: testACS})
	r.idp.Now = func() time.Time { return r.now }
	file := filepath.Join(t.TempDir(), "idp.xml")
	if err := os.WriteFile(file, r.idp.Metadata(), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := New(Config{SPEntityID: testSP, ACSURL: testACS, IDPMetadataFile: file})
	if err != nil {
		t.Fatal(err)
	}
	p.now = func() time.Time { return r.now }
	r.p = p
	return r
}

// begin starts a login and returns the state and the AuthnRequest ID.
func (r *rig) begin(state string) string {
	r.t.Helper()
	res, err := r.p.GetAuthURL(context.Background(), sso.AuthURLRequest{State: state})
	if err != nil {
		r.t.Fatal(err)
	}
	u, _ := url.Parse(res.URL)
	info, err := samltest.ParseRequest(u.Query().Get("SAMLRequest"))
	if err != nil {
		r.t.Fatal(err)
	}
	return info.ID
}

func (r *rig) callback(state, resp string) (*sso.IdentityResult, error) {
	return r.p.HandleCallback(context.Background(), sso.CallbackRequest{State: state, SAMLResponse: resp})
}

// wantCode runs a login with the given response options and expects one error code.
func (r *rig) wantCode(name string, o samltest.Opts, code sso.SSOErrorCode) {
	r.t.Helper()
	r.t.Run(name, func(t *testing.T) {
		rr := newRig(t)
		rr.now = r.now
		id := rr.begin("st")
		if o.InResponseTo == "" {
			o.InResponseTo = id
		}
		_, err := rr.callback("st", rr.idp.Response(o))
		assertCode(t, err, code)
	})
}

func assertCode(t *testing.T, err error, code sso.SSOErrorCode) {
	t.Helper()
	se, ok := err.(*sso.SSOError)
	if !ok {
		t.Fatalf("want SSOError %s, got %v", code, err)
	}
	if se.Code != code {
		t.Fatalf("want %s, got %s: %s", code, se.Code, se.Message)
	}
}

func TestHappyPath(t *testing.T) {
	for name, mode := range map[string]samltest.SignMode{
		"signed response": samltest.SignResponse, "signed assertion": samltest.SignAssertion, "signed both": samltest.SignBoth,
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			id := r.begin("st")
			res, err := r.callback("st", r.idp.Response(samltest.Opts{InResponseTo: id, Sign: mode}))
			if err != nil {
				t.Fatal(err)
			}
			u := res.User
			if res.Protocol != sso.ProtocolSAML2 || res.ProviderID != "saml" {
				t.Fatalf("bad result %+v", res)
			}
			if u.ID != testIdP+"|alice@example.com" {
				t.Fatalf("user id must be scoped by the IdP entity id, got %q", u.ID)
			}
			if u.Email != "alice@example.com" || u.EmailVerified || u.FirstName != "Alice" || u.LastName != "Example" ||
				u.DisplayName != "Alice Example" || len(u.Groups) != 2 {
				t.Fatalf("bad mapping %+v", u)
			}
		})
	}
}

func TestEmailFromNameIDWhenNoAttribute(t *testing.T) {
	r := newRig(t)
	id := r.begin("st")
	res, err := r.callback("st", r.idp.Response(samltest.Opts{InResponseTo: id, Attributes: map[string][]string{}}))
	if err != nil {
		t.Fatal(err)
	}
	if res.User.Email != "alice@example.com" {
		t.Fatalf("email should come from an emailAddress NameID, got %q", res.User.Email)
	}
}

func TestRejections(t *testing.T) {
	r := newRig(t)
	past := t0.Add(-time.Hour)
	r.wantCode("not success", samltest.Opts{Status: "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"}, sso.ErrCodeIdPRejected)
	r.wantCode("unsigned", samltest.Opts{Sign: samltest.SignNone}, sso.ErrCodeSignatureInvalid)
	r.wantCode("wrong key", samltest.Opts{WrongKey: true}, sso.ErrCodeSignatureInvalid)
	r.wantCode("sha1", samltest.Opts{SHA1: true}, sso.ErrCodeSignatureInvalid)
	r.wantCode("wrong audience", samltest.Opts{Audience: "https://other.example.com"}, sso.ErrCodeInvalidToken)
	r.wantCode("wrong destination", samltest.Opts{Destination: "https://evil.example.com/cb"}, sso.ErrCodeInvalidToken)
	r.wantCode("wrong recipient", samltest.Opts{Recipient: "https://evil.example.com/cb"}, sso.ErrCodeInvalidToken)
	r.wantCode("wrong issuer", samltest.Opts{Issuer: "https://evil.example.com/idp"}, sso.ErrCodeInvalidToken)
	r.wantCode("expired", samltest.Opts{NotOnOrAfter: past}, sso.ErrCodeTokenExpired)
	r.wantCode("not yet valid", samltest.Opts{NotBefore: t0.Add(time.Hour)}, sso.ErrCodeInvalidToken)
	r.wantCode("wrong InResponseTo", samltest.Opts{InResponseTo: "_other"}, sso.ErrCodeInvalidToken)
	r.wantCode("xxe doctype", samltest.Opts{XXE: true}, sso.ErrCodeInvalidToken)
	r.wantCode("tampered after signing", samltest.Opts{Mutate: func(resp *etree.Element) {
		resp.FindElement("//NameID").SetText("mallory@example.com")
	}}, sso.ErrCodeSignatureInvalid)
}

func TestClockSkew(t *testing.T) {
	r := newRig(t)
	// Expired 30s ago: inside the 60s tolerance, so accepted.
	id := r.begin("a")
	if _, err := r.callback("a", r.idp.Response(samltest.Opts{InResponseTo: id, NotOnOrAfter: t0.Add(-30 * time.Second)})); err != nil {
		t.Fatalf("within skew must pass: %v", err)
	}
	// Not valid for another 30s: inside tolerance too.
	id = r.begin("b")
	if _, err := r.callback("b", r.idp.Response(samltest.Opts{InResponseTo: id, NotBefore: t0.Add(30 * time.Second)})); err != nil {
		t.Fatalf("within skew must pass: %v", err)
	}
	// Expired 2 minutes ago: refused.
	id = r.begin("c")
	_, err := r.callback("c", r.idp.Response(samltest.Opts{InResponseTo: id, NotOnOrAfter: t0.Add(-2 * time.Minute)}))
	assertCode(t, err, sso.ErrCodeTokenExpired)
}

// An attacker keeps a valid signed assertion but adds an unsigned one that
// names someone else. Only the verified element may be read.
func TestSignatureWrappingIsIgnored(t *testing.T) {
	r := newRig(t)
	id := r.begin("st")
	xml := r.idp.ResponseXML(samltest.Opts{InResponseTo: id, Sign: samltest.SignAssertion, Mutate: func(resp *etree.Element) {
		evil := resp.FindElement("//Assertion").Copy()
		for _, s := range evil.FindElements(".//Signature") {
			s.Parent().RemoveChild(s)
		}
		evil.FindElement(".//NameID").SetText("mallory@example.com")
		evil.CreateAttr("ID", "_evil")
		resp.InsertChildAt(1, evil) // before the real one
	}})
	_, err := r.callback("st", base64.StdEncoding.EncodeToString(xml))
	if err == nil {
		t.Fatal("a Response with two assertions must be refused")
	}
	assertCode(t, err, sso.ErrCodeInvalidToken)
}

// A valid signature that references some other element must not count.
func TestSignatureMustReferenceTheSignedElement(t *testing.T) {
	r := newRig(t)
	id := r.begin("st")
	xml := r.idp.ResponseXML(samltest.Opts{InResponseTo: id, Sign: samltest.SignAssertion, Mutate: func(resp *etree.Element) {
		resp.FindElement("//Assertion").CreateAttr("ID", "_changed")
	}})
	_, err := r.callback("st", base64.StdEncoding.EncodeToString(xml))
	assertCode(t, err, sso.ErrCodeSignatureInvalid)
}

func TestReplayAndUnsolicited(t *testing.T) {
	r := newRig(t)
	id := r.begin("one")
	resp := r.idp.Response(samltest.Opts{InResponseTo: id, AssertionID: "_fixed"})
	if _, err := r.callback("one", resp); err != nil {
		t.Fatal(err)
	}
	// Same state again: the pending request was consumed.
	_, err := r.callback("one", resp)
	assertCode(t, err, sso.ErrCodeStateMismatch)

	// New login, same assertion ID: replay cache refuses it.
	id2 := r.begin("two")
	_, err = r.callback("two", r.idp.Response(samltest.Opts{InResponseTo: id2, AssertionID: "_fixed"}))
	assertCode(t, err, sso.ErrCodeInvalidToken)
	if !strings.Contains(err.Error(), "replay") {
		t.Fatalf("want a replay error, got %v", err)
	}

	// IdP-initiated: no pending request for this state.
	_, err = r.callback("never-started", r.idp.Response(samltest.Opts{InResponseTo: ""}))
	assertCode(t, err, sso.ErrCodeStateMismatch)

	// A response answering another login's request ID is refused too.
	idA := r.begin("A")
	_ = r.begin("B")
	_, err = r.callback("B", r.idp.Response(samltest.Opts{InResponseTo: idA}))
	assertCode(t, err, sso.ErrCodeInvalidToken)
}

func TestPendingRequestExpires(t *testing.T) {
	r := newRig(t)
	id := r.begin("st")
	r.now = r.now.Add(pendingTTL + time.Minute)
	_, err := r.callback("st", r.idp.Response(samltest.Opts{InResponseTo: id, NotOnOrAfter: r.now.Add(time.Hour)}))
	assertCode(t, err, sso.ErrCodeStateMismatch)
}

func TestMalformedInput(t *testing.T) {
	r := newRig(t)
	r.begin("st")
	for name, in := range map[string]string{
		"not base64":    "%%%",
		"not xml":       base64.StdEncoding.EncodeToString([]byte("hello")),
		"wrong root":    base64.StdEncoding.EncodeToString([]byte(`<a xmlns="urn:x"/>`)),
		"huge":          strings.Repeat("A", maxXMLBytes*2),
		"nul bytes":     base64.StdEncoding.EncodeToString([]byte("<\x00a\x00/>")),
		"entity decl":   base64.StdEncoding.EncodeToString([]byte(`<!ENTITY a "b"><x/>`)),
		"doctype lcase": base64.StdEncoding.EncodeToString([]byte(`<!doctype r [<!ENTITY a "b">]><r/>`)),
	} {
		t.Run(name, func(t *testing.T) {
			rr := newRig(t)
			rr.begin("st")
			_, err := rr.callback("st", in)
			assertCode(t, err, sso.ErrCodeInvalidToken)
		})
	}
}

func TestEncryptedAssertionRefused(t *testing.T) {
	r := newRig(t)
	id := r.begin("st")
	_, err := r.callback("st", r.idp.Response(samltest.Opts{InResponseTo: id, Mutate: func(resp *etree.Element) {
		resp.CreateElement("saml:EncryptedAssertion")
	}}))
	if err == nil {
		t.Fatal("encrypted assertions must be refused")
	}
}

func TestCallbackErrorsAndMissingResponse(t *testing.T) {
	r := newRig(t)
	_, err := r.p.HandleCallback(context.Background(), sso.CallbackRequest{Error: "access_denied", ErrorDesc: "no"})
	assertCode(t, err, sso.ErrCodeIdPRejected)
	_, err = r.p.HandleCallback(context.Background(), sso.CallbackRequest{State: "x"})
	assertCode(t, err, sso.ErrCodeIdPRejected)
}

func TestAuthnRequest(t *testing.T) {
	r := newRig(t)
	res, err := r.p.GetAuthURL(context.Background(), sso.AuthURLRequest{State: "relay"})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(res.URL)
	if !strings.HasPrefix(res.URL, testSSO+"?SAMLRequest=") {
		t.Fatalf("redirect must go to the IdP SSO URL: %s", res.URL)
	}
	if u.Query().Get("RelayState") != "relay" || u.Query().Get("Signature") != "" {
		t.Fatalf("unexpected query: %v", u.Query())
	}
	info, err := samltest.ParseRequest(u.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Issuer != testSP || info.ACSURL != testACS || info.Destination != testSSO || !strings.HasPrefix(info.ID, "_") {
		t.Fatalf("bad AuthnRequest %+v", info)
	}
	if _, err := r.p.GetAuthURL(context.Background(), sso.AuthURLRequest{}); err == nil {
		t.Fatal("empty state must be refused")
	}
	// Each login gets its own request ID.
	if id2 := r.begin("again"); id2 == info.ID {
		t.Fatal("request ids must be unique")
	}
}

func writeSPKey(t *testing.T, bits int) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	path := filepath.Join(t.TempDir(), "sp.key")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSignedAuthnRequest(t *testing.T) {
	r := newRig(t)
	keyPath := writeSPKey(t, 2048)
	p, err := New(Config{SPEntityID: testSP, ACSURL: testACS, IDPMetadataFile: r.p.cfg.IDPMetadataFile,
		SPCertFile: "unused-but-paired.crt", SPKeyFile: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	res, err := p.GetAuthURL(context.Background(), sso.AuthURLRequest{State: "relay"})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(res.URL)
	if u.Query().Get("SigAlg") != rsaSHA256URI || u.Query().Get("Signature") == "" {
		t.Fatalf("request must carry SigAlg and Signature: %v", u.Query())
	}
	// The signature covers the raw, ordered query without Signature.
	raw := strings.TrimPrefix(res.URL, testSSO+"?")
	signed := raw[:strings.LastIndex(raw, "&Signature=")]
	if !strings.HasSuffix(signed, "&SigAlg="+url.QueryEscape(rsaSHA256URI)) || !strings.Contains(signed, "&RelayState=relay&") {
		t.Fatalf("signed octets are not in binding order: %s", signed)
	}
	if err := verifyWith(p.key, raw); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	file := filepath.Join(t.TempDir(), "m.xml")
	r := newRig(t)
	_ = os.WriteFile(file, r.idp.Metadata(), 0o600)
	ok := Config{SPEntityID: testSP, ACSURL: testACS, IDPMetadataFile: file}
	bad := map[string]func(*Config){
		"no entity id":     func(c *Config) { c.SPEntityID = "" },
		"no acs":           func(c *Config) { c.ACSURL = "" },
		"http acs":         func(c *Config) { c.ACSURL = "http://evil.example.com/cb" },
		"both sources":     func(c *Config) { c.IDPMetadataURL = "https://idp.example.com/m" },
		"no source":        func(c *Config) { c.IDPMetadataFile = "" },
		"http metadata":    func(c *Config) { c.IDPMetadataFile, c.IDPMetadataURL = "", "http://idp.example.com/m" },
		"cert without key": func(c *Config) { c.SPCertFile = "x" },
		"missing file":     func(c *Config) { c.IDPMetadataFile = filepath.Join(t.TempDir(), "nope.xml") },
		"weak sp key":      func(c *Config) { c.SPCertFile, c.SPKeyFile = "x", writeSPKey(t, 1024) },
		"missing sp key":   func(c *Config) { c.SPCertFile, c.SPKeyFile = "x", filepath.Join(t.TempDir(), "nope") },
	}
	for name, mut := range bad {
		t.Run(name, func(t *testing.T) {
			c := ok
			mut(&c)
			_, err := New(c)
			assertCode(t, err, sso.ErrCodeInvalidConfig)
		})
	}
	if p, err := New(ok); err != nil || p.ID() != "saml" || p.Name() != "SAML 2.0" || p.Protocol() != sso.ProtocolSAML2 {
		t.Fatalf("defaults wrong: %v", err)
	}
}

func TestMetadataRejections(t *testing.T) {
	r := newRig(t)
	good := string(r.idp.Metadata())
	cases := map[string]string{
		"doctype":     `<!DOCTYPE x [<!ENTITY a "b">]>` + good,
		"no idp":      `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x"/>`,
		"no entityid": strings.Replace(good, `entityID="`+testIdP+`"`, "", 1),
		"no redirect": strings.Replace(good, "bindings:HTTP-Redirect", "bindings:HTTP-POST", 1),
		"no cert":     regexpDropCert(good),
		"http sso":    strings.Replace(good, testSSO, "http://idp.example.com/sso", 1),
		"bad cert":    regexpBadCert(good),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseMetadata("t", []byte(in)); err == nil {
				t.Fatal("metadata must be refused")
			}
		})
	}
}

func TestWeakIdPKeyRefused(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 1024)
	tmpl := &x509.Certificate{SerialNumber: bigOne(), NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if _, err := parseCert(base64.StdEncoding.EncodeToString(der)); err == nil {
		t.Fatal("a 1024 bit IdP key must be refused")
	}
}

func TestMetadataFromURL(t *testing.T) {
	idp := samltest.New(samltest.Config{EntityID: testIdP, SSOURL: testSSO, SPEntityID: testSP, ACSURL: testACS})
	hits, fail := 0, false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		if fail {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(idp.Metadata())
	}))
	defer srv.Close()
	p, err := New(Config{SPEntityID: testSP, ACSURL: testACS, IDPMetadataURL: srv.URL, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if hits != 0 {
		t.Fatal("New must not touch the network")
	}
	now := t0
	p.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if _, err := p.GetAuthURL(context.Background(), sso.AuthURLRequest{State: "s"}); err != nil {
			t.Fatal(err)
		}
	}
	if hits != 1 {
		t.Fatalf("metadata must be cached, fetched %d times", hits)
	}
	// After the TTL a failing refresh keeps the cached copy.
	now = now.Add(metaTTL + time.Minute)
	fail = true
	if _, err := p.GetAuthURL(context.Background(), sso.AuthURLRequest{State: "s2"}); err != nil {
		t.Fatalf("stale metadata must be kept when the refresh fails: %v", err)
	}
	// With nothing cached, a failure is NETWORK_FAILURE.
	p2, _ := New(Config{SPEntityID: testSP, ACSURL: testACS, IDPMetadataURL: srv.URL, HTTPClient: srv.Client()})
	_, err = p2.GetAuthURL(context.Background(), sso.AuthURLRequest{State: "s3"})
	assertCode(t, err, sso.ErrCodeNetworkFailure)
}

func TestUnsupportedMethods(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	_, e1 := r.p.ValidateToken(ctx, "t")
	_, e2 := r.p.RefreshToken(ctx, "t")
	e3 := r.p.RevokeToken(ctx, "t")
	_, e4 := r.p.GetLogoutURL(ctx, sso.LogoutRequest{})
	_, e5 := r.p.FetchUserInfo(ctx, "t")
	for _, e := range []error{e1, e2, e3, e4, e5} {
		assertCode(t, e, sso.ErrCodeUnsupportedMethod)
	}
}

func TestDriverRegistered(t *testing.T) {
	r := newRig(t)
	p, err := sso.NewProvider(DriverName, map[string]string{
		"sp_entity_id": testSP, "acs_url": testACS, "idp_metadata_file": r.p.cfg.IDPMetadataFile,
	})
	if err != nil || p.Protocol() != sso.ProtocolSAML2 {
		t.Fatalf("driver: %v", err)
	}
	if _, err := sso.NewProvider(DriverName, map[string]string{}); err == nil {
		t.Fatal("an empty config must fail")
	}
}

func TestPendingLimit(t *testing.T) {
	r := newRig(t)
	for i := 0; i < maxPending; i++ {
		r.p.pending[string(rune(i))+"k"+strings.Repeat("x", i%7)+time.Duration(i).String()] = pendingReq{exp: r.now.Add(time.Hour)}
	}
	_, err := r.p.GetAuthURL(context.Background(), sso.AuthURLRequest{State: "overflow"})
	assertCode(t, err, sso.ErrCodeInternal)
}

// The next tests isolate checks that a second, overlapping check would
// otherwise hide, so removing either one makes a test fail.

func TestConditionsExpiryIsCheckedOnItsOwn(t *testing.T) {
	r := newRig(t)
	id := r.begin("st")
	_, err := r.callback("st", r.idp.Response(samltest.Opts{InResponseTo: id, CondNotOnOrAfter: t0.Add(-5 * time.Minute)}))
	assertCode(t, err, sso.ErrCodeTokenExpired)
}

func TestConfirmationExpiryIsCheckedOnItsOwn(t *testing.T) {
	r := newRig(t)
	id := r.begin("st")
	_, err := r.callback("st", r.idp.Response(samltest.Opts{
		InResponseTo: id, NotOnOrAfter: t0.Add(-5 * time.Minute), CondNotOnOrAfter: t0.Add(time.Hour)}))
	assertCode(t, err, sso.ErrCodeTokenExpired)
}

func TestResponseInResponseToIsCheckedOnItsOwn(t *testing.T) {
	r := newRig(t)
	id := r.begin("st")
	// Only the Assertion is signed, so the Response attribute can be changed
	// while the assertion keeps the correct InResponseTo.
	_, err := r.callback("st", r.idp.Response(samltest.Opts{InResponseTo: id, Sign: samltest.SignAssertion,
		Mutate: func(resp *etree.Element) { resp.CreateAttr("InResponseTo", "_someone_elses") }}))
	assertCode(t, err, sso.ErrCodeInvalidToken)
}

func TestSignatureMethodAllowListOnItsOwn(t *testing.T) {
	const sigXML = `<s xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Signature><ds:SignedInfo>` +
		`<ds:SignatureMethod Algorithm="%s"/><ds:Reference><ds:DigestMethod Algorithm="%s"/></ds:Reference>` +
		`</ds:SignedInfo></ds:Signature></s>`
	const (
		sha1Sig   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
		sha256Sig = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
		sha1Dig   = "http://www.w3.org/2000/09/xmldsig#sha1"
		sha256Dig = "http://www.w3.org/2001/04/xmlenc#sha256"
	)
	check := func(sig, dig string) error {
		d := etree.NewDocument()
		if err := d.ReadFromString(strings.Replace(strings.Replace(sigXML, "%s", sig, 1), "%s", dig, 1)); err != nil {
			t.Fatal(err)
		}
		return checkAlgorithms(d.Root())
	}
	if err := check(sha256Sig, sha256Dig); err != nil {
		t.Fatalf("sha256 must pass: %v", err)
	}
	if check(sha1Sig, sha256Dig) == nil {
		t.Fatal("a SHA-1 signature method must be refused even with a SHA-256 digest")
	}
	if check(sha256Sig, sha1Dig) == nil {
		t.Fatal("a SHA-1 digest must be refused even with a SHA-256 signature")
	}
}

func TestDuplicateReferenceIsRefusedByOurOwnCheck(t *testing.T) {
	r := newRig(t)
	id := r.begin("st")
	_, err := r.callback("st", r.idp.Response(samltest.Opts{InResponseTo: id, Mutate: func(resp *etree.Element) {
		si := resp.FindElement("./Signature/SignedInfo")
		si.AddChild(si.FindElement("./Reference").Copy())
	}}))
	assertCode(t, err, sso.ErrCodeSignatureInvalid)
	if !strings.Contains(err.Error(), "exactly one reference") {
		t.Fatalf("our reference check must be the one that fires, got: %v", err)
	}
}

func TestResponseDestinationIsCheckedOnItsOwn(t *testing.T) {
	r := newRig(t)
	id := r.begin("st")
	// Only the Assertion is signed, so a wrong Response Destination is not
	// covered by any signature and must be caught by the Destination check.
	_, err := r.callback("st", r.idp.Response(samltest.Opts{InResponseTo: id, Sign: samltest.SignAssertion,
		Destination: "https://evil.example.com/cb"}))
	assertCode(t, err, sso.ErrCodeInvalidToken)
	if !strings.Contains(err.Error(), "Destination") {
		t.Fatalf("the Destination check must fire, got: %v", err)
	}
}
