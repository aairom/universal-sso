// Package samltest provides an in-process SAML 2.0 identity provider for
// tests and the end-to-end harness.
//
// It publishes metadata, answers an SP-initiated AuthnRequest with an
// auto-submitting HTML form (the HTTP-POST binding), and can build Responses
// that are deliberately broken (wrong audience, expired, signature wrapping,
// SHA-1, XXE ...) so the adapter's refusals can be tested. It signs with a
// throw-away RSA key generated at start-up and asks nobody to sign in, so it is
// not a substitute for a real IdP.
package samltest

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"html"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	nsProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsMetadata  = "urn:oasis:names:tc:SAML:2.0:metadata"
	nsDSig      = "http://www.w3.org/2000/09/xmldsig#"

	// StatusSuccess is the SAML success status code.
	StatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"
)

// SignMode selects what the IdP signs.
type SignMode int

const (
	SignResponse  SignMode = iota // the Response (default)
	SignAssertion                 // only the Assertion
	SignBoth
	SignNone
)

// Config sets the identities the fake uses. All fields are required.
type Config struct {
	EntityID   string // the IdP entity ID (metadata entityID, Issuer)
	SSOURL     string // the HTTP-Redirect SingleSignOnService location
	SPEntityID string // expected Audience
	ACSURL     string // where Responses are delivered (Destination, Recipient)
}

// Opts shapes one Response. Zero values mean "a valid Response".
type Opts struct {
	InResponseTo string
	NameID       string // default "alice@example.com"
	NameIDFormat string // default emailAddress
	Attributes   map[string][]string
	Status       string // default StatusSuccess
	Sign         SignMode

	// Overrides, each used instead of the correct value when non-empty / non-zero.
	Destination  string
	Recipient    string
	Audience     string
	Issuer       string
	AssertionID  string
	NotBefore    time.Time // Conditions NotBefore (default: omitted)
	NotOnOrAfter time.Time // Conditions and confirmation (default: now + 5 minutes)

	SHA1     bool // sign with RSA-SHA1 and a SHA-1 digest
	WrongKey bool // sign with a key that is not in the metadata
	XXE      bool // prepend a DOCTYPE that declares an entity

	// Mutate edits the Response after signing (to break signatures or wrap
	// content). Raw edits the serialized XML last.
	Mutate func(resp *etree.Element)
	Raw    func([]byte) []byte
}

// Fake is the identity provider. Set Now before use to control the clock.
type Fake struct {
	cfg   Config
	Now   func() time.Time
	key   *rsa.PrivateKey
	cert  *x509.Certificate
	other *rsa.PrivateKey // a second key, never published
	oCert *x509.Certificate
}

func newKey() (*rsa.PrivateKey, *x509.Certificate) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "samltest idp"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		panic(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return k, c
}

// New creates a fake IdP with a fresh throw-away key.
func New(cfg Config) *Fake {
	f := &Fake{cfg: cfg, Now: time.Now}
	f.key, f.cert = newKey()
	f.other, f.oCert = newKey()
	return f
}

// Metadata returns the IdP metadata XML.
func (f *Fake) Metadata() []byte {
	doc := etree.NewDocument()
	ed := doc.CreateElement("md:EntityDescriptor")
	ed.CreateAttr("xmlns:md", nsMetadata)
	ed.CreateAttr("xmlns:ds", nsDSig)
	ed.CreateAttr("entityID", f.cfg.EntityID)
	idp := ed.CreateElement("md:IDPSSODescriptor")
	idp.CreateAttr("WantAuthnRequestsSigned", "false")
	idp.CreateAttr("protocolSupportEnumeration", nsProtocol)
	kd := idp.CreateElement("md:KeyDescriptor")
	kd.CreateAttr("use", "signing")
	kd.CreateElement("ds:KeyInfo").CreateElement("ds:X509Data").CreateElement("ds:X509Certificate").
		SetText(base64.StdEncoding.EncodeToString(f.cert.Raw))
	sso := idp.CreateElement("md:SingleSignOnService")
	sso.CreateAttr("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
	sso.CreateAttr("Location", f.cfg.SSOURL)
	out, _ := doc.WriteToBytes()
	return out
}

func id() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "_" + hex.EncodeToString(b)
}

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

func or(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

func (f *Fake) signer(o Opts) *dsig.SigningContext {
	k, c := f.key, f.cert
	if o.WrongKey {
		k, c = f.other, f.oCert
	}
	sc, err := dsig.NewSigningContext(k, [][]byte{c.Raw})
	if err != nil {
		panic(err)
	}
	sc.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if o.SHA1 {
		if err := sc.SetSignatureMethod(dsig.RSASHA1SignatureMethod); err != nil {
			panic(err)
		}
	}
	return sc
}

func (f *Fake) sign(sc *dsig.SigningContext, el *etree.Element) *etree.Element {
	out, err := sc.SignEnveloped(el)
	if err != nil {
		panic(err)
	}
	return out
}

func (f *Fake) assertion(o Opts, now time.Time) *etree.Element {
	a := etree.NewElement("saml:Assertion")
	a.CreateAttr("xmlns:saml", nsAssertion)
	a.CreateAttr("ID", or(o.AssertionID, id()))
	a.CreateAttr("Version", "2.0")
	a.CreateAttr("IssueInstant", stamp(now))
	a.CreateElement("saml:Issuer").SetText(or(o.Issuer, f.cfg.EntityID))

	until := o.NotOnOrAfter
	if until.IsZero() {
		until = now.Add(5 * time.Minute)
	}
	subj := a.CreateElement("saml:Subject")
	nid := subj.CreateElement("saml:NameID")
	nid.CreateAttr("Format", or(o.NameIDFormat, "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"))
	nid.SetText(or(o.NameID, "alice@example.com"))
	sc := subj.CreateElement("saml:SubjectConfirmation")
	sc.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	d := sc.CreateElement("saml:SubjectConfirmationData")
	d.CreateAttr("Recipient", or(o.Recipient, f.cfg.ACSURL))
	d.CreateAttr("InResponseTo", o.InResponseTo)
	d.CreateAttr("NotOnOrAfter", stamp(until))

	cond := a.CreateElement("saml:Conditions")
	if !o.NotBefore.IsZero() {
		cond.CreateAttr("NotBefore", stamp(o.NotBefore))
	}
	cond.CreateAttr("NotOnOrAfter", stamp(until))
	cond.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").
		SetText(or(o.Audience, f.cfg.SPEntityID))

	as := a.CreateElement("saml:AuthnStatement")
	as.CreateAttr("AuthnInstant", stamp(now))
	as.CreateElement("saml:AuthnContext").CreateElement("saml:AuthnContextClassRef").
		SetText("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")

	attrs := o.Attributes
	if attrs == nil {
		attrs = map[string][]string{
			"email": {"alice@example.com"}, "givenName": {"Alice"}, "surname": {"Example"},
			"groups": {"staff", "admins"},
		}
	}
	if len(attrs) > 0 {
		st := a.CreateElement("saml:AttributeStatement")
		for _, name := range sortedKeys(attrs) {
			at := st.CreateElement("saml:Attribute")
			at.CreateAttr("Name", name)
			for _, v := range attrs[name] {
				at.CreateElement("saml:AttributeValue").SetText(v)
			}
		}
	}
	return a
}

func sortedKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ { // tiny insertion sort keeps output stable
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

// ResponseXML builds the Response XML described by o.
func (f *Fake) ResponseXML(o Opts) []byte {
	now := f.Now()
	sc := f.signer(o)

	resp := etree.NewElement("samlp:Response")
	resp.CreateAttr("xmlns:samlp", nsProtocol)
	resp.CreateAttr("xmlns:saml", nsAssertion)
	resp.CreateAttr("ID", id())
	resp.CreateAttr("Version", "2.0")
	resp.CreateAttr("IssueInstant", stamp(now))
	resp.CreateAttr("Destination", or(o.Destination, f.cfg.ACSURL))
	resp.CreateAttr("InResponseTo", o.InResponseTo)
	resp.CreateElement("saml:Issuer").SetText(or(o.Issuer, f.cfg.EntityID))
	st := resp.CreateElement("samlp:Status")
	st.CreateElement("samlp:StatusCode").CreateAttr("Value", or(o.Status, StatusSuccess))

	if or(o.Status, StatusSuccess) == StatusSuccess {
		a := f.assertion(o, now)
		if o.Sign == SignAssertion || o.Sign == SignBoth {
			a = f.sign(sc, a)
		}
		resp.AddChild(a)
	}
	if o.Sign == SignResponse || o.Sign == SignBoth {
		resp = f.sign(sc, resp)
	}
	if o.Mutate != nil {
		o.Mutate(resp)
	}
	doc := etree.NewDocument()
	doc.SetRoot(resp)
	out, err := doc.WriteToBytes()
	if err != nil {
		panic(err)
	}
	if o.XXE {
		out = append([]byte(`<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>`), out...)
	}
	if o.Raw != nil {
		out = o.Raw(out)
	}
	return out
}

// Response returns the base64 SAMLResponse form value for o.
func (f *Fake) Response(o Opts) string {
	return base64.StdEncoding.EncodeToString(f.ResponseXML(o))
}

// RequestInfo is what the fake read from an AuthnRequest.
type RequestInfo struct {
	ID, Issuer, ACSURL, Destination string
}

// ParseRequest decodes an HTTP-Redirect SAMLRequest value (base64, raw DEFLATE).
func ParseRequest(samlRequest string) (*RequestInfo, error) {
	raw, err := base64.StdEncoding.DecodeString(samlRequest)
	if err != nil {
		return nil, err
	}
	xmlBytes, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(raw)), 1<<16))
	if err != nil {
		return nil, err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		return nil, err
	}
	r := doc.Root()
	if r == nil || r.Tag != "AuthnRequest" {
		return nil, io.ErrUnexpectedEOF
	}
	info := &RequestInfo{
		ID: r.SelectAttrValue("ID", ""), ACSURL: r.SelectAttrValue("AssertionConsumerServiceURL", ""),
		Destination: r.SelectAttrValue("Destination", ""),
	}
	if iss := r.SelectElement("Issuer"); iss != nil {
		info.Issuer = strings.TrimSpace(iss.Text())
	}
	return info, nil
}

// Handler serves "/metadata" and "/sso" (matched by suffix, so any prefix works).
// /sso answers an AuthnRequest with an auto-submitting form that POSTs a valid
// Response to the ACS URL, as a browser would after the user signs in.
func (f *Fake) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/metadata"):
			w.Header().Set("Content-Type", "application/samlmetadata+xml")
			_, _ = w.Write(f.Metadata())
		case strings.HasSuffix(r.URL.Path, "/sso"):
			f.sso(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

func (f *Fake) sso(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	req, err := ParseRequest(q.Get("SAMLRequest"))
	if err != nil || req.ID == "" {
		http.Error(w, "bad SAMLRequest", http.StatusBadRequest)
		return
	}
	if req.Issuer != f.cfg.SPEntityID || (req.ACSURL != "" && req.ACSURL != f.cfg.ACSURL) {
		http.Error(w, "unknown service provider or ACS URL", http.StatusBadRequest)
		return
	}
	resp := f.Response(Opts{InResponseTo: req.ID})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(`<!DOCTYPE html><html><body onload="document.forms[0].submit()">` +
		`<form method="post" action="` + html.EscapeString(f.cfg.ACSURL) + `">` +
		`<input type="hidden" name="SAMLResponse" value="` + html.EscapeString(resp) + `"/>` +
		`<input type="hidden" name="RelayState" value="` + html.EscapeString(q.Get("RelayState")) + `"/>` +
		`<noscript><button type="submit">Continue</button></noscript></form></body></html>`))
}

// VerifyRedirectSignature checks the SigAlg/Signature of a signed HTTP-Redirect
// query against cert's public key. The signed octets are the raw query
// parameters SAMLRequest, RelayState, SigAlg in that order.
func VerifyRedirectSignature(rawQuery string, cert *x509.Certificate) error {
	var parts []string
	var sig string
	for _, kv := range strings.Split(rawQuery, "&") {
		switch {
		case strings.HasPrefix(kv, "Signature="):
			s, err := url.QueryUnescape(strings.TrimPrefix(kv, "Signature="))
			if err != nil {
				return err
			}
			sig = s
		default:
			parts = append(parts, kv)
		}
	}
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return err
	}
	return cert.CheckSignature(x509.SHA256WithRSA, []byte(strings.Join(parts, "&")), raw)
}
