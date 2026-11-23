package saml

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/beevik/etree"

	"github.com/universal-sso/universal-sso/pkg/sso"
	"github.com/universal-sso/universal-sso/pkg/sso/oidc"
)

const (
	bindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	minRSABits      = 2048
)

// idpMeta is what the adapter needs from the IdP metadata.
type idpMeta struct {
	EntityID string
	SSOURL   string // HTTP-Redirect SingleSignOnService location
	Certs    []*x509.Certificate
}

// parseMetadata reads IdP metadata. The metadata itself is not signature
// checked: trust comes from where it is loaded (a local file you control, or
// an https URL), the same trust model as an OIDC discovery document.
func parseMetadata(name string, data []byte) (*idpMeta, error) {
	bad := func(format string, a ...any) error {
		return sso.ErrInvalidConfig(name+": IdP metadata: "+fmt.Sprintf(format, a...), nil)
	}
	doc, err := parseXML(data)
	if err != nil {
		return nil, bad("%v", err)
	}
	var idps []*etree.Element
	var walk func(*etree.Element)
	walk = func(el *etree.Element) {
		if is(el, nsMetadata, "EntityDescriptor") && len(children(el, nsMetadata, "IDPSSODescriptor")) > 0 {
			idps = append(idps, el)
			return
		}
		for _, c := range el.ChildElements() {
			walk(c)
		}
	}
	walk(doc.Root())
	if len(idps) != 1 {
		return nil, bad("expected exactly one EntityDescriptor with an IDPSSODescriptor, found %d", len(idps))
	}
	ed := idps[0]
	m := &idpMeta{EntityID: strings.TrimSpace(ed.SelectAttrValue("entityID", ""))}
	if m.EntityID == "" {
		return nil, bad("entityID is missing")
	}
	sd := children(ed, nsMetadata, "IDPSSODescriptor")
	if len(sd) != 1 {
		return nil, bad("expected exactly one IDPSSODescriptor")
	}
	for _, s := range children(sd[0], nsMetadata, "SingleSignOnService") {
		if s.SelectAttrValue("Binding", "") == bindingRedirect {
			m.SSOURL = strings.TrimSpace(s.SelectAttrValue("Location", ""))
			break
		}
	}
	if m.SSOURL == "" {
		return nil, bad("no SingleSignOnService with the HTTP-Redirect binding")
	}
	if err := oidc.ValidateURL(name, "IdP single sign-on URL", m.SSOURL); err != nil {
		return nil, err
	}
	for _, kd := range children(sd[0], nsMetadata, "KeyDescriptor") {
		if use := kd.SelectAttrValue("use", ""); use != "" && use != "signing" {
			continue
		}
		for _, c := range kd.FindElements(".//X509Certificate") {
			if c.NamespaceURI() != nsDSig {
				continue
			}
			cert, err := parseCert(text(c))
			if err != nil {
				return nil, bad("signing certificate: %v", err)
			}
			m.Certs = append(m.Certs, cert)
		}
	}
	if len(m.Certs) == 0 {
		return nil, bad("no signing certificate")
	}
	return m, nil
}

// parseCert decodes a base64 DER certificate and rejects weak RSA keys.
func parseCert(b64 string) (*x509.Certificate, error) {
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(b64), ""))
	if err != nil {
		return nil, errors.New("not base64")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if k, ok := cert.PublicKey.(*rsa.PublicKey); ok && k.N.BitLen() < minRSABits {
		return nil, fmt.Errorf("RSA key is %d bits, minimum is %d", k.N.BitLen(), minRSABits)
	}
	return cert, nil
}
