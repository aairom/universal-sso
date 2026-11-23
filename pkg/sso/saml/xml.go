package saml

import (
	"bytes"
	"errors"
	"strings"

	"github.com/beevik/etree"
)

// XML namespaces used by SAML 2.0 and XML Signature.
const (
	nsAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsMetadata  = "urn:oasis:names:tc:SAML:2.0:metadata"
	nsDSig      = "http://www.w3.org/2000/09/xmldsig#"
)

// maxXMLBytes caps every XML document the package parses (metadata and
// responses), both before and after base64 decoding.
const maxXMLBytes = 1 << 20

// parseXML parses untrusted XML. It refuses, before the parser sees them:
//   - documents over maxXMLBytes;
//   - any DOCTYPE or ENTITY declaration, which closes XXE and "billion
//     laughs" attacks (the parser is also given no entity table);
//   - NUL bytes, which would mean a non-ASCII-compatible encoding such as
//     UTF-16 that could hide a DOCTYPE from the byte check.
func parseXML(data []byte) (*etree.Document, error) {
	if len(data) == 0 {
		return nil, errors.New("empty XML document")
	}
	if len(data) > maxXMLBytes {
		return nil, errors.New("XML document is too large")
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return nil, errors.New("XML document contains NUL bytes (unsupported encoding)")
	}
	upper := bytes.ToUpper(data)
	if bytes.Contains(upper, []byte("<!DOCTYPE")) || bytes.Contains(upper, []byte("<!ENTITY")) {
		return nil, errors.New("DTDs and entity declarations are not allowed")
	}
	doc := etree.NewDocument()
	doc.ReadSettings.Permissive = false
	doc.ReadSettings.Entity = nil
	if err := doc.ReadFromBytes(data); err != nil {
		return nil, err
	}
	if doc.Root() == nil {
		return nil, errors.New("XML document has no root element")
	}
	return doc, nil
}

// is reports whether el is the named element in the given namespace.
func is(el *etree.Element, ns, tag string) bool {
	return el != nil && el.Tag == tag && el.NamespaceURI() == ns
}

// children returns the direct child elements of el with this namespace and tag.
func children(el *etree.Element, ns, tag string) []*etree.Element {
	var out []*etree.Element
	for _, c := range el.ChildElements() {
		if is(c, ns, tag) {
			out = append(out, c)
		}
	}
	return out
}

// child returns the only direct child with this namespace and tag. It returns
// (nil, nil) when there is none and an error when there is more than one.
func child(el *etree.Element, ns, tag string) (*etree.Element, error) {
	cs := children(el, ns, tag)
	switch len(cs) {
	case 0:
		return nil, nil
	case 1:
		return cs[0], nil
	}
	return nil, errors.New("more than one <" + tag + "> element")
}

// text returns the trimmed text of el, or "" when el is nil.
func text(el *etree.Element) string {
	if el == nil {
		return ""
	}
	return strings.TrimSpace(el.Text())
}
