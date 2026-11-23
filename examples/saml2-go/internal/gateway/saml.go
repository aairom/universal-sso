package gateway

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/url"
)

// maxSAMLRequestBytes bounds the inflated AuthnRequest (defence against
// decompression bombs).
const maxSAMLRequestBytes = 64 << 10

// authnRequest holds the attributes of a SAML 2.0 <AuthnRequest> that this
// client checks. encoding/xml does not resolve external entities.
type authnRequest struct {
	XMLName                     xml.Name `xml:"AuthnRequest"`
	ID                          string   `xml:"ID,attr"`
	Destination                 string   `xml:"Destination,attr"`
	AssertionConsumerServiceURL string   `xml:"AssertionConsumerServiceURL,attr"`
}

// InspectSAMLRequest decodes a SAML HTTP-Redirect binding SAMLRequest value
// (URL-decoded, base64, raw DEFLATE) and checks the AuthnRequest:
//   - it parses and has an ID;
//   - Destination, if present, equals the redirect URL without its query;
//   - AssertionConsumerServiceURL, if present, is on the gateway's host.
func InspectSAMLRequest(samlRequest string, redirect, gateway *url.URL) error {
	raw, err := base64.StdEncoding.DecodeString(samlRequest)
	if err != nil {
		return policyErr("SAMLRequest is not base64: %v", err)
	}
	zr := flate.NewReader(bytes.NewReader(raw))
	defer zr.Close()
	xmlBytes, err := io.ReadAll(io.LimitReader(zr, maxSAMLRequestBytes+1))
	if err != nil {
		return policyErr("SAMLRequest is not valid DEFLATE data: %v", err)
	}
	if len(xmlBytes) > maxSAMLRequestBytes {
		return policyErr("SAMLRequest is larger than %d bytes", maxSAMLRequestBytes)
	}
	var req authnRequest
	if err := xml.Unmarshal(xmlBytes, &req); err != nil {
		return policyErr("SAMLRequest is not an AuthnRequest: %v", err)
	}
	if req.ID == "" {
		return policyErr("AuthnRequest has no ID")
	}
	if req.Destination != "" {
		base := *redirect
		base.RawQuery, base.Fragment = "", ""
		if req.Destination != base.String() {
			return policyErr("AuthnRequest Destination does not match the redirect")
		}
	}
	if req.AssertionConsumerServiceURL != "" {
		acs, err := url.Parse(req.AssertionConsumerServiceURL)
		if err != nil || acs.Host != gateway.Host {
			return policyErr("AssertionConsumerServiceURL is not on the gateway host")
		}
	}
	return nil
}
