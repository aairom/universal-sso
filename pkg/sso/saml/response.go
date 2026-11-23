package saml

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"

	"github.com/universal-sso/universal-sso/pkg/sso"
)

const statusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"

// Signature and digest algorithms accepted. SHA-1 variants are deliberately
// absent: goxmldsig would verify them, so the allow-list is the only guard.
var (
	allowedSigMethods = map[string]bool{
		dsig.RSASHA256SignatureMethod: true, dsig.RSASHA384SignatureMethod: true, dsig.RSASHA512SignatureMethod: true,
		dsig.ECDSASHA256SignatureMethod: true, dsig.ECDSASHA384SignatureMethod: true, dsig.ECDSASHA512SignatureMethod: true,
	}
	allowedDigests = map[string]bool{
		"http://www.w3.org/2001/04/xmlenc#sha256":       true,
		"http://www.w3.org/2001/04/xmldsig-more#sha384": true,
		"http://www.w3.org/2001/04/xmlenc#sha512":       true,
	}
)

func (p *Provider) fail(code sso.SSOErrorCode, status int, format string, a ...any) *sso.SSOError {
	return sso.NewError(code, p.errf(format, a...), status, nil)
}

func (p *Provider) invalid(format string, a ...any) *sso.SSOError {
	return p.fail(sso.ErrCodeInvalidToken, http.StatusUnauthorized, format, a...)
}

// HandleCallback validates the SAMLResponse and maps the assertion to a user.
func (p *Provider) HandleCallback(ctx context.Context, req sso.CallbackRequest) (*sso.IdentityResult, error) {
	if req.Error != "" {
		return nil, sso.NewError(sso.ErrCodeIdPRejected, req.Error+": "+req.ErrorDesc, http.StatusUnauthorized, nil)
	}
	if req.SAMLResponse == "" {
		return nil, p.fail(sso.ErrCodeIdPRejected, http.StatusBadRequest, "missing SAMLResponse")
	}
	// RelayState is the signed state; the manager has verified it and made it
	// single use. A Response the gateway did not ask for has no request ID.
	reqID, ok := p.take(req.State)
	if !ok {
		return nil, sso.ErrStateInvalid(p.errf("no pending AuthnRequest for this response (unsolicited or expired)"))
	}
	meta, err := p.loadMeta(ctx)
	if err != nil {
		return nil, err
	}
	user, err := p.validateResponse(req.SAMLResponse, meta, reqID)
	if err != nil {
		return nil, err
	}
	return &sso.IdentityResult{ProviderID: p.cfg.ID, Protocol: sso.ProtocolSAML2, User: user}, nil
}

// validateResponse runs every check on one base64 SAMLResponse.
func (p *Provider) validateResponse(b64 string, meta *idpMeta, reqID string) (*sso.UserInfo, error) {
	if len(b64) > maxXMLBytes*4/3+8 {
		return nil, p.invalid("SAMLResponse is too large")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(b64), ""))
	if err != nil {
		return nil, p.invalid("SAMLResponse is not base64")
	}
	doc, err := parseXML(raw)
	if err != nil {
		return nil, p.invalid("SAMLResponse is not acceptable XML: %v", err)
	}
	root := doc.Root()
	if !is(root, nsProtocol, "Response") {
		return nil, p.invalid("root element is not a SAML Response")
	}

	// 1. The IdP's verdict. Nothing is trusted here, a refusal just ends the login.
	if st := statusOf(root); st != statusSuccess {
		return nil, p.fail(sso.ErrCodeIdPRejected, http.StatusUnauthorized, "IdP answered with status %q", st)
	}
	if len(children(root, nsAssertion, "EncryptedAssertion")) > 0 {
		return nil, p.invalid("encrypted assertions are not supported")
	}

	// 2. Algorithms: every signature in the document must use allowed ones.
	if err := checkAlgorithms(root); err != nil {
		return nil, p.fail(sso.ErrCodeSignatureInvalid, http.StatusUnauthorized, "%v", err)
	}

	// 3. Signature. From here on only the verified copy is read, so content
	// an attacker wrapped around or beside the signed element is ignored.
	respEl, assertion, err := p.verified(root, meta.Certs)
	if err != nil {
		return nil, err
	}

	// 4. Response-level claims (read from the verified copy when it is signed).
	if v := respEl.SelectAttrValue("Version", ""); v != "2.0" {
		return nil, p.invalid("unsupported SAML version %q", v)
	}
	if respEl.SelectAttrValue("InResponseTo", "") != reqID {
		return nil, p.invalid("InResponseTo does not match the pending AuthnRequest")
	}
	if d := respEl.SelectAttrValue("Destination", ""); d != p.cfg.ACSURL {
		if d != "" || respEl != root { // a signed Response must carry its Destination
			return nil, p.invalid("Destination does not match the ACS URL")
		}
	}
	if iss, _ := child(respEl, nsAssertion, "Issuer"); iss != nil && text(iss) != meta.EntityID {
		return nil, p.invalid("Response Issuer is not the configured IdP")
	}
	return p.checkAssertion(assertion, meta, reqID)
}

// statusOf returns the top-level StatusCode value, or "" if absent.
func statusOf(resp *etree.Element) string {
	st, err := child(resp, nsProtocol, "Status")
	if err != nil || st == nil {
		return ""
	}
	sc, err := child(st, nsProtocol, "StatusCode")
	if err != nil || sc == nil {
		return ""
	}
	return sc.SelectAttrValue("Value", "")
}

// checkAlgorithms inspects every ds:Signature in the document.
func checkAlgorithms(root *etree.Element) error {
	var sigs []*etree.Element
	collect(root, nsDSig, "Signature", &sigs)
	for _, s := range sigs {
		var sm, dm []*etree.Element
		collect(s, nsDSig, "SignatureMethod", &sm)
		collect(s, nsDSig, "DigestMethod", &dm)
		if len(sm) != 1 || !allowedSigMethods[sm[0].SelectAttrValue("Algorithm", "")] {
			return errors.New("signature method is not allowed (SHA-1 and unknown methods are refused)")
		}
		if len(dm) == 0 {
			return errors.New("signature has no digest method")
		}
		for _, d := range dm {
			if !allowedDigests[d.SelectAttrValue("Algorithm", "")] {
				return errors.New("digest method is not allowed (SHA-1 and unknown methods are refused)")
			}
		}
	}
	return nil
}

func collect(el *etree.Element, ns, tag string, out *[]*etree.Element) {
	for _, c := range el.ChildElements() {
		if is(c, ns, tag) {
			*out = append(*out, c)
		}
		collect(c, ns, tag, out)
	}
}

// verified checks the signature and returns the verified Response (or the
// unsigned root when only the Assertion is signed) and the verified Assertion.
func (p *Provider) verified(root *etree.Element, certs []*x509.Certificate) (resp, assertion *etree.Element, err error) {
	if hasSig(root) {
		vr, err := p.verifyElement(root, certs)
		if err != nil {
			return nil, nil, err
		}
		as := children(vr, nsAssertion, "Assertion")
		if len(as) != 1 {
			return nil, nil, p.invalid("expected exactly one Assertion, found %d", len(as))
		}
		return vr, as[0], nil
	}
	as := children(root, nsAssertion, "Assertion")
	if len(as) != 1 {
		return nil, nil, p.invalid("expected exactly one Assertion, found %d", len(as))
	}
	if !hasSig(as[0]) {
		return nil, nil, p.fail(sso.ErrCodeSignatureInvalid, http.StatusUnauthorized, "neither the Response nor the Assertion is signed")
	}
	va, err := p.verifyElement(as[0], certs)
	if err != nil {
		return nil, nil, err
	}
	return root, va, nil
}

// hasSig reports whether el has a direct ds:Signature child.
func hasSig(el *etree.Element) bool { return len(children(el, nsDSig, "Signature")) > 0 }

// verifyElement validates the enveloped signature on el against the IdP
// certificates and returns the verified copy. The reference must be exactly
// "#<ID of el>", and there must be exactly one direct Signature.
func (p *Provider) verifyElement(el *etree.Element, certs []*x509.Certificate) (*etree.Element, error) {
	sigFail := func(format string, a ...any) error {
		return p.fail(sso.ErrCodeSignatureInvalid, http.StatusUnauthorized, format, a...)
	}
	id := el.SelectAttrValue("ID", "")
	if id == "" {
		return nil, sigFail("signed element has no ID")
	}
	sigs := children(el, nsDSig, "Signature")
	if len(sigs) != 1 {
		return nil, sigFail("expected exactly one signature on the element")
	}
	var refs []*etree.Element
	collect(sigs[0], nsDSig, "Reference", &refs)
	if len(refs) != 1 || refs[0].SelectAttrValue("URI", "") != "#"+id {
		return nil, sigFail("signature must have exactly one reference, to the element's own ID")
	}
	pctx, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		return nil, sigFail("cannot resolve namespaces")
	}
	detached, err := etreeutils.NSDetatch(pctx, el)
	if err != nil {
		return nil, sigFail("cannot isolate the signed element")
	}
	vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: certs})
	vc.Clock = dsig.NewFakeClockAt(p.now())
	out, err := vc.Validate(detached)
	if err != nil {
		return nil, sigFail("signature verification failed: %v", err)
	}
	if out.SelectAttrValue("ID", "") != id {
		return nil, sigFail("verified element differs from the referenced element")
	}
	return out, nil
}

// parseTime reads an xs:dateTime.
func parseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, strings.TrimSpace(s))
}

// checkAssertion applies the assertion-level rules and maps it to a user.
func (p *Provider) checkAssertion(a *etree.Element, meta *idpMeta, reqID string) (*sso.UserInfo, error) {
	now, skew := p.now(), p.cfg.ClockSkew
	if v := a.SelectAttrValue("Version", ""); v != "2.0" {
		return nil, p.invalid("unsupported assertion version %q", v)
	}
	aid := a.SelectAttrValue("ID", "")
	if aid == "" {
		return nil, p.invalid("assertion has no ID")
	}
	iss, err := child(a, nsAssertion, "Issuer")
	if err != nil || iss == nil || text(iss) != meta.EntityID {
		return nil, p.invalid("assertion Issuer is not the configured IdP")
	}

	// Subject: a bearer confirmation aimed at this ACS, for this request.
	subj, err := child(a, nsAssertion, "Subject")
	if err != nil || subj == nil {
		return nil, p.invalid("assertion has no Subject")
	}
	nid, err := child(subj, nsAssertion, "NameID")
	if err != nil || nid == nil || text(nid) == "" {
		return nil, p.invalid("assertion has no NameID")
	}
	var confirmedUntil time.Time
	for _, sc := range children(subj, nsAssertion, "SubjectConfirmation") {
		if sc.SelectAttrValue("Method", "") != "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
			continue
		}
		d, err := child(sc, nsAssertion, "SubjectConfirmationData")
		if err != nil || d == nil {
			continue
		}
		if d.SelectAttrValue("Recipient", "") != p.cfg.ACSURL || d.SelectAttrValue("InResponseTo", "") != reqID {
			continue
		}
		until, err := parseTime(d.SelectAttrValue("NotOnOrAfter", ""))
		if err != nil {
			continue
		}
		if nb := d.SelectAttrValue("NotBefore", ""); nb != "" { // not allowed on bearer data, refuse
			continue
		}
		if !now.Before(until.Add(skew)) {
			return nil, p.fail(sso.ErrCodeTokenExpired, http.StatusUnauthorized, "assertion confirmation has expired")
		}
		confirmedUntil = until
		break
	}
	if confirmedUntil.IsZero() {
		return nil, p.invalid("no bearer confirmation with the expected Recipient and InResponseTo")
	}

	// Conditions: validity window and audience.
	cond, err := child(a, nsAssertion, "Conditions")
	if err != nil || cond == nil {
		return nil, p.invalid("assertion has no Conditions")
	}
	if nb := cond.SelectAttrValue("NotBefore", ""); nb != "" {
		t, err := parseTime(nb)
		if err != nil || now.Add(skew).Before(t) {
			return nil, p.invalid("assertion is not valid yet")
		}
	}
	noa, err := parseTime(cond.SelectAttrValue("NotOnOrAfter", ""))
	if err != nil {
		return nil, p.invalid("assertion has no valid NotOnOrAfter")
	}
	if !now.Before(noa.Add(skew)) {
		return nil, p.fail(sso.ErrCodeTokenExpired, http.StatusUnauthorized, "assertion has expired")
	}
	restr := children(cond, nsAssertion, "AudienceRestriction")
	if len(restr) == 0 {
		return nil, p.invalid("assertion has no AudienceRestriction")
	}
	for _, r := range restr {
		found := false
		for _, au := range children(r, nsAssertion, "Audience") {
			if text(au) == p.cfg.SPEntityID {
				found = true
			}
		}
		if !found {
			return nil, p.invalid("Audience does not include this service provider")
		}
	}

	// Replay: an assertion ID is accepted once until it would expire anyway.
	keep := confirmedUntil
	if noa.After(keep) {
		keep = noa
	}
	if !p.markSeen(aid, keep.Add(skew)) {
		return nil, p.invalid("assertion was already used (replay)")
	}
	return p.userFromAssertion(a, nid, meta), nil
}

// markSeen records an assertion ID. It returns false if the ID was already
// recorded and not yet expired.
func (p *Provider) markSeen(id string, until time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	for k, exp := range p.seen {
		if now.After(exp) {
			delete(p.seen, k)
		}
	}
	if _, dup := p.seen[id]; dup {
		return false
	}
	p.seen[id] = until
	return true
}

// Attribute names (and OIDs) commonly used for each user field.
var (
	emailNames  = []string{"email", "mail", "emailaddress", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "urn:oid:0.9.2342.19200300.100.1.3"}
	givenNames  = []string{"givenname", "firstname", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", "urn:oid:2.5.4.42"}
	surNames    = []string{"surname", "sn", "lastname", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", "urn:oid:2.5.4.4"}
	displayName = []string{"displayname", "name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "urn:oid:2.16.840.1.113730.3.1.241"}
	groupNames  = []string{"groups", "memberof", "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"}
	roleNames   = []string{"roles", "role", "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"}
)

func pick(attrs map[string][]string, names []string) []string {
	for _, n := range names {
		if v := attrs[strings.ToLower(n)]; len(v) > 0 {
			return v
		}
	}
	return nil
}

func firstOf(v []string) string {
	if len(v) > 0 {
		return v[0]
	}
	return ""
}

// userFromAssertion maps the NameID and attributes. The user ID is the NameID
// scoped by the IdP entity ID, so two IdPs cannot produce the same ID. The
// email is never marked verified: SAML does not say whether it is.
func (p *Provider) userFromAssertion(a, nameID *etree.Element, meta *idpMeta) *sso.UserInfo {
	attrs := map[string][]string{}
	raw := map[string]any{}
	for _, st := range children(a, nsAssertion, "AttributeStatement") {
		for _, at := range children(st, nsAssertion, "Attribute") {
			name := at.SelectAttrValue("Name", "")
			if name == "" {
				continue
			}
			var vals []string
			for _, v := range children(at, nsAssertion, "AttributeValue") {
				vals = append(vals, text(v))
			}
			attrs[strings.ToLower(name)] = append(attrs[strings.ToLower(name)], vals...)
			raw[name] = vals
		}
	}
	raw["name_id"] = text(nameID)
	raw["name_id_format"] = nameID.SelectAttrValue("Format", "")
	raw["idp_entity_id"] = meta.EntityID

	email := firstOf(pick(attrs, emailNames))
	if email == "" && strings.HasSuffix(nameID.SelectAttrValue("Format", ""), "nameid-format:emailAddress") {
		email = text(nameID)
	}
	u := &sso.UserInfo{
		ID:            meta.EntityID + "|" + text(nameID),
		Email:         email,
		EmailVerified: false,
		Username:      text(nameID),
		FirstName:     firstOf(pick(attrs, givenNames)),
		LastName:      firstOf(pick(attrs, surNames)),
		DisplayName:   firstOf(pick(attrs, displayName)),
		Groups:        pick(attrs, groupNames),
		Roles:         pick(attrs, roleNames),
		RawAttributes: raw,
	}
	if u.DisplayName == "" {
		u.DisplayName = strings.TrimSpace(u.FirstName + " " + u.LastName)
	}
	return u
}
