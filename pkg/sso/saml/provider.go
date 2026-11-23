// Package saml is a SAML 2.0 service provider for the gateway: SP-initiated
// Web Browser SSO with the HTTP-Redirect binding for the AuthnRequest and the
// HTTP-POST binding for the Response.
//
// The gateway never trusts a Response because it arrived. Every Response goes
// through the checks in response.go: signature against the IdP certificates
// from the metadata, only the verified XML is read afterwards (signature
// wrapping defence), DTDs and oversize input are refused, and Destination,
// Recipient, Audience, Issuer, validity window, InResponseTo and assertion
// replay are enforced. Responses the gateway did not ask for are refused.
//
// Not supported: encrypted assertions, IdP-initiated SSO, Single Logout,
// SHA-1 signatures. Unsupported provider methods return UNSUPPORTED_METHOD.
//
// Importing the package registers the "saml" driver with the sso registry.
package saml

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"bytes"
	"compress/flate"

	"github.com/beevik/etree"

	"github.com/universal-sso/universal-sso/pkg/sso"
	"github.com/universal-sso/universal-sso/pkg/sso/oidc"
)

// DriverName is the name under which the provider is registered.
const DriverName = "saml"

const (
	defaultSkew   = 60 * time.Second
	metaTTL       = time.Hour
	pendingTTL    = 15 * time.Minute
	maxPending    = 10000
	rsaSHA256URI  = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	bindingPOST   = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	maxMetaBytes  = maxXMLBytes
	requestIDSize = 20
)

func init() {
	sso.RegisterDriver(DriverName, func(cfg map[string]string) (sso.Provider, error) {
		p, err := New(Config{
			ID:              cfg["id"],
			SPEntityID:      cfg["sp_entity_id"],
			ACSURL:          cfg["acs_url"],
			IDPMetadataURL:  cfg["idp_metadata_url"],
			IDPMetadataFile: cfg["idp_metadata_file"],
			SPCertFile:      cfg["sp_cert_file"],
			SPKeyFile:       cfg["sp_key_file"],
		})
		if err != nil {
			return nil, err // never wrap a nil *Provider in the interface
		}
		return p, nil
	})
}

// Config configures a Provider. SPEntityID, ACSURL and one metadata source
// are required.
type Config struct {
	ID   string // provider ID used in URLs (default "saml")
	Name string // human-readable name (default "SAML 2.0")

	SPEntityID string // the SP's entity ID, also the expected Audience
	ACSURL     string // assertion consumer service URL, also Destination and Recipient

	IDPMetadataURL  string // https URL of the IdP metadata (fetched lazily)
	IDPMetadataFile string // or a local file (alternative to the URL)

	// SPCertFile and SPKeyFile are optional. When both are set the
	// AuthnRequest is signed (RSA-SHA256, HTTP-Redirect binding).
	SPCertFile string
	SPKeyFile  string

	ClockSkew  time.Duration // tolerated clock difference (default 60s)
	HTTPClient *http.Client
}

type pendingReq struct {
	id  string
	exp time.Time
}

// Provider is a SAML 2.0 service provider.
type Provider struct {
	cfg  Config
	http *http.Client
	now  func() time.Time
	key  *rsa.PrivateKey // optional request signing key

	mu      sync.Mutex
	meta    *idpMeta
	metaAt  time.Time
	pending map[string]pendingReq // RelayState (the signed state) -> AuthnRequest ID
	seen    map[string]time.Time  // assertion ID -> forget-after, the replay cache
}

// New validates cfg and creates the provider. It does no network access: IdP
// metadata given by URL is fetched on first use, so the gateway can start
// before the IdP is reachable.
func New(cfg Config) (*Provider, error) {
	if cfg.ID == "" {
		cfg.ID = DriverName
	}
	if cfg.Name == "" {
		cfg.Name = "SAML 2.0"
	}
	if cfg.SPEntityID == "" || cfg.ACSURL == "" {
		return nil, sso.ErrInvalidConfig(cfg.Name+": sp_entity_id and acs_url are required", nil)
	}
	if (cfg.IDPMetadataURL == "") == (cfg.IDPMetadataFile == "") {
		return nil, sso.ErrInvalidConfig(cfg.Name+": set exactly one of idp_metadata_url and idp_metadata_file", nil)
	}
	if err := oidc.ValidateURL(cfg.Name, "acs_url", cfg.ACSURL); err != nil {
		return nil, err
	}
	if cfg.IDPMetadataURL != "" {
		if err := oidc.ValidateURL(cfg.Name, "idp_metadata_url", cfg.IDPMetadataURL); err != nil {
			return nil, err
		}
	}
	if cfg.ClockSkew <= 0 {
		cfg.ClockSkew = defaultSkew
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		}}
	}
	p := &Provider{
		cfg: cfg, http: hc, now: time.Now,
		pending: map[string]pendingReq{}, seen: map[string]time.Time{},
	}
	if (cfg.SPCertFile == "") != (cfg.SPKeyFile == "") {
		return nil, sso.ErrInvalidConfig(cfg.Name+": sp_cert_file and sp_key_file must be set together", nil)
	}
	if cfg.SPKeyFile != "" {
		k, err := loadKey(cfg.SPKeyFile)
		if err != nil {
			return nil, sso.ErrInvalidConfig(cfg.Name+": sp_key_file: "+err.Error(), nil)
		}
		p.key = k
	}
	if cfg.IDPMetadataFile != "" { // a local file is cheap: fail at start-up
		if _, err := p.loadMeta(context.Background()); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func (p *Provider) ID() string                 { return p.cfg.ID }
func (p *Provider) Name() string               { return p.cfg.Name }
func (p *Provider) Protocol() sso.ProtocolType { return sso.ProtocolSAML2 }

func (p *Provider) errf(format string, a ...any) string {
	return p.cfg.Name + ": " + fmt.Sprintf(format, a...)
}

func (p *Provider) unsupported(what string) error {
	return sso.NewError(sso.ErrCodeUnsupportedMethod, p.errf("%s is not supported by SAML 2.0 sign-in", what), http.StatusNotImplemented, nil)
}

// loadKey reads an RSA private key (PKCS#8 or PKCS#1 PEM) of at least 2048 bits.
func loadKey(path string) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	var key *rsa.PrivateKey
	if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("only RSA keys are supported")
		}
		key = rk
	} else if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		key = k
	} else {
		return nil, fmt.Errorf("cannot parse the private key")
	}
	if key.N.BitLen() < minRSABits {
		return nil, fmt.Errorf("RSA key is %d bits, minimum is %d", key.N.BitLen(), minRSABits)
	}
	return key, nil
}

// loadMeta returns the IdP metadata, using a cached copy for metaTTL. If a
// refresh fails and an older copy exists, the older copy is kept.
func (p *Provider) loadMeta(ctx context.Context) (*idpMeta, error) {
	p.mu.Lock()
	cached, at := p.meta, p.metaAt
	p.mu.Unlock()
	if cached != nil && p.now().Sub(at) < metaTTL {
		return cached, nil
	}
	var data []byte
	if p.cfg.IDPMetadataFile != "" {
		b, err := os.ReadFile(p.cfg.IDPMetadataFile)
		if err != nil {
			if cached != nil {
				return cached, nil
			}
			return nil, sso.ErrInvalidConfig(p.errf("cannot read idp_metadata_file: %v", err), nil)
		}
		data = b
	} else {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.IDPMetadataURL, nil)
		if err != nil {
			return nil, sso.NewError(sso.ErrCodeNetworkFailure, p.errf("build metadata request"), http.StatusBadGateway, err)
		}
		resp, err := p.http.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				err = fmt.Errorf("status %d", resp.StatusCode)
			} else {
				data, err = io.ReadAll(io.LimitReader(resp.Body, maxMetaBytes+1))
			}
		}
		if err != nil {
			if cached != nil {
				return cached, nil
			}
			return nil, sso.NewError(sso.ErrCodeNetworkFailure, p.errf("fetch IdP metadata failed"), http.StatusBadGateway, err)
		}
	}
	m, err := parseMetadata(p.cfg.Name, data)
	if err != nil {
		if cached != nil {
			return cached, nil
		}
		return nil, err
	}
	p.mu.Lock()
	p.meta, p.metaAt = m, p.now()
	p.mu.Unlock()
	return m, nil
}

// deflate compresses with raw DEFLATE (RFC 1951), as the HTTP-Redirect binding requires.
func deflate(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(b); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// buildAuthnRequest returns the AuthnRequest XML and its ID.
func (p *Provider) buildAuthnRequest(destination string) ([]byte, string, error) {
	raw := make([]byte, requestIDSize)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", err
	}
	id := "_" + hex.EncodeToString(raw) // an XML ID must not start with a digit
	doc := etree.NewDocument()
	ar := doc.CreateElement("samlp:AuthnRequest")
	ar.CreateAttr("xmlns:samlp", nsProtocol)
	ar.CreateAttr("xmlns:saml", nsAssertion)
	ar.CreateAttr("ID", id)
	ar.CreateAttr("Version", "2.0")
	ar.CreateAttr("IssueInstant", p.now().UTC().Format("2006-01-02T15:04:05Z"))
	ar.CreateAttr("Destination", destination)
	ar.CreateAttr("ProtocolBinding", bindingPOST)
	ar.CreateAttr("AssertionConsumerServiceURL", p.cfg.ACSURL)
	ar.CreateElement("saml:Issuer").SetText(p.cfg.SPEntityID)
	np := ar.CreateElement("samlp:NameIDPolicy")
	np.CreateAttr("AllowCreate", "true")
	out, err := doc.WriteToBytes()
	return out, id, err
}

// GetAuthURL builds the HTTP-Redirect URL: SAMLRequest (raw DEFLATE, base64)
// and RelayState (the signed state), plus SigAlg and Signature when a key is
// configured. The AuthnRequest ID is remembered under the state so the
// Response can be matched to it.
func (p *Provider) GetAuthURL(ctx context.Context, req sso.AuthURLRequest) (*sso.AuthURLResponse, error) {
	if req.State == "" {
		return nil, sso.ErrInvalidConfig(p.errf("state is required"), nil)
	}
	meta, err := p.loadMeta(ctx)
	if err != nil {
		return nil, err
	}
	xmlBytes, id, err := p.buildAuthnRequest(meta.SSOURL)
	if err != nil {
		return nil, sso.NewError(sso.ErrCodeInternal, p.errf("build AuthnRequest"), http.StatusInternalServerError, err)
	}
	comp, err := deflate(xmlBytes)
	if err != nil {
		return nil, sso.NewError(sso.ErrCodeInternal, p.errf("compress AuthnRequest"), http.StatusInternalServerError, err)
	}
	// The signed octets are the URL-encoded parameters in this exact order
	// (SAML bindings 3.4.4.1), so build the query by hand.
	query := "SAMLRequest=" + url.QueryEscape(base64.StdEncoding.EncodeToString(comp)) +
		"&RelayState=" + url.QueryEscape(req.State)
	if p.key != nil {
		query += "&SigAlg=" + url.QueryEscape(rsaSHA256URI)
		sum := sha256.Sum256([]byte(query))
		sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, sum[:])
		if err != nil {
			return nil, sso.NewError(sso.ErrCodeInternal, p.errf("sign AuthnRequest"), http.StatusInternalServerError, err)
		}
		query += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	}
	if err := p.remember(req.State, id); err != nil {
		return nil, err
	}
	u := meta.SSOURL
	if strings.Contains(u, "?") {
		u += "&" + query
	} else {
		u += "?" + query
	}
	return &sso.AuthURLResponse{URL: u, State: req.State}, nil
}

// remember stores the AuthnRequest ID under the state, dropping expired entries.
func (p *Provider) remember(state, id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if len(p.pending) >= maxPending {
		for k, v := range p.pending {
			if now.After(v.exp) {
				delete(p.pending, k)
			}
		}
		if len(p.pending) >= maxPending {
			return sso.NewError(sso.ErrCodeInternal, p.errf("too many pending sign-ins"), http.StatusServiceUnavailable, nil)
		}
	}
	p.pending[state] = pendingReq{id: id, exp: now.Add(pendingTTL)}
	return nil
}

// take removes and returns the AuthnRequest ID stored for state.
func (p *Provider) take(state string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	v, ok := p.pending[state]
	delete(p.pending, state)
	if !ok || p.now().After(v.exp) {
		return "", false
	}
	return v.id, true
}

// ValidateToken is not supported: a SAML assertion is consumed once at sign-in.
func (p *Provider) ValidateToken(context.Context, string) (*sso.Claims, error) {
	return nil, p.unsupported("token validation")
}

// RefreshToken is not supported: SAML has no refresh tokens.
func (p *Provider) RefreshToken(context.Context, string) (*sso.TokenResponse, error) {
	return nil, p.unsupported("token refresh")
}

// RevokeToken is not supported: SAML has no tokens to revoke.
func (p *Provider) RevokeToken(context.Context, string) error {
	return p.unsupported("token revocation")
}

// GetLogoutURL is not supported: Single Logout is not implemented.
func (p *Provider) GetLogoutURL(context.Context, sso.LogoutRequest) (*sso.LogoutURLResponse, error) {
	return nil, p.unsupported("Single Logout")
}

// FetchUserInfo is not supported: there is no access token to call with.
func (p *Provider) FetchUserInfo(context.Context, string) (*sso.UserInfo, error) {
	return nil, p.unsupported("userinfo lookup")
}

var _ sso.Provider = (*Provider)(nil)
