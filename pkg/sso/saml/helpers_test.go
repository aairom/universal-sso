package saml

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
	"net/url"
	"regexp"
	"strings"
)

var certRe = regexp.MustCompile(`<ds:X509Certificate>[^<]*</ds:X509Certificate>`)

// regexpDropCert removes the signing certificate from metadata.
func regexpDropCert(md string) string { return certRe.ReplaceAllString(md, "") }

// regexpBadCert replaces the signing certificate with valid base64 that is not a certificate.
func regexpBadCert(md string) string {
	return certRe.ReplaceAllString(md, "<ds:X509Certificate>bm90IGEgY2VydA==</ds:X509Certificate>")
}

func bigOne() *big.Int { return big.NewInt(1) }

// verifyWith checks the Signature of a signed HTTP-Redirect query with key's public half.
func verifyWith(key *rsa.PrivateKey, rawQuery string) error {
	i := strings.LastIndex(rawQuery, "&Signature=")
	if i < 0 {
		return errors.New("no Signature")
	}
	sigB64, err := url.QueryUnescape(rawQuery[i+len("&Signature="):])
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(rawQuery[:i]))
	return rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], sig)
}
