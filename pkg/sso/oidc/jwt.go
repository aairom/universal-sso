package oidc

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
)

// idClaims are the ID-token claims this provider reads.
type idClaims struct {
	Issuer        string   `json:"iss"`
	Subject       string   `json:"sub"`
	Audience      audience `json:"aud"`
	ExpiresAt     int64    `json:"exp"`
	IssuedAt      int64    `json:"iat"`
	NotBefore     int64    `json:"nbf"`
	Nonce         string   `json:"nonce"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Name          string   `json:"name"`
	GivenName     string   `json:"given_name"`
	FamilyName    string   `json:"family_name"`
	Picture       string   `json:"picture"`
}

// audience accepts both the string and array forms of the "aud" claim.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

func (a audience) contains(s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// parsedJWT is a compact JWS split into its verified-later parts.
type parsedJWT struct {
	header  jwtHeader
	claims  idClaims
	signing string // "<header>.<payload>"
	sig     []byte
	raw     map[string]any
}

var errMalformedJWT = errors.New("malformed jwt")

// parseJWT decodes a compact JWT without verifying it. Only RS256 is accepted,
// which rejects "none" and algorithm-confusion attempts up front.
func parseJWT(token string) (*parsedJWT, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errMalformedJWT
	}
	dec := base64.RawURLEncoding
	hb, err := dec.DecodeString(parts[0])
	if err != nil {
		return nil, errMalformedJWT
	}
	pb, err := dec.DecodeString(parts[1])
	if err != nil {
		return nil, errMalformedJWT
	}
	sig, err := dec.DecodeString(parts[2])
	if err != nil {
		return nil, errMalformedJWT
	}
	j := &parsedJWT{signing: parts[0] + "." + parts[1], sig: sig}
	if err := json.Unmarshal(hb, &j.header); err != nil {
		return nil, errMalformedJWT
	}
	if err := json.Unmarshal(pb, &j.claims); err != nil {
		return nil, errMalformedJWT
	}
	if err := json.Unmarshal(pb, &j.raw); err != nil {
		return nil, errMalformedJWT
	}
	if j.header.Alg != "RS256" {
		return nil, errors.New("unsupported jwt algorithm: " + j.header.Alg)
	}
	return j, nil
}

// verify checks the RS256 signature with the given public key.
func (j *parsedJWT) verify(pub *rsa.PublicKey) error {
	sum := sha256.Sum256([]byte(j.signing))
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], j.sig)
}

// jwk is one entry of a JSON Web Key Set.
type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (k jwk) publicKey() (*rsa.PublicKey, error) {
	if k.Kty != "RSA" {
		return nil, errors.New("unsupported key type: " + k.Kty)
	}
	if k.Use != "" && k.Use != "sig" {
		return nil, errors.New("key is not a signing key")
	}
	nb, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	e := new(big.Int).SetBytes(eb)
	if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
		return nil, errors.New("invalid rsa exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(e.Int64())}, nil
}
