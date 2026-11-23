package sso

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// MinStateSecretLen is the minimum accepted length (bytes) for the HMAC state secret.
const MinStateSecretLen = 32

var b64 = base64.RawURLEncoding

// RandomString returns a URL-safe random string built from nBytes of entropy.
func RandomString(nBytes int) (string, error) {
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return b64.EncodeToString(buf), nil
}

// NewCodeVerifier generates an RFC 7636 PKCE code verifier (43 characters).
func NewCodeVerifier() (string, error) {
	return RandomString(32)
}

// CodeChallengeS256 derives the S256 PKCE code challenge from a verifier.
func CodeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return b64.EncodeToString(sum[:])
}

// StateSigner issues and verifies HMAC-SHA256 signed, expiring state parameters.
type StateSigner struct {
	secret []byte
	ttl    time.Duration
	now    func() time.Time
}

// NewStateSigner builds a signer. The secret must be at least MinStateSecretLen bytes.
func NewStateSigner(secret []byte, ttl time.Duration) (*StateSigner, error) {
	if len(secret) < MinStateSecretLen {
		return nil, ErrInvalidConfig(fmt.Sprintf("state secret must be at least %d bytes", MinStateSecretLen), nil)
	}
	if ttl <= 0 {
		return nil, ErrInvalidConfig("state ttl must be positive", nil)
	}
	return &StateSigner{secret: append([]byte(nil), secret...), ttl: ttl, now: time.Now}, nil
}

func (s *StateSigner) mac(payload string) []byte {
	h := hmac.New(sha256.New, s.secret)
	h.Write([]byte(payload))
	return h.Sum(nil)
}

// Sign returns a new state value: base64url(random.expiryUnix) + "." + base64url(hmac).
func (s *StateSigner) Sign() (string, error) {
	nonce, err := RandomString(16)
	if err != nil {
		return "", NewError(ErrCodeInternal, "random generation failed", 500, err)
	}
	payload := nonce + "." + strconv.FormatInt(s.now().Add(s.ttl).Unix(), 10)
	return b64.EncodeToString([]byte(payload)) + "." + b64.EncodeToString(s.mac(payload)), nil
}

// Verify checks the signature (constant time) and expiry of a state value.
func (s *StateSigner) Verify(state string) error {
	parts := strings.Split(state, ".")
	if len(parts) != 2 {
		return ErrStateInvalid("malformed state")
	}
	rawPayload, err := b64.DecodeString(parts[0])
	if err != nil {
		return ErrStateInvalid("malformed state payload")
	}
	sig, err := b64.DecodeString(parts[1])
	if err != nil {
		return ErrStateInvalid("malformed state signature")
	}
	payload := string(rawPayload)
	if subtle.ConstantTimeCompare(sig, s.mac(payload)) != 1 {
		return ErrStateInvalid("state signature mismatch")
	}
	idx := strings.LastIndex(payload, ".")
	if idx < 0 {
		return ErrStateInvalid("malformed state payload")
	}
	exp, err := strconv.ParseInt(payload[idx+1:], 10, 64)
	if err != nil {
		return ErrStateInvalid("malformed state expiry")
	}
	if s.now().Unix() > exp {
		return NewError(ErrCodeStateExpired, "state expired", 400, nil)
	}
	return nil
}
