package sso

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestMemoryCache(t *testing.T) {
	ctx := context.Background()
	c := NewMemoryCache(0)

	if _, ok, _ := c.Get(ctx, "missing"); ok {
		t.Fatal("expected miss")
	}
	_ = c.Set(ctx, "k", []byte("v"), 0)
	v, ok, _ := c.Get(ctx, "k")
	if !ok || string(v) != "v" {
		t.Fatalf("got %q %v", v, ok)
	}
	v[0] = 'x' // mutating the copy must not affect the store
	if v2, _, _ := c.Get(ctx, "k"); string(v2) != "v" {
		t.Fatal("cache returned aliased bytes")
	}
	_ = c.Delete(ctx, "k")
	if _, ok, _ := c.Get(ctx, "k"); ok {
		t.Fatal("expected deleted")
	}
	_ = c.Set(ctx, "a", []byte("1"), time.Minute)
	_ = c.Clear(ctx)
	if _, ok, _ := c.Get(ctx, "a"); ok {
		t.Fatal("expected cleared")
	}
}

func TestMemoryCacheTTL(t *testing.T) {
	ctx := context.Background()
	c := NewMemoryCache(5 * time.Millisecond)
	_ = c.Set(ctx, "k", []byte("v"), 10*time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	if _, ok, _ := c.Get(ctx, "k"); ok {
		t.Fatal("expected expiry")
	}
}

func TestCacheKey(t *testing.T) {
	if CacheKey("a", "b") != "a:b" {
		t.Fatal("unexpected key")
	}
}

func TestErrors(t *testing.T) {
	cause := errors.New("boom")
	e := ErrInvalidConfig("bad", cause)
	if !errors.Is(e, cause) || !strings.Contains(e.Error(), "boom") {
		t.Fatal("cause not wrapped")
	}
	if ErrNotFound("x").HTTPStatus != 404 || ErrStateInvalid("x").HTTPStatus != 400 ||
		ErrTokenValidation("x", nil).HTTPStatus != 401 || ErrUnauthorizedAccess("x").HTTPStatus != 401 {
		t.Fatal("unexpected http status")
	}
	if strings.Contains(ErrNotFound("x").Error(), ":") && !strings.HasPrefix(ErrNotFound("x").Error(), "[PROVIDER_NOT_FOUND]") {
		t.Fatal("unexpected format")
	}
}

func TestPKCE(t *testing.T) {
	// RFC 7636 appendix B test vector.
	got := CodeChallengeS256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
	if got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("challenge %s", got)
	}
	v, err := NewCodeVerifier()
	if err != nil || len(v) != 43 {
		t.Fatalf("verifier %q %v", v, err)
	}
}

func newSigner(t *testing.T, ttl time.Duration) *StateSigner {
	t.Helper()
	s, err := NewStateSigner([]byte(strings.Repeat("k", 32)), ttl)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestStateSignerConfig(t *testing.T) {
	if _, err := NewStateSigner([]byte("short"), time.Minute); err == nil {
		t.Fatal("expected short secret error")
	}
	if _, err := NewStateSigner([]byte(strings.Repeat("k", 32)), 0); err == nil {
		t.Fatal("expected ttl error")
	}
}

func TestStateSignVerify(t *testing.T) {
	s := newSigner(t, time.Minute)
	st, err := s.Sign()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(st); err != nil {
		t.Fatalf("valid state rejected: %v", err)
	}
	for _, bad := range []string{"", "abc", "a.b.c", "!!.!!", st + "x", "x" + st} {
		if err := s.Verify(bad); err == nil {
			t.Fatalf("tampered state %q accepted", bad)
		}
	}
	other, _ := NewStateSigner([]byte(strings.Repeat("z", 32)), time.Minute)
	if err := other.Verify(st); err == nil {
		t.Fatal("state accepted under different secret")
	}
}

func TestStateExpiry(t *testing.T) {
	s := newSigner(t, time.Minute)
	st, _ := s.Sign()
	s.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	err := s.Verify(st)
	var se *SSOError
	if !errors.As(err, &se) || se.Code != ErrCodeStateExpired {
		t.Fatalf("expected expired, got %v", err)
	}
}

func TestRegistry(t *testing.T) {
	RegisterDriver("test-driver", func(map[string]string) (Provider, error) { return nil, nil })
	if _, err := NewProvider("nope", nil); err == nil {
		t.Fatal("expected unknown driver error")
	}
	if _, err := NewProvider("test-driver", nil); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range Drivers() {
		found = found || n == "test-driver"
	}
	if !found {
		t.Fatal("driver not listed")
	}
	mustPanic(t, func() { RegisterDriver("test-driver", func(map[string]string) (Provider, error) { return nil, nil }) })
	mustPanic(t, func() { RegisterDriver("nil-driver", nil) })
}

func mustPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	f()
}
