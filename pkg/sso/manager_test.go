package sso_test

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/universal-sso/universal-sso/pkg/sso"
	"github.com/universal-sso/universal-sso/pkg/sso/mock"
)

func newManager(t *testing.T) *sso.Manager {
	t.Helper()
	signer, err := sso.NewStateSigner([]byte(strings.Repeat("s", 32)), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	m := sso.NewManager(sso.NewMemoryCache(0), signer, time.Minute)
	if err := m.Register(mock.New("mock")); err != nil {
		t.Fatal(err)
	}
	return m
}

func stateFromURL(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("state")
}

func TestFullLoginFlow(t *testing.T) {
	ctx := context.Background()
	m := newManager(t)

	resp, err := m.BeginLogin(ctx, "mock", sso.AuthURLRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp.URL, "code_challenge_method=S256") {
		t.Fatalf("PKCE not enforced: %s", resp.URL)
	}

	res, err := m.CompleteLogin(ctx, "mock", sso.CallbackRequest{State: stateFromURL(t, resp.URL), Code: "abc"})
	if err != nil {
		t.Fatal(err)
	}
	if res.User.Email != "user@example.test" || res.Tokens.AccessToken == "" { // nosecret
		t.Fatalf("unexpected result %+v", res)
	}

	p, _ := m.Get("mock")
	claims, err := p.ValidateToken(ctx, res.Tokens.AccessToken)
	if err != nil || claims.Subject != "mock-user-1" {
		t.Fatalf("validate: %v %+v", err, claims)
	}
	if ui, err := p.FetchUserInfo(ctx, res.Tokens.AccessToken); err != nil || ui.ID != "mock-user-1" {
		t.Fatalf("userinfo: %v", err)
	}

	nt, err := p.RefreshToken(ctx, res.Tokens.RefreshToken)
	if err != nil || nt.AccessToken == res.Tokens.AccessToken {
		t.Fatalf("refresh: %v", err)
	}
	if _, err := p.RefreshToken(ctx, res.Tokens.RefreshToken); err == nil {
		t.Fatal("refresh token reuse must fail")
	}

	if err := p.RevokeToken(ctx, nt.AccessToken); err != nil {
		t.Fatal(err)
	}
	if _, err := p.ValidateToken(ctx, nt.AccessToken); err == nil {
		t.Fatal("revoked token still valid")
	}
	lo, _ := p.GetLogoutURL(ctx, sso.LogoutRequest{PostLogoutURL: "https://app.test/", State: "s"})
	if !strings.Contains(lo.URL, "post_logout_redirect_uri") {
		t.Fatalf("logout url %s", lo.URL)
	}
}

func TestStateReplayRejected(t *testing.T) {
	ctx := context.Background()
	m := newManager(t)
	resp, _ := m.BeginLogin(ctx, "mock", sso.AuthURLRequest{})
	cb := sso.CallbackRequest{State: stateFromURL(t, resp.URL), Code: "abc"}
	if _, err := m.CompleteLogin(ctx, "mock", cb); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CompleteLogin(ctx, "mock", cb); err == nil {
		t.Fatal("replayed state accepted")
	}
}

func TestCallbackFailures(t *testing.T) {
	ctx := context.Background()
	m := newManager(t)

	if _, err := m.BeginLogin(ctx, "nope", sso.AuthURLRequest{}); err == nil {
		t.Fatal("expected provider not found")
	}
	if _, err := m.CompleteLogin(ctx, "mock", sso.CallbackRequest{State: "forged", Code: "x"}); err == nil {
		t.Fatal("forged state accepted")
	}
	if _, err := m.CompleteLogin(ctx, "mock", sso.CallbackRequest{Error: "access_denied"}); err == nil {
		t.Fatal("idp error must propagate")
	}
	// Valid signature but never issued by BeginLogin.
	signer, _ := sso.NewStateSigner([]byte(strings.Repeat("s", 32)), time.Minute)
	st, _ := signer.Sign()
	if _, err := m.CompleteLogin(ctx, "mock", sso.CallbackRequest{State: st, Code: "x"}); err == nil {
		t.Fatal("unissued state accepted")
	}
	// State bound to a different provider.
	_ = m.Register(mock.New("other"))
	resp, _ := m.BeginLogin(ctx, "mock", sso.AuthURLRequest{})
	if _, err := m.CompleteLogin(ctx, "other", sso.CallbackRequest{State: stateFromURL(t, resp.URL), Code: "x"}); err == nil {
		t.Fatal("cross-provider state accepted")
	}
	// Missing code.
	resp, _ = m.BeginLogin(ctx, "mock", sso.AuthURLRequest{})
	if _, err := m.CompleteLogin(ctx, "mock", sso.CallbackRequest{State: stateFromURL(t, resp.URL)}); err == nil {
		t.Fatal("missing code accepted")
	}
}

func TestManagerRegistry(t *testing.T) {
	m := newManager(t)
	if err := m.Register(mock.New("mock")); err == nil {
		t.Fatal("duplicate registration accepted")
	}
	_ = m.Register(mock.New("a"))
	ids := m.Providers()
	if len(ids) != 2 || ids[0] != "a" || ids[1] != "mock" {
		t.Fatalf("providers %v", ids)
	}
}

func TestMockDriver(t *testing.T) {
	p, err := sso.NewProvider(mock.DriverName, map[string]string{"id": "custom"})
	if err != nil || p.ID() != "custom" || p.Protocol() != sso.ProtocolMock || p.Name() == "" {
		t.Fatalf("driver: %v", err)
	}
	d, _ := sso.NewProvider(mock.DriverName, nil)
	if d.ID() != "mock" {
		t.Fatal("default id")
	}
	if _, err := p.GetAuthURL(context.Background(), sso.AuthURLRequest{}); err == nil {
		t.Fatal("empty state accepted")
	}
	if _, err := p.ValidateToken(context.Background(), "bogus"); err == nil {
		t.Fatal("bogus token accepted")
	}
}
