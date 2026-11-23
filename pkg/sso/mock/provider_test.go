package mock

import (
	"context"
	"strings"
	"testing"

	"github.com/universal-sso/universal-sso/pkg/sso"
)

func TestAuthorizeURLOverride(t *testing.T) {
	p := New("m")
	req := sso.AuthURLRequest{State: "s", Nonce: "n", CodeVerifier: "v"}

	resp, err := p.GetAuthURL(context.Background(), req)
	if err != nil || !strings.HasPrefix(resp.URL, "https://mock.idp.invalid/authorize?") {
		t.Fatalf("default URL: %v %v", resp, err)
	}
	p.SetAuthorizeURL("/mock/authorize")
	resp, err = p.GetAuthURL(context.Background(), req)
	if err != nil || !strings.HasPrefix(resp.URL, "/mock/authorize?") {
		t.Fatalf("override URL: %v %v", resp, err)
	}
}
