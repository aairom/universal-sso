# Quickstart

This is a Go library plus a small reference server, `cmd/ssod`, that exposes the Manager over HTTP with the mock provider.

1. Copy `.env.example` to `.env`; set `SSO_STATE_SECRET` to at least 32 random bytes.
2. Run the tests: `make test`
3. Start and stop the server: `make start` (prints the URL), `make stop`, `make restart`. Try `curl <URL>/healthz` and open `<URL>/auth/mock/login`.
4. Use the library directly:

```go
signer, _ := sso.NewStateSigner([]byte(os.Getenv("SSO_STATE_SECRET")), 10*time.Minute)
mgr := sso.NewManager(sso.NewMemoryCache(time.Minute), signer, 10*time.Minute)
_ = mgr.Register(mock.New("mock"))

resp, _ := mgr.BeginLogin(ctx, "mock", sso.AuthURLRequest{}) // redirect user to resp.URL
// in the callback handler:
result, err := mgr.CompleteLogin(ctx, "mock", sso.CallbackRequest{State: state, Code: code})
```

5. Google sign-in: fill the `SSO_PROVIDERS_GOOGLE_*` values in `.env`, then run `make google-check`, `make google-url` and `make google-exchange CODE='<full redirected URL>'`. Then `make restart` and open `<URL>/auth/google/login`. See [Google-SSO-Setup.md](Google-SSO-Setup.md).
6. Other providers: setup guides exist for [Azure AD / Entra ID](Azure-AD-SSO-Setup.md), [Okta](Okta-SSO-Setup.md), [Auth0](Auth0-SSO-Setup.md), [SAML 2.0](SAML-SSO-Setup.md) and [generic OAuth 2.0](OAuth2-SSO-Setup.md). Their adapters are planned, so `ssod` returns `404 PROVIDER_NOT_FOUND` for them today. Each guide shows how to configure and verify the provider side manually.

Providers can also be created by name via `sso.NewProvider("mock", cfg)` after importing the driver package.
