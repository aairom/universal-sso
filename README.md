# Universal SSO

A modular Go SDK that gives applications one `Provider` abstraction over OIDC, OAuth 2.0 and SAML 2.0 identity providers. The core ships signed state (HMAC), mandatory PKCE (S256), one-time-use login state, a pluggable cache, a driver registry and an in-memory mock provider for tests.

**Status:** core, `Manager`, registry, mock provider and the **Google OIDC provider** (`pkg/sso/google`) are implemented. The **Okta, Auth0 and Microsoft Entra ID OIDC adapters** (`pkg/sso/okta`, `auth0`, `entra`, on the shared `pkg/sso/oidc`) are implemented and tested against a fake IdP, not yet against live tenants. SAML 2.0 and generic OAuth 2.0 adapters are planned; see [Docs/Architecture.md](Docs/Architecture.md).

## Architecture

```mermaid
flowchart LR
    App[Application or browser] --> H[cmd/ssod HTTP server]
    H --> M[sso.Manager]
    M --> S[StateSigner HMAC + PKCE]
    M --> C[(Cache)]
    M --> R[Driver registry]
    R --> P1[mock.Provider]
    R --> P3[google.Provider OIDC + PKCE + JWKS]
    P3 --> G[(Google accounts)]
    R --> P2[okta / auth0 / entra adapters on pkg/sso/oidc]
    P2 --> I[(Okta, Auth0, Entra ID)]
```

## Workflow

```mermaid
sequenceDiagram
    participant U as User
    participant A as Application
    participant M as Manager
    participant P as Provider
    U->>A: Click login
    A->>M: BeginLogin(provider)
    M->>M: sign state, nonce, PKCE verifier and cache them
    M->>P: GetAuthURL
    P-->>U: redirect to IdP
    U->>A: callback (state, code)
    A->>M: CompleteLogin
    M->>M: verify signature/expiry, consume state once
    M->>P: HandleCallback (code + verifier)
    P-->>A: IdentityResult
```

## Quick start

See [Docs/Quickstart.md](Docs/Quickstart.md), [Docs/Architecture.md](Docs/Architecture.md) and, for Google sign-in, [Docs/Google-SSO-Setup.md](Docs/Google-SSO-Setup.md).

```bash
cp .env.example .env     # then set SSO_STATE_SECRET to: openssl rand -base64 48 (ssod refuses the example value)
make start               # builds cmd/ssod, runs it detached, prints the URL
make stop                # graceful SIGTERM, SIGKILL after STOP_TIMEOUT
make restart
make test                # go vet + go test -race -cover
```

Before publishing, run `bash .bob/skills/secure-config/scripts/scan_secrets.sh .`, then `scripts/github-push.sh` (interactive helper that sets the remote, commits and pushes).

### Google credential helper (`ssoctl`)

`cmd/ssoctl` validates your Google OAuth setup and runs a PKCE sign-in by hand, independent of `ssod`. It never prints secrets.

```bash
make google-check                        # validate .env (add --offline via go run to skip network)
make google-url                          # print a sign-in URL, saves PKCE session to .run/
make google-exchange CODE='<full redirected URL>'   # exchange the code and check ID-token claims
```

Full walkthrough and troubleshooting: [Docs/Google-SSO-Setup.md](Docs/Google-SSO-Setup.md).

### Example clients (Rust, Go, Python, Java, C#)

`examples/` holds five command-line clients for the gateway: generic OAuth 2.0 in Rust, SAML 2.0 in Go, Auth0 in Python, Okta in Java and Azure AD / Entra ID in C#. They are clients of `ssod`: the gateway keeps the secrets and tokens. Their providers are still planned in the gateway, so they report `PROVIDER_NOT_FOUND` today and complete a full sign-in with `SSO_PROVIDER=mock`. Details, limits and test instructions: [Docs/Examples.md](Docs/Examples.md). Run every suite with `make test-examples`.

### Provider setup guides

Each guide follows the same structure: quick-start, how the pieces fit, provider-side setup, configuration values, verification with `curl`/`python3`, security, and troubleshooting.

| Provider | Guide | Adapter status |
|---|---|---|
| Google | [Docs/Google-SSO-Setup.md](Docs/Google-SSO-Setup.md) | Implemented (`pkg/sso/google`) |
| Azure AD / Microsoft Entra ID | [Docs/Azure-AD-SSO-Setup.md](Docs/Azure-AD-SSO-Setup.md) | Implemented (fake-IdP tested) |
| Okta | [Docs/Okta-SSO-Setup.md](Docs/Okta-SSO-Setup.md) | Implemented (fake-IdP tested) |
| Auth0 | [Docs/Auth0-SSO-Setup.md](Docs/Auth0-SSO-Setup.md) | Implemented (fake-IdP tested) |
| Generic SAML 2.0 | [Docs/SAML-SSO-Setup.md](Docs/SAML-SSO-Setup.md) | Planned |
| Generic OAuth 2.0 | [Docs/OAuth2-SSO-Setup.md](Docs/OAuth2-SSO-Setup.md) | Planned |

Okta, Auth0 and Azure AD are verified against an in-process fake OIDC server only (`bash tests/e2e.sh` signs every example client in through each adapter). They have **not** been exercised against a live tenant. For SAML 2.0 and generic OAuth 2.0 (planned) the identity-provider side can be configured and verified with the manual steps in each guide, and `ssod` answers `404 PROVIDER_NOT_FOUND`.

## Lifecycle scripts

| Command | Script | Behaviour |
|---|---|---|
| `make start` | `scripts/start.sh` | Loads `.env`, builds `.run/ssod`, starts it detached, waits for `/healthz`, prints `URL`, PID and log path. Already running: reports the PID and exits 0. |
| `make stop` | `scripts/stop.sh` | SIGTERM, waits up to `STOP_TIMEOUT` (default 15 s), then SIGKILL. Nothing running or stale PID file: exits 0. |
| `make restart` | stop, then start | |
| `make clean` | `scripts/cleanup.sh [--dry-run]` | Stops the app and removes `.run/`, `node_modules`, `.venv`, `__pycache__`. |

State lives in `.run/` (`app.pid`, `app.log`, `ssod`), which is git-ignored. Variables: `SSO_SERVER_HOST` (default `127.0.0.1`), `SSO_SERVER_PORT` (default `8080`), `SSO_STATE_SECRET` (required), `START_TIMEOUT`, `STOP_TIMEOUT`.

`ssod` endpoints: `GET /` (landing page with login links), `GET /mock/authorize` (local stand-in IdP for the mock provider), `GET /healthz`, `GET /providers`, `GET /auth/{provider}/login`, `GET /auth/{provider}/callback`. It always registers `mock`, and registers `google` when `SSO_PROVIDERS_GOOGLE_CLIENT_ID` and `SSO_PROVIDERS_GOOGLE_CLIENT_SECRET` are set to real values (optional `SSO_PROVIDERS_GOOGLE_HOSTED_DOMAIN`). The registered providers are logged at startup and listed at `/providers`.

## License

MIT
