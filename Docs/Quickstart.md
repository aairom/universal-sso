# Quickstart

Universal SSO is a Go library plus a small reference server, `cmd/ssod`, that exposes the `Manager` over HTTP. It ships with a `mock` provider (no setup) and a `google` provider (needs credentials).

## Contents

1. [Prerequisites](#prerequisites)
2. [Configure](#configure)
3. [Run and verify](#run-and-verify)
4. [Provider status](#provider-status)
5. [Sign in with Google](#sign-in-with-google)
6. [Use as a library](#use-as-a-library)
7. [Before you push](#before-you-push)
8. [Troubleshooting](#troubleshooting)
9. [What next](#what-next)

## Prerequisites

| Tool | Why |
|---|---|
| Go 1.25.3 or newer | build and test (`go.mod` pins it) |
| `make` | wraps build, test, start and stop |
| `curl` | verify endpoints |
| `openssl` | generate the state secret |

On macOS, port 5000 is reserved by AirDrop. `scripts/start.sh` refuses it, so keep the default `8080` or pick another.

## Configure

```bash
cp -n .env.example .env && chmod 600 .env
sed -i.bak "s|^SSO_STATE_SECRET=.*|SSO_STATE_SECRET=$(openssl rand -base64 48 | tr -d '\n')|" .env && rm .env.bak
```

- `SSO_STATE_SECRET` signs the login state (HMAC). It must be at least 32 bytes and private.
- The example value in `.env.example` is public. `ssod` **refuses to start** with it and tells you to generate your own.
- `.env` is git-ignored and is read by the shell in `scripts/start.sh`, so quote values that contain spaces or `$`.
- Leave the `SSO_PROVIDERS_*` entries untouched to run with the mock provider only. Values ending in `-placeholder` are treated as unset.

## Run and verify

```bash
make test        # go vet + go test -race -cover
make start       # builds cmd/ssod and runs it detached
```

Expected output of `make start`:

```text
Application started (pid 12345)
URL: http://127.0.0.1:8080
Logs: .run/app.log
```

The pid differs on each run. Then:

```bash
curl -s http://127.0.0.1:8080/healthz      # {"status":"ok"}
curl -s http://127.0.0.1:8080/providers    # lists registered providers
make stop                                  # graceful shutdown; make restart does stop + start
```

| Endpoint | Purpose |
|---|---|
| `GET /` | landing page |
| `GET /healthz` | liveness check |
| `GET /providers` | registered provider ids |
| `GET /auth/{provider}/login` | start a sign-in, redirects to the provider |
| `GET /auth/{provider}/callback` | provider redirects back here |
| `GET /mock/authorize` | built-in fake login page for the mock provider |

Try the full flow without any account: open `http://127.0.0.1:8080/auth/mock/login` in a browser.

## Provider status

| Provider | Status | Guide |
|---|---|---|
| mock | Implemented | none needed |
| Google | Implemented | [Google-SSO-Setup.md](Google-SSO-Setup.md) |
| Azure AD / Entra ID | Implemented, tested against a fake IdP only | [Azure-AD-SSO-Setup.md](Azure-AD-SSO-Setup.md) |
| Okta | Implemented, tested against a fake IdP only | [Okta-SSO-Setup.md](Okta-SSO-Setup.md) |
| Auth0 | Implemented, tested against a fake IdP only | [Auth0-SSO-Setup.md](Auth0-SSO-Setup.md) |
| Generic OAuth 2.0 | Implemented, tested against a fake IdP only | [OAuth2-SSO-Setup.md](OAuth2-SSO-Setup.md) |
| SAML 2.0 | Implemented (SP-initiated Web Browser SSO), tested against a fake IdP only | [SAML-SSO-Setup.md](SAML-SSO-Setup.md) |

Okta, Auth0, Azure AD / Entra ID and generic OAuth 2.0 are registered when their `SSO_PROVIDERS_<NAME>_CLIENT_ID` and `_CLIENT_SECRET` are set to real values in `.env` (OAuth 2.0 also needs `_AUTH_URL`, `_TOKEN_URL` and `_USERINFO_URL`). They are covered by unit tests and an end-to-end run against in-process fake servers (`bash tests/e2e.sh`). **They have not been signed in against a live tenant or provider**: do that once with your own account following the guide. Check the settings first with `make provider-check P=okta|auth0|azure|oauth2|saml`. SAML 2.0 is registered when `SSO_PROVIDERS_SAML_SP_ENTITY_ID` is set to a real value together with IdP metadata (`SSO_PROVIDERS_SAML_IDP_METADATA_URL` or `_IDP_METADATA_FILE`); it needs no client id or secret. It is also fake-IdP tested only, and only the Go example client can complete a SAML sign-in, because the other clients need OAuth `state` and PKCE parameters that a SAML redirect does not carry. SAML does not support encrypted assertions, IdP-initiated SSO, Single Logout or SHA-1.

## Sign in with Google

1. Fill the `SSO_PROVIDERS_GOOGLE_*` values in `.env` (see the Google guide for where to find them).
2. Validate and test the setup:

   ```bash
   make google-check                                   # validates .env
   make google-url                                     # prints a sign-in URL
   make google-exchange CODE='<full redirected URL>'   # checks the token claims
   ```

3. `make restart`. The log line `providers: google, mock` in `.run/app.log` confirms Google is registered.
4. Open `http://127.0.0.1:8080/auth/google/login`.

## Use as a library

The snippet builds the provider directly with `mock.New`. To create providers by name with `sso.NewProvider("mock", cfg)`, import the driver package for its side effect: `import _ "github.com/universal-sso/universal-sso/pkg/sso/mock"`.

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/universal-sso/universal-sso/pkg/sso"
	"github.com/universal-sso/universal-sso/pkg/sso/mock"
)

func main() {
	ctx := context.Background()
	ttl := 10 * time.Minute

	signer, err := sso.NewStateSigner([]byte(os.Getenv("SSO_STATE_SECRET")), ttl)
	if err != nil {
		log.Fatal(err)
	}
	mgr := sso.NewManager(sso.NewMemoryCache(time.Minute), signer, ttl)
	if err := mgr.Register(mock.New("mock")); err != nil {
		log.Fatal(err)
	}

	// 1. Redirect the user to resp.URL.
	resp, err := mgr.BeginLogin(ctx, "mock", sso.AuthURLRequest{})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(resp.URL)

	// 2. In your callback handler, pass back the state and code from the query string.
	var state, code string // read from the request
	result, err := mgr.CompleteLogin(ctx, "mock", sso.CallbackRequest{State: state, Code: code})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(result.User.Email)
}
```

The cache is in memory. Pending logins are lost on restart and are not shared between instances, so run one instance or supply your own `sso.Cache` implementation.

## Before you push

```bash
bash .bob/skills/secure-config/scripts/scan_secrets.sh .
bash .bob/skills/test-gate/scripts/run_tests.sh
scripts/github-push.sh        # interactive helper: sets the remote, commits, pushes
```

`.env` and `_sources/` are git-ignored. Do not paste real or realistic-looking Google Client IDs or `GOCSPX-` client secrets into docs, code or tests: GitHub push protection matches their shape and blocks the push. Describe them in words, or build test values by string concatenation.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `ssod: configuration error: SSO_STATE_SECRET still holds the public example value` | Run the command in [Configure](#configure) to generate your own secret. |
| `make start` complains about `SSO_STATE_SECRET` or port 5000 | Set a non-empty secret, and pick a port other than 5000 on macOS. |
| `404 PROVIDER_NOT_FOUND` on `/auth/<provider>/login` | The provider is not configured (empty or sample client id; for SAML 2.0, no `SP_ENTITY_ID` or no IdP metadata). Check `/providers` and the [status table](#provider-status). |
| Google sign-in fails | Run `make google-check`, then see [Google-SSO-Setup.md](Google-SSO-Setup.md). |
| Server not reachable | Read `.run/app.log`; `make stop` then `make start`. |

## What next

- [Architecture.md](Architecture.md): components, protocols, security model.
- [Examples.md](Examples.md): command-line gateway clients in Rust, Go, Python, Java and C#.
- Provider guides in the [status table](#provider-status).
- Open items: signing in against a live tenant or IdP for Okta, Auth0, Entra, OAuth 2.0 and SAML 2.0 (everything so far ran against in-process fakes), and a Node.js client (none exists).
