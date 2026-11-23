# Auth0 in Python

A Python client for the Universal SSO gateway (`ssod`). It starts a sign-in for the `auth0` provider with an Auth0 tenant, checks the redirect the gateway returns, and (for the mock provider) completes the sign-in without a browser.

> **Read this first.** The gateway in this repository implements the `mock` and `google` providers only. The `auth0` adapter is **planned**, so against today's `ssod` this example gets `404 PROVIDER_NOT_FOUND`, and prints a clear message. The full flow runs today with `SSO_PROVIDER=mock`. Once the `auth0` adapter exists in the gateway, this client works unchanged. See [Provider status](../../Docs/Quickstart.md#provider-status).

## What this client does, and does not do

| Does | Does not |
|---|---|
| Checks the gateway: `GET /healthz`, `GET /providers` | Hold OAuth client ids, secrets or signing keys. They stay in the gateway's `.env` |
| Starts a login: `GET /auth/{provider}/login` | Create or verify the signed `state`, PKCE verifier or nonce. The gateway does |
| Refuses unsafe redirects: non-https IdP, wrong host, missing `state`, missing PKCE `S256` | Receive tokens. The gateway's callback returns the user profile only and never echoes tokens |
| Reads the profile from `GET /auth/{provider}/callback` (mock only, no browser needed) | Manage sessions, refresh tokens or call protected APIs. The gateway has no such endpoints yet |

Token refresh, session cookies and protected-resource calls need gateway features that do not exist today. Adding fake ones to a client would be misleading, so they are left out on purpose.

## Gateway contract

| Request | Success | Error |
|---|---|---|
| `GET /healthz` | `200 {"status":"ok"}` | |
| `GET /providers` | `200 {"providers":["mock","google"]}` | |
| `GET /auth/{provider}/login` | `302` to the IdP authorization URL, carrying `state` and PKCE `code_challenge` (`S256`) | `{"code","message"}`, for example `404 PROVIDER_NOT_FOUND` |
| `GET /auth/{provider}/callback` | `200 {"provider_id","user":{id,email,email_verified,display_name,roles}}` | `400 STATE_MISMATCH`, `400 STATE_EXPIRED`, `401 IDP_REJECTED` |

The callback URL registered with the identity provider is the **gateway's**: `<SSO_SERVER_BASE_URL>/auth/auth0/callback`. This client has no callback of its own.

```mermaid
sequenceDiagram
    participant C as This client
    participant G as ssod gateway
    participant B as Browser
    participant I as Identity provider
    C->>G: GET /auth/auth0/login
    G-->>C: 302 to IdP (state, PKCE S256)
    C->>C: check redirect policy
    C->>B: print URL to open
    B->>I: authenticate
    I-->>B: redirect to gateway callback with code and state
    B->>G: GET /auth/auth0/callback
    G-->>B: 200 user profile (no tokens)
```

## Prerequisites

- Python 3.9 or newer (standard library only)
- A running gateway (default `http://localhost:8080`): `make start` in the repository root.
- For a real provider: its adapter in the gateway, plus a sandbox tenant with credentials from [Docs/Auth0-SSO-Setup.md](../../Docs/Auth0-SSO-Setup.md). None are included here.

## Configure

```bash
cp .env.example .env     # then edit; .env is git-ignored
```

| Variable | Default | Meaning |
|---|---|---|
| `SSO_GATEWAY_URL` | `http://localhost:8080` | gateway base URL; plain http only for loopback |
| `SSO_PROVIDER` | `auth0` | provider id registered in the gateway |
| `SSO_EXPECTED_IDP_HOST` | empty | pin the IdP host (the host or a subdomain of it) |
| `SSO_HTTP_TIMEOUT_SECONDS` | `10` | request timeout, 1 to 300 |
| `SSO_LOG_LEVEL` | `warn` | `debug`, `info` or `warn` |

The `Makefile` loads `.env` when it exists. Values are read from the process environment, so you can also export them.

## Run

```bash
make check                          # gateway reachable and provider registered
make login                          # prints the URL to open in a browser
make login-mock                     # full sign-in without a browser, mock provider only
```

Against the repository's gateway with only the mock provider registered:

```text
$ make login-mock
signed in via mock as Mock User (user@example.test)
$ make login
the gateway has no such provider. Its adapter may not be implemented yet: see Docs/Architecture.md
```

Exit codes: `0` success, `1` failure (gateway error, refused redirect, provider missing), `2` bad usage or configuration.

## Test

```bash
make test
```

This runs:

```bash
python3 -m unittest discover -s tests
```

The tests start an in-process fake of the gateway contract, so they need no network and no credentials. They cover configuration validation, every redirect-policy rule, the mock flow, structured gateway errors, non-JSON error bodies and an unreachable gateway. The live check against a real `ssod` is the `make login-mock` run above.

## Build and deploy

```bash
make build
```

This runs:

```bash
(nothing to build)
```

This is a command-line client. To deploy it, ship the built artifact and set the variables above. Use `https` for `SSO_GATEWAY_URL` outside loopback: the configuration loader rejects plain http for other hosts.

## Security notes

- **Secrets:** none are read or stored here. Do not put OAuth client secrets in this client's `.env`.
- **Redirect policy:** an external identity provider must use https. With `SSO_EXPECTED_IDP_HOST` set, look-alike hosts such as `notexample.com` are refused.
- **PKCE:** a redirect without `code_challenge_method=S256` is refused.
- **Bounded input:** response bodies are capped at 1 MiB, redirects are never followed automatically, and `--follow` stops at the first redirect that leaves the gateway host.
- **Logging:** state values and URLs with query strings are not logged.

### Library use

```python
from sso_client import Client, Config
import os

client = Client(Config.from_lookup(os.environ.get, "auth0"))
login = client.start_login()   # validated redirect
print(login.authorize_url)     # hand this to the user's browser
```

## Layout

```text
sso_client/cli.py      CLI: check, login [--follow]
sso_client/config.py   environment configuration and validation
sso_client/client.py   HTTP client (urllib, redirects disabled)
sso_client/policy.py   redirect safety policy
sso_client/errors.py   exception types
tests/                 unittest suite with an in-process fake gateway (conftest.py)
```

## License

MIT, same as the repository. See the [root README](../../README.md#license).
