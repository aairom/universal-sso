# Pluggable SSO Framework: User Stories (v2)

Source: the article "Pluggable SSO Architecture: Building a Universal Authentication Framework".
Baseline reviewed: [`Docs/Architecture.md`](../../Docs/Architecture.md), `pkg/sso/{types,manager,cache,registry}.go`, `cmd/ssod/{main,handler}.go`.

Decisions applied in this version:

| # | Question | Decision | Effect on the stories |
|---|---|---|---|
| 1 | Are the article's code samples normative? | No, they are illustrative. Enhancement suggestions for a technical blog post are welcome. | LDAP and the JavaScript sketches are not committed scope. LDAP stories are `COULD`. Section 7 lists blog enhancements. |
| 2 | Unknown implementation method | Describe both approaches and document what the codebase does today. | Stories with open design choices carry an "Approach A / Approach B / Current state" block. |
| 3 | Database | Any standard SQL database is acceptable. | Storage stories add a `database/sql` backend next to Redis. |

---

## 1. Terminology map (article to codebase)

| Article term | Codebase equivalent | Note |
|---|---|---|
| Application Layer (Express routes) | `cmd/ssod/handler.go` (`net/http` mux) | Go gateway, not Express |
| SSO Core Orchestrator | `sso.Manager` (`BeginLogin`, `CompleteLogin`) | Provider resolution and flow management |
| Provider Interface Layer / `SSOProvider` contract | `sso.Provider` interface (`types.go`) | 9 methods, redirect-oriented |
| `ProviderRegistry` (service locator + factory) | `Manager.Register/Get/Providers` and `sso.NewProvider(driver, cfg)` | Providers are built eagerly at start-up by `ssod` (`build()`) |
| `getAuthenticationRequest` / `handleCallback` | `GetAuthURL` / `HandleCallback` | |
| `normalizeUserProfile` (on the contract) | Private to each adapter. The result is `IdentityResult{User *UserInfo}` | Normalized profile is delivered, but not as a contract method |
| `validateCredentials` | No equivalent | Only matters for credential protocols such as LDAP |
| `logout` | `GetLogoutURL` (RP-initiated or SLO URL) | No gateway route calls it yet |
| OAuth / SAML / LDAP adapters | `pkg/sso/oauth2`, `pkg/sso/saml`, none for LDAP. Also `oidc`, `okta`, `auth0`, `entra`, `google`, `mock` | |
| Session backends (Redis, database, memory) | `sso.Cache` interface. Only `MemoryCache` exists | `ssod` hard-wires `NewMemoryCache` (`main.go:106`) |

## 2. Current state (verified against the source)

| Capability named in the article | State | Evidence |
|---|---|---|
| Interface-driven providers | DELIVERED | `types.go` `Provider` |
| Registry and factory | DELIVERED | `registry.go` `NewProvider`, `Manager.Register` (duplicate ID returns `ErrInvalidConfig`) |
| OAuth 2.0 adapter | DELIVERED, stricter than the article (PKCE S256, 1 MiB cap, single-use code) | Architecture.md |
| SAML adapter | DELIVERED, with real XML-signature verification and assertion replay cache | Architecture.md |
| OIDC vendors | DELIVERED (beyond the article) | `pkg/sso/{oidc,okta,auth0,entra,google}` |
| Mock provider for tests | DELIVERED | `pkg/sso/mock` |
| State and CSRF: signed state, expiry, one-time use, provider binding | DELIVERED, but the one-time use is not atomic | `manager.go:120-139` does `Get` then `Delete` |
| Normalized profile | DELIVERED | `UserInfo` |
| LDAP adapter and `validateCredentials` | NOT PRESENT (illustrative in the article) | no LDAP code in `pkg/` or `cmd/` |
| Session after login | NOT PRESENT: the callback returns JSON `{provider_id, user}` and sets no cookie | `handler.go:69` |
| Logout, refresh, revoke over HTTP | NOT PRESENT: interface methods exist, no routes | `handler.go` routes: `/`, `/healthz`, `/providers`, `/auth/{p}/login`, `/auth/{p}/callback` (GET, POST) |
| Pluggable cache backends | PARTIAL: interface only, memory implementation only | `cache.go` |
| Embedded middleware, sidecar, multi-tenant routing | NOT PRESENT in code, though Architecture.md section 6 describes them | no matches in `cmd/` or `pkg/` |
| YAML or JSON config layers | NOT PRESENT: configuration is environment variables only | `cmd/ssod/*.go` |
| Fallback providers, audit decorator | NOT PRESENT: logging is `log.Printf` only | `cmd/ssod/main.go` |
| MFA, conditional access, identity linking | NOT PRESENT (future directions in the article) | `Claims` has no `amr` or `acr` |

Documentation inconsistency found: Architecture.md section 2 says only RS256 is accepted, but section 5 lists "RS256, ES256, EdDSA". See US-3.6.

## 3. Story index

Legend. Type: F functional, NF non-functional, T technical, E epic decomposition, S spike. Priority: MoSCoW. Size: S (up to 2 days), M (up to 1 week), L (over 1 week). Status: PARTIAL (exists, incomplete), GAP (missing), COULD-ILLUSTRATIVE (article-only, not committed).

| ID | Title | Type | Pri | Size | Status | Depends on |
|---|---|---|---|---|---|---|
| E1 | Provider Interface Contract and Registry | E | | | | |
| US-1.1 | Provider conformance test suite | NF | Must | M | PARTIAL | |
| US-1.2 | Safe registration and lookup | T | Should | S | PARTIAL | |
| US-1.3 | "Write your own provider" guide | F | Should | S | GAP | US-1.1 |
| E2 | Credential-based providers (LDAP) | E | | | | |
| US-2.1 | Credential authentication capability | F | Could | M | GAP | US-1.1 |
| US-2.2 | LDAP adapter | F | Could | L | COULD-ILLUSTRATIVE | US-2.1 |
| US-2.3 | LDAP security hardening | NF | Could | M | COULD-ILLUSTRATIVE | US-2.2 |
| E3 | Gateway and application integration | E | | | | |
| US-3.1 | Atomic one-time state consumption | NF | Must | S | PARTIAL | |
| US-3.2 | Session establishment after login | F | Must | M | GAP | US-3.1 |
| US-3.3 | Logout, refresh and revoke endpoints | F | Should | M | GAP | US-3.2 |
| US-3.4 | Embedded HTTP middleware | F | Should | M | GAP | US-3.2 |
| US-3.5 | Auth sidecar mode | F | Could | M | GAP | US-3.4 |
| US-3.6 | Reconcile documentation with the code | T | Must | S | PARTIAL | |
| E4 | Pluggable state and session storage | E | | | | |
| US-4.1 | Select the cache backend by configuration | T | Must | S | GAP | |
| US-4.2 | SQL cache backend | T | Should | M | GAP | US-4.1, US-4.5 |
| US-4.3 | Redis cache backend | T | Should | M | GAP | US-4.1, US-4.5 |
| US-4.4 | Move SAML replay and request-ID state into the cache | NF | Must | M | GAP | US-4.1 |
| US-4.5 | Cache contract test suite | NF | Must | S | GAP | |
| E5 | Resilience and observability | E | | | | |
| US-5.1 | Fallback provider on outage | F | Could | L | GAP | US-4.4 |
| US-5.2 | Audit logging decorator | NF | Should | M | GAP | |
| E6 | Future directions (spikes) | E | | | | |
| US-6.1 | Authentication assurance (MFA signal) | S | Could | S | GAP | |
| US-6.2 | Conditional access policy | S | Could | S | GAP | US-6.1 |
| US-6.3 | Identity linking across providers (SQL) | S | Could | S | GAP | US-4.2 |
| US-6.4 | Multi-tenant provider routing | S | Could | S | GAP | |

Suggested order: (1) US-3.1, US-4.5, US-1.1, US-3.6; (2) US-4.1, US-4.4, US-3.2; (3) US-4.2, US-4.3, US-5.2, US-3.3, US-3.4, US-1.2, US-1.3; (4) LDAP stories if confirmed; (5) fallback and spikes.

---

## 4. Epic 1: Provider Interface Contract and Registry

### US-1.1 Provider conformance test suite
Type: Non-functional. Status: PARTIAL (per-adapter tests exist, no shared suite).

As a **platform developer**,
I need one reusable conformance suite that every `Provider` implementation must pass,
So that the "providers conform to a standardized interface" promise is enforced by tests rather than by convention.

Acceptance Criteria:
1. A helper such as `ssotest.RunProviderSuite(t, factory)` exercises `ID`, `Name`, `Protocol`, `GetAuthURL`, `HandleCallback`, `GetLogoutURL`, and the "unsupported" methods.
2. Every shipped provider (`mock`, `oidc` wrappers, `oauth2`, `saml`, `google`) runs the suite in its own package tests.
3. The suite asserts: `ID()` is non-empty and stable; `GetAuthURL` echoes the supplied `State`; the returned URL carries a `code_challenge` with `S256` for OIDC and OAuth 2.0; unsupported methods return `UNSUPPORTED_METHOD` and never `nil, nil`.
4. The suite asserts that `IdentityResult.User.ID` is non-empty and namespaced so two providers cannot produce the same ID for different people. (SAML already uses `<entityID>|<NameID>`. Verify the others.)
5. `EmailVerified` is `false` unless the adapter can prove it. The suite checks this for OAuth 2.0 and SAML.
6. Run with `go test -race`.

Edge cases: provider returning a nil `User` or nil `Tokens`; provider that panics (the suite fails the test, it does not crash the run).

### US-1.2 Safe registration and lookup
Type: Technical. Status: PARTIAL (duplicate ID is rejected, other inputs are not).

As a **platform developer**,
I need `Manager.Register` to reject invalid providers and `Manager.Get` to fail with a typed error,
So that a misconfigured provider fails at start-up instead of at the first login.

Acceptance Criteria:
1. `Register(nil)` and a provider with an empty `ID()` return `ErrInvalidConfig` and do not panic (today `p.ID()` on a nil provider panics).
2. IDs are matched exactly. IDs that differ only by case are rejected as duplicates, or the behavior is documented and tested.
3. `Get` of an unknown ID returns `ErrNotFound` (already true, keep a test).
4. Concurrent `Register`, `Get` and `Providers` calls pass under `-race`.
5. Optional: `Manager.SetDefault(id)` for implicit selection, as in the article's `setDefaultProvider`. Unknown IDs are rejected. Use only for the credential and landing flows, never for callbacks (see US-3.1).

### US-1.3 "Write your own provider" guide
Type: Functional (documentation). Status: GAP.

As an **integration engineer**,
I need a short guide with a compiling example of a custom provider,
So that I can add an identity source without editing `pkg/sso/*.go`.

Acceptance Criteria:
1. `Docs/` contains the guide, linked from README and Architecture.md.
2. The example lives in a `_test.go` file or `examples/` and compiles in CI, so it cannot rot.
3. The guide lists the steps: implement `Provider`, return `UNSUPPORTED_METHOD` where a protocol has no equivalent, add a factory entry in `registry.go`, add env-var configuration in `cmd/ssod`, run the US-1.1 suite.
4. The guide states which security checks every adapter owns: state and nonce binding, token or assertion signature verification, issuer and audience, response size cap.

---

## 5. Epic 2: Credential-based providers (LDAP)

Scope note: per decision 1, the article's LDAP code is illustrative. These stories are a backlog candidate, to be confirmed. They are also the source material for the blog enhancements in section 7.

### US-2.1 Credential authentication capability
Type: Functional. Status: GAP.

As an **integrator of a directory-style identity source**,
I need the framework to model "username and password" providers as well as redirect providers,
So that LDAP-like sources fit the same orchestrator.

Design choice, both approaches documented:
- **Approach A, optional companion interface.** Add `type CredentialAuthenticator interface { Authenticate(ctx, username, password string) (*IdentityResult, error) }`. Redirect providers are untouched. `Manager.BeginCredentialLogin(ctx, providerID, creds)` type-asserts for it. Pro: no breaking change to `Provider`. Con: a provider can be registered that satisfies neither flow, so the registry must validate at `Register`.
- **Approach B, extend `Provider`.** Add `AuthMethod() AuthMethod` (`redirect` or `credentials`) and an `Authenticate` method that redirect providers answer with `UNSUPPORTED_METHOD`, which is the pattern the SAML adapter already uses for refresh and revoke. Pro: one contract, matches the article's `validateCredentials`. Con: breaking change for third-party providers.
- **Current state:** neither exists. `Provider` has only redirect-oriented methods.

Acceptance Criteria:
1. One approach is chosen and recorded in a short decision note in `Docs/`.
2. A mock credential provider proves the flow end to end with no LDAP dependency.
3. The login is bound to a signed, expiring state/CSRF token, as redirect logins are.
4. Failures are uniform: wrong user and wrong password produce the same error and comparable timing.
5. Rate limiting is available per username and per IP (default: 5 failures in 5 minutes returns `429`).
6. The callback never reads the provider from a request parameter (see US-3.1).

### US-2.2 LDAP adapter
Type: Functional. Status: COULD-ILLUSTRATIVE.

As an **enterprise administrator with a legacy directory**,
I need to authenticate against LDAP or Active Directory through the same gateway,
So that on-premises users get single sign-on alongside cloud providers.

Acceptance Criteria:
1. New package `pkg/sso/ldap` with driver name `ldap`, configured via `SSO_PROVIDERS_LDAP_*` variables documented in `.env.example`. No secrets in code.
2. Search-then-bind: bind with the service account, search for exactly one entry, then bind as the found DN. Zero or more than one match fails the login.
3. The result carries ID (namespaced), email, display name, and groups from `memberOf`. `EmailVerified` is `false`.
4. `RefreshToken`, `RevokeToken`, `ValidateToken`, `FetchUserInfo` return `UNSUPPORTED_METHOD`.
5. Unit tests use an in-process fake LDAP server, in the style of `oidctest` and `samltest`. No network.
6. Decision to record: which LDAP client library to use. A new third-party dependency must be approved, as `goxmldsig` was.

### US-2.3 LDAP security hardening
Type: Non-functional. Status: COULD-ILLUSTRATIVE (mandatory if US-2.2 is built).

As a **security engineer**,
I need all LDAP input escaped and all LDAP traffic encrypted,
So that attackers cannot bypass authentication or read the directory.

Acceptance Criteria:
1. Usernames are escaped per RFC 4515 (filters) and RFC 4514 (DNs). Tests cover `*`, `(`, `)`, `\`, NUL and `)(uid=*))(|(uid=*`.
2. An empty password is rejected before any bind, because an LDAP bind with an empty password is an anonymous bind and can "succeed".
3. `ldaps://` or StartTLS is required. Plain `ldap://` is refused unless an explicit, logged opt-out is set. Certificate verification is on, with an optional CA file and no "skip verify".
4. Connections come from a bounded pool with connect and read timeouts (default 5 s). A dropped connection is re-dialed with one retry.
5. Searches set size limit 1 and a time limit.
6. Passwords never appear in logs or errors.

---

## 6. Epics 3 to 6

### US-3.1 Atomic one-time state consumption
Type: Non-functional (security). Status: PARTIAL.

Current state: `CompleteLogin` verifies the signature, then does `cache.Get` followed by `cache.Delete` (`manager.go:120-129`). Provider binding is already checked (`pending.ProviderID != providerID`). Two concurrent callbacks with the same state can both pass the `Get` before either `Delete`, and with a shared store (Epic 4) this window is wider.

As a **security engineer**,
I need the pending-login record to be consumed atomically,
So that a state value can complete at most one login, even under concurrency or across replicas.

Design choice:
- **Approach A:** add `Take(ctx, key) ([]byte, bool, error)` to `Cache`. Breaking for custom caches.
- **Approach B:** add an optional `AtomicTaker` interface. `Manager` uses it when present, else falls back to `Get`+`Delete` and logs a warning at start-up. Non-breaking.

Acceptance Criteria:
1. Approach chosen and recorded.
2. A test fires 50 concurrent callbacks with one valid state: exactly one succeeds, 49 are rejected with a state error. Runs under `-race`.
3. `MemoryCache` implements the atomic operation under a single lock.
4. Existing behavior is kept: wrong provider, tampered, expired and replayed state are all rejected (add any missing test).
5. The HMAC check in `state.go` uses constant-time comparison (verify).

### US-3.2 Session establishment after login
Type: Functional. Status: GAP (the callback returns JSON and sets no session).

As an **application developer**,
I need the gateway to establish an authenticated session after a successful login,
So that my application does not have to build its own session handling around the JSON response.

Design choice:
- **Approach A, server-side session.** An opaque random ID in a `Secure`, `HttpOnly`, `SameSite=Lax` cookie, with the session stored in the `Cache` or SQL backend (Epic 4). Pro: revocable, small cookie. Con: needs shared storage for several replicas.
- **Approach B, stateless signed cookie or JWT.** Signed with key material like `SSO_STATE_SECRET` and a short TTL. Pro: no storage. Con: not revocable before expiry, size limits.
- **Current state:** neither. `IdentityResult.SessionID` exists as a field but nothing populates it from the gateway.

Acceptance Criteria:
1. One approach is chosen, or a config switch allows both.
2. Cookie flags are as above. `Secure` is on unless the base URL is `http://localhost`.
3. Session lifetime and idle timeout are configurable. Tokens are not placed in the cookie.
4. The session ID is rotated on login (session-fixation defense).
5. A `GET /session` endpoint returns the normalized `UserInfo` for a valid session and `401` otherwise.
6. After the callback, the user is redirected to a configured post-login URL, validated against an allow-list (open-redirect defense).

### US-3.3 Logout, refresh and revoke endpoints
Type: Functional. Status: GAP (interface methods exist, no routes).

As a **signed-in user**,
I need to sign out of the application and, where the provider supports it, of the identity provider,
So that my session cannot be reused.

Acceptance Criteria:
1. `POST /logout` destroys the session, then redirects to the URL from `GetLogoutURL` when the provider supports it. Providers answering `UNSUPPORTED_METHOD` (OAuth 2.0 and SAML today) only end the local session.
2. Logout is `POST` with CSRF protection, so a cross-site image tag cannot log a user out.
3. Optional `POST /token/refresh` and `/token/revoke` call `RefreshToken` and `RevokeToken`. They require a session and never return tokens to the browser (matches the existing "tokens are deliberately not echoed" rule).
4. `post_logout_url` is validated against an allow-list.

### US-3.4 Embedded HTTP middleware
Type: Functional. Status: GAP (Architecture.md section 6 describes it, no code exists).

As an **application developer using Go**,
I need a `net/http` middleware that requires a session and exposes the user in the request context,
So that I can protect routes by wrapping a handler.

Acceptance Criteria:
1. `sso.RequireAuth(manager, opts)` returns `func(http.Handler) http.Handler`. Unauthenticated browser requests redirect to login. Requests with `Accept: application/json` get `401`.
2. `sso.UserFromContext(ctx)` returns `*UserInfo`.
3. The login redirect preserves the requested path through the signed state, with an allow-list check.
4. An example in `examples/` uses it and is covered by a test. Adapters for Gin, Echo, Fiber and Chi are out of scope, since each is a thin wrapper to add later.

### US-3.5 Auth sidecar mode
Type: Functional. Status: GAP.

As an **operator of non-Go services**,
I need to put the gateway in front of an upstream and receive `X-User-ID`, `X-User-Email` and `X-User-Roles` headers,
So that languages without a client library can still use the framework.

Design choice:
- **Approach A, reverse proxy.** `ssod` proxies to the upstream and injects headers.
- **Approach B, forward-auth.** `ssod` exposes `GET /auth/verify` returning `200` with headers or `401`, for nginx `auth_request`, Envoy `ext_authz` or Traefik forward-auth. Smaller attack surface, no proxying of bodies.
- **Current state:** neither exists.

Acceptance Criteria:
1. One approach chosen and documented.
2. Inbound `X-User-*` headers from the client are always stripped, so they cannot be spoofed.
3. Header values are sanitized (no CR or LF).
4. A container recipe follows the `container-images` rules (multi-stage, non-root).

### US-3.6 Reconcile documentation with the code
Type: Technical (documentation). Status: PARTIAL.

As a **reader of Architecture.md**,
I need the document to separate implemented features from planned ones,
So that I am not misled by features that do not exist.

Acceptance Criteria:
1. Section 5 ("RS256, ES256, EdDSA") and section 2 ("only RS256 is accepted") agree. Fix whichever is wrong after checking `pkg/sso/oidc`.
2. Section 4 (YAML/JSON config layers, "Dynamic Provider Discovery") and section 6 (middleware, sidecar, multi-tenant gateway) are labeled "Planned" or "Implemented" per item, with links to the stories above.
3. Section 5 lists in-flight request tracking as implemented only for SAML (already stated). Add the US-3.1 caveat until it is fixed.
4. README and Architecture.md Mermaid diagrams are updated where they change.

### US-4.1 Select the cache backend by configuration
Type: Technical. Status: GAP (`main.go:106` always uses `NewMemoryCache`).

As an **operator**,
I need to choose the state/session store through configuration,
So that I can run several gateway replicas.

Acceptance Criteria:
1. `SSO_CACHE_DRIVER` accepts `memory` (default), `redis`, `sql`. Unknown values fail at start-up with a clear message.
2. Backend DSN or URL comes from `.env` and is listed in `.env.example`. Passwords are never logged.
3. A start-up warning is printed when `memory` is used with a non-local `SSO_SERVER_BASE_URL`.
4. The cache is wired into the `Manager` and, via US-4.4, into the SAML provider.

### US-4.2 SQL cache backend
Type: Technical. Status: GAP. Per decision 3, any standard SQL database is acceptable.

As an **operator with an existing SQL database**,
I need a `Cache` implementation on `database/sql`,
So that I can store state and sessions without adding Redis.

Acceptance Criteria:
1. Table `sso_cache(key TEXT PRIMARY KEY, val BLOB, expires_at TIMESTAMP)` with an index on `expires_at`. Migration SQL ships for PostgreSQL, MySQL/MariaDB and SQLite.
2. `Get` ignores expired rows. A background purge (`DELETE ... WHERE expires_at < now`) runs on an interval.
3. The atomic take from US-3.1 uses `DELETE ... RETURNING` (PostgreSQL, SQLite 3.35+) or a transaction with `SELECT ... FOR UPDATE` (MySQL), one code path per dialect, covered by the contract suite.
4. Only parameterized queries. The table name is a validated identifier.
5. The package lives in a separate Go module or a build-tagged package, so the core stays free of database drivers (the repo's only third-party dependency is `goxmldsig`).
6. If the database is down, logins fail closed with an availability error, never by skipping state checks.

### US-4.3 Redis cache backend
Type: Technical. Status: GAP.

As an **operator running replicas**,
I need a Redis-backed `Cache`,
So that a login started on one replica can finish on another with low latency.

Acceptance Criteria:
1. `Set` uses `SET key val PX ttl`. The atomic take uses `GETDEL` (Redis 6.2+) or a Lua script on older versions.
2. TLS and password are supported through `.env`.
3. Same contract suite as US-4.5. Same module-isolation rule as US-4.2.
4. Fails closed when Redis is unreachable.

### US-4.4 Move SAML replay and request-ID state into the cache
Type: Non-functional. Status: GAP. The SAML adapter keeps its `state` to `AuthnRequest` ID map and its assertion-ID replay cache in process memory (Architecture.md: map capped at 10000 entries, 15 minute TTL).

As a **security engineer**,
I need those two structures stored in the shared `Cache`,
So that a SAML response cannot be replayed against a different replica and unsolicited-response checks work across replicas.

Acceptance Criteria:
1. The SAML provider accepts a `Cache` through its config. The default stays in-process for single-node use.
2. Assertion-ID replay uses an atomic set-if-absent with a TTL equal to the assertion's validity plus skew.
3. A two-instance test sharing one cache proves that a replayed assertion is rejected by the second instance.
4. Existing SAML tests and the 9 documented mutation checks still pass.

### US-4.5 Cache contract test suite
Type: Non-functional. Status: GAP.

As a **platform developer**,
I need one test suite that every `Cache` implementation passes,
So that memory, SQL and Redis behave identically.

Acceptance Criteria:
1. Covers `Get`, `Set`, `Delete`, `Clear`, TTL expiry, zero TTL meaning "no expiry" (as `MemoryCache` does today), defensive copy of values, atomic take, and concurrent access.
2. `MemoryCache` passes. SQL and Redis tests run against in-memory SQLite and a containerized Redis, and skip with a clear message when unavailable.

### US-5.1 Fallback provider on outage
Type: Functional. Status: GAP (no fallback logic in the codebase).

As an **administrator**,
I need an ordered fallback for a provider (for example Okta, then a second IdP),
So that users can still sign in when the primary identity system is down.

Design choice:
- **Approach A, in the Manager.** `SSO_PROVIDERS_<ID>_FALLBACK=<id>`. The Manager retries `BeginLogin` against the fallback when the primary reports an availability error. Pro: one place, testable with the mock. Con: grows the Manager.
- **Approach B, user-visible choice.** The landing page shows a banner and a second login button when the primary's health check fails, so the user chooses. Pro: no silent identity switch. Con: needs a provider health probe.
- **Current state:** `/healthz` is process liveness only. There is no provider health.

Acceptance Criteria:
1. Cycles and unknown IDs are rejected at start-up.
2. Fallback triggers only on availability errors (timeout, connection refused, 5xx), never on `IdP_REJECTED` or policy denials.
3. A circuit breaker (open after 3 consecutive failures, half-open after 30 s) stops probing a down provider.
4. The user always sees which provider is used. The identity keeps the real provider's namespaced ID.
5. A fallback with weaker assurance than the primary is refused unless explicitly allowed (depends on US-6.1).

### US-5.2 Audit logging decorator
Type: Non-functional (compliance). Status: GAP.

As a **compliance officer**,
I need a structured audit record for each login, failure, refresh, revoke and logout,
So that I can answer who signed in, through which provider, and when.

Acceptance Criteria:
1. `AuditedProvider` wraps any `Provider` (the decorator pattern named in the article) without changing it.
2. Record fields: timestamp, provider ID, operation, outcome, error code, request ID, source IP, hashed user ID.
3. Never recorded: passwords, tokens, authorization codes, SAML assertions, state values. A canary-secret test proves it.
4. Output goes to a pluggable sink (JSON on stdout by default, via `log/slog`).
5. A sink failure never changes the login result. It increments a counter and is reported once per minute.

### US-6.1 Authentication assurance (MFA signal), spike
Type: Spike. Status: GAP (`Claims` and `UserInfo` carry no `amr`, `acr` or `AuthnContextClassRef`).

As a **security architect**,
I need a design for exposing how the user authenticated,
So that applications can require MFA without knowing the provider.

Acceptance Criteria:
1. One-page design in `Docs/`: map OIDC `amr`/`acr`, SAML `AuthnContextClassRef` and credential providers (none) into one field.
2. Missing data is "unknown", never "MFA satisfied".
3. Follow-up stories are written from the chosen design.

### US-6.2 Conditional access policy, spike
Type: Spike. Status: GAP.

As an **administrator**,
I need rules such as "admins require MFA" or "block these email domains",
So that sign-in adapts to risk without application changes.

Acceptance Criteria:
1. Design covers inputs (provider, group, domain, IP, assurance), outputs (allow, deny, step-up), the hook point in `CompleteLogin`, and where policy is stored (config file or SQL).
2. Default is deny when a policy cannot be evaluated.
3. Policies can be tested with the mock provider.

### US-6.3 Identity linking across providers, spike
Type: Spike. Status: GAP.

As a **user with accounts at several providers**,
I need those identities linked to one application account,
So that I keep my data when my company changes provider.

Acceptance Criteria:
1. Design for a SQL table keyed on `(provider_id, subject)` pointing to an application user ID.
2. Automatic linking by email is refused when `EmailVerified` is `false`, which is always the case for OAuth 2.0 and SAML today.
3. Linking requires a recent re-authentication on both identities.

### US-6.4 Multi-tenant provider routing, spike
Type: Spike. Status: GAP (Architecture.md section 6 mentions routing by domain, path, query or header; `UserInfo.TenantID` exists, routing does not).

As an **operator serving several organizations**,
I need requests routed to different providers by tenant,
So that each organization signs in with its own identity provider.

Acceptance Criteria:
1. Compare routing keys (host, path, `login_hint` domain) and the risk of each. Routing by a user-supplied query parameter must not weaken the provider binding in US-3.1.
2. Decide how per-tenant provider config is stored (env, file, SQL).
3. Output: stories, or a decision to defer.

---

## 7. Blog post enhancement suggestions (decision 1)

The article's samples are illustrative. These changes make them safe to copy and tie them to the stories above.

| Article sample | Problem | Suggested enhancement | Story |
|---|---|---|---|
| `SAMLProvider.verifySignature` | `return true; // Simplified` disables the check | Show a real verification call, or throw `NotImplemented` so the sample cannot be pasted into production. Add a "signature wrapping" paragraph | US-1.1 |
| `OAuth2Provider.getAuthenticationRequest` | No PKCE | Add `code_challenge` (S256) and store the verifier with the state | US-1.1 |
| `OAuth2Provider.handleCallback` | Nonce generated but never verified. State compared with `!==`. State not cleared | Verify the ID token nonce, compare with `crypto.timingSafeEqual`, delete state after first use | US-3.1 |
| `app.post('/auth/callback')` | Provider read from `req.query.provider` | Store the provider ID with the state, as `Manager.CompleteLogin` does | US-3.1 |
| `LDAPProvider` | DN and filter built by string interpolation (injection). One client created at start-up. Empty password may bind anonymously. No TLS | Escape input (RFC 4514 and 4515), search-then-bind, require `ldaps://`, reject empty passwords, pool connections | US-2.3 |
| `ProviderRegistry.getProvider` | Two concurrent first calls can create two instances | Cache the initialization promise, or build providers eagerly at start-up as `ssod` does | US-1.2 |
| `getAuthenticationRequest` | Returns three different shapes (`redirect`, `post`, `credentials`) | Use a discriminated union (`{type: 'redirect', url}` and so on) and show a TypeScript type | US-2.1 |
| `fetch` calls | No timeout, no size cap | Add `AbortSignal.timeout` and a response size limit (the Go code caps at 1 MiB) | US-1.1 |
| "Switch providers through configuration" | The sample registers providers in code | Show env-driven registration, matching `SSO_PROVIDERS_<ID>_*` | US-4.1 |
| Conclusion: "fallback providers", "decorator pattern", "pluggable session handlers" | Claimed but no code is shown | Add a short snippet for each, or label them "future work" | US-5.1, US-5.2, Epic 4 |
| Conclusion: "weeks to days" | Unsupported number | Remove it, or measure it (time to add a conformant provider using the US-1.3 guide) | US-1.3 |
| Contract: `normalizeUserProfile` on the interface | Mixes input parsing with the contract | Show it as a private adapter helper and have `handleCallback` return the normalized profile, as the Go `IdentityResult` does | US-1.1 |

## 8. Open questions

1. Confirm that LDAP (Epic 2) is optional. If it is dropped, US-2.1 can still be kept as a small contract change, or deferred.
2. Choose between the A and B approaches for US-2.1, US-3.1, US-3.2, US-3.5 and US-5.1. A decision note per story is the acceptance proof.
3. Is the repository allowed to add `database/sql` drivers and a Redis client as separate modules (US-4.2, US-4.3)?
4. Which SQL dialects must be supported first (PostgreSQL, MySQL/MariaDB, SQLite)?
