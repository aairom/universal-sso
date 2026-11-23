#!/usr/bin/env bash
# Tests for scripts/sso-common.sh, scripts/provider-check.sh and scripts/run-example.sh.
# Needs only bash, openssl, go and python3. No network, no real credentials: env files are generated here.
# Usage: bash tests/scripts_test.sh   Exit 0 all passed, 1 a check failed.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT="$PWD"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0
ok() { echo "PASS $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL $1"; FAIL=$((FAIL + 1)); }
expect() { # description, expected-rc, command...   (output kept in $OUT)
  local d="$1" want="$2"; shift 2
  OUT="$("$@" 2>&1)"; local rc=$?
  if [ "$rc" -eq "$want" ]; then ok "$d"; else bad "$d (rc $rc, want $want): $(echo "$OUT" | head -3)"; fi
}
contains() { # description, needle   (searches $OUT)
  if grep -qF -- "$2" <<<"$OUT"; then ok "$1"; else bad "$1: missing '$2'"; fi
}
lacks() { if grep -qF -- "$2" <<<"$OUT"; then bad "$1: found '$2'"; else ok "$1"; fi; }

# shellcheck source=scripts/sso-common.sh
. scripts/sso-common.sh

# ---- sso-common.sh
cat >"$TMP/c.env" <<'EOF'
# comment
A=plain
B="double quoted"
C='single quoted'
D=with comment # trailing
export E=exported
A=last-wins
EOF
[ "$(envget "$TMP/c.env" A)" = last-wins ] && ok "envget: last assignment wins" || bad "envget last"
[ "$(envget "$TMP/c.env" B)" = "double quoted" ] && ok "envget: strips double quotes" || bad "envget dq"
[ "$(envget "$TMP/c.env" C)" = "single quoted" ] && ok "envget: strips single quotes" || bad "envget sq"
[ "$(envget "$TMP/c.env" D)" = "with comment" ] && ok "envget: strips inline comment" || bad "envget comment"
[ "$(envget "$TMP/c.env" E)" = exported ] && ok "envget: handles export" || bad "envget export"
[ -z "$(envget "$TMP/c.env" MISSING)" ] && ok "envget: absent key is empty" || bad "envget missing"
[ -z "$(envget "$TMP/none.env" A)" ] && ok "envget: absent file is empty" || bad "envget nofile"
is_placeholder "" && is_placeholder "okta-client-id-placeholder" && is_placeholder "0oa123456789okta" && ok "is_placeholder: empty, -placeholder, legacy id" || bad "is_placeholder true"
is_placeholder "real-id" && bad "is_placeholder: real id treated as placeholder" || ok "is_placeholder: real id is not a placeholder"

# ---- provider-check.sh (env files are throw-away)
SECRET="$(openssl rand -base64 48)"
good() { # provider, extra lines...
  local p="$1"; shift
  printf 'SSO_STATE_SECRET=%s\nSSO_SERVER_PORT=8080\nSSO_SERVER_BASE_URL=http://localhost:8080\n' "$SECRET" >"$TMP/$p.env"
  printf '%s\n' "$@" >>"$TMP/$p.env"
}
good okta SSO_PROVIDERS_OKTA_CLIENT_ID=0oaTEST1 SSO_PROVIDERS_OKTA_CLIENT_SECRET=testvalue1 SSO_PROVIDERS_OKTA_ISSUER_URL=https://corp.okta.test/oauth2/default
good auth0 SSO_PROVIDERS_AUTH0_CLIENT_ID=abc123 SSO_PROVIDERS_AUTH0_CLIENT_SECRET=testvalue1 SSO_PROVIDERS_AUTH0_ISSUER_URL=https://corp.eu.auth0.test/
good azure SSO_PROVIDERS_AZURE_CLIENT_ID=abc123 SSO_PROVIDERS_AZURE_CLIENT_SECRET=testvalue1 SSO_PROVIDERS_AZURE_TENANT_ID=11111111-1111-1111-1111-111111111111
good oauth2 SSO_PROVIDERS_OAUTH2_CLIENT_ID=abc123 SSO_PROVIDERS_OAUTH2_CLIENT_SECRET=testvalue1 \
  SSO_PROVIDERS_OAUTH2_AUTH_URL=https://idp.corp.test/authorize SSO_PROVIDERS_OAUTH2_TOKEN_URL=https://idp.corp.test/token \
  SSO_PROVIDERS_OAUTH2_USERINFO_URL=https://idp.corp.test/user "SSO_PROVIDERS_OAUTH2_SCOPES=read:user user:email"

for p in okta auth0 azure oauth2; do
  expect "provider-check $p: valid settings pass" 0 scripts/provider-check.sh $p --env "$TMP/$p.env"
  contains "provider-check $p: shows the redirect URI to register" "/auth/$p/callback"
  lacks "provider-check $p: never prints the secret value" "testvalue1"
  lacks "provider-check $p: never prints the state secret" "$SECRET"
  expect "provider-check $p: a second run gives the same result (idempotent)" 0 scripts/provider-check.sh $p --env "$TMP/$p.env"
done

sed 's/^SSO_PROVIDERS_OKTA_CLIENT_ID=.*/SSO_PROVIDERS_OKTA_CLIENT_ID=okta-client-id-placeholder/' "$TMP/okta.env" >"$TMP/okta-ph.env"
expect "provider-check: sample client id fails" 1 scripts/provider-check.sh okta --env "$TMP/okta-ph.env"
contains "provider-check: explains the provider stays off" "switched off"
sed 's#^SSO_PROVIDERS_OKTA_ISSUER_URL=.*#SSO_PROVIDERS_OKTA_ISSUER_URL=http://corp.okta.test/x#' "$TMP/okta.env" >"$TMP/okta-http.env"
expect "provider-check: http issuer on a non-loopback host fails" 1 scripts/provider-check.sh okta --env "$TMP/okta-http.env"
sed 's/^SSO_STATE_SECRET=.*/SSO_STATE_SECRET=change-this-in-production-xxxxxxxxxxxxxxxx/' "$TMP/auth0.env" >"$TMP/auth0-ex.env"
expect "provider-check: public example state secret fails" 1 scripts/provider-check.sh auth0 --env "$TMP/auth0-ex.env"
sed 's/^SSO_SERVER_PORT=.*/SSO_SERVER_PORT=5000/' "$TMP/auth0.env" >"$TMP/auth0-5000.env"
if [ "$(uname -s)" = Darwin ]; then expect "provider-check: port 5000 fails on macOS" 1 scripts/provider-check.sh auth0 --env "$TMP/auth0-5000.env"; fi
cp "$TMP/azure.env" "$TMP/azure-multi.env"
sed -i.bak 's/^SSO_PROVIDERS_AZURE_TENANT_ID=.*/SSO_PROVIDERS_AZURE_TENANT_ID=common/' "$TMP/azure-multi.env"
expect "provider-check: multi-tenant without an allow-list passes with a warning" 0 scripts/provider-check.sh azure --env "$TMP/azure-multi.env"
contains "provider-check: warns about the open allow-list" "[WARN]"
echo "SSO_PROVIDERS_AZURE_ALLOWED_TENANTS=not-a-guid" >>"$TMP/azure-multi.env"
expect "provider-check: non-GUID allowed tenant fails" 1 scripts/provider-check.sh azure --env "$TMP/azure-multi.env"
sed -i.bak 's/^SSO_PROVIDERS_AZURE_TENANT_ID=.*/SSO_PROVIDERS_AZURE_TENANT_ID=bad tenant!/' "$TMP/azure.env"
expect "provider-check: malformed tenant fails" 1 scripts/provider-check.sh azure --env "$TMP/azure.env"
sed 's#^SSO_PROVIDERS_OAUTH2_TOKEN_URL=.*#SSO_PROVIDERS_OAUTH2_TOKEN_URL=http://idp.corp.test/token#' "$TMP/oauth2.env" >"$TMP/oauth2-http.env"
expect "provider-check oauth2: http token URL on a non-loopback host fails" 1 scripts/provider-check.sh oauth2 --env "$TMP/oauth2-http.env"
grep -v '^SSO_PROVIDERS_OAUTH2_USERINFO_URL=' "$TMP/oauth2.env" >"$TMP/oauth2-nouser.env"
expect "provider-check oauth2: missing profile URL fails" 1 scripts/provider-check.sh oauth2 --env "$TMP/oauth2-nouser.env"
contains "provider-check oauth2: names the missing variable" "SSO_PROVIDERS_OAUTH2_USERINFO_URL is not set"
cp "$TMP/oauth2.env" "$TMP/oauth2-style.env"; echo "SSO_PROVIDERS_OAUTH2_AUTH_STYLE=header" >>"$TMP/oauth2-style.env"
expect "provider-check oauth2: unknown auth style fails" 1 scripts/provider-check.sh oauth2 --env "$TMP/oauth2-style.env"
cp "$TMP/oauth2.env" "$TMP/oauth2-post.env"; echo "SSO_PROVIDERS_OAUTH2_AUTH_STYLE=post" >>"$TMP/oauth2-post.env"
expect "provider-check oauth2: auth style post passes" 0 scripts/provider-check.sh oauth2 --env "$TMP/oauth2-post.env"
expect "provider-check: missing env file fails with a hint" 1 scripts/provider-check.sh okta --env "$TMP/none.env"
contains "provider-check: hint names .env.example" "cp .env.example .env"
expect "provider-check: unknown provider is a usage error" 2 scripts/provider-check.sh nope
expect "provider-check: no arguments is a usage error" 2 scripts/provider-check.sh
expect "provider-check: unknown option is a usage error" 2 scripts/provider-check.sh okta --bogus

# ---- run-example.sh: usage and refusal paths (nothing is built)
expect "run-example --list" 0 scripts/run-example.sh --list
for e in rust go python java csharp; do contains "run-example --list names $e" "$e "; done
expect "run-example: unknown example" 2 scripts/run-example.sh php
expect "run-example: unknown mode" 2 scripts/run-example.sh python --mode bogus
expect "run-example: port 5000 refused" 2 scripts/run-example.sh python --port 5000
expect "run-example: low port refused" 2 scripts/run-example.sh python --port 80
expect "run-example: option without value" 2 scripts/run-example.sh python --mode
expect "run-example: mock mode refuses a vendor provider" 2 scripts/run-example.sh python --mode mock --provider okta
expect "run-example: saml has no adapter" 2 scripts/run-example.sh go --mode e2e
contains "run-example: explains saml is planned" "no 'saml' adapter yet"
expect "run-example: oauth2 is accepted (rust default, toolchain check only)" 0 scripts/run-example.sh rust --mode e2e --check-only
expect "run-example: google is real-only" 2 scripts/run-example.sh python --mode e2e --provider google
expect "run-example --check-only builds nothing" 0 scripts/run-example.sh python --mode mock --check-only
OUT="$(cd "$TMP" && ROOT_OVERRIDE=1 bash "$ROOT/scripts/run-example.sh" --help 2>&1)"; contains "run-example --help documents the modes" "Modes"

# ---- run-example.sh: full flows (python is the fastest client; the rest are covered by tests/e2e.sh)
PORT=$((20000 + RANDOM % 5000))
expect "run-example python mock: full sign-in" 0 scripts/run-example.sh python --mode mock --port "$PORT"
contains "run-example python mock: signed in" "signed in via mock"
expect "run-example python mock: second run is idempotent" 0 scripts/run-example.sh python --mode mock --port "$PORT"
if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then bad "run-example: gateway left running after the run"; else ok "run-example: throw-away gateway is stopped on exit"; fi
expect "run-example python e2e okta: fake IdP sign-in" 0 scripts/run-example.sh python --mode e2e --provider okta --port "$PORT"
contains "run-example e2e: labels the IdP as fake" "FAKE identity provider"
contains "run-example e2e: signed in via okta" "signed in via okta"
expect "run-example python e2e oauth2: fake IdP sign-in" 0 scripts/run-example.sh python --mode e2e --provider oauth2 --port "$PORT"
contains "run-example e2e oauth2: signed in via oauth2" "signed in via oauth2"

echo "== scripts: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
