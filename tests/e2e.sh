#!/usr/bin/env bash
# End-to-end check: every example client signs in through the real ssod
# handler and the real Okta, Auth0, Entra, generic OAuth 2.0 and SAML 2.0
# adapters, against in-process FAKE identity providers (ssod built with
# -tags e2e).
#
# What this proves: the gateway adapters and the example clients work together
# over HTTP (login redirect, authorization code + PKCE, token exchange, ID token
# verification, nonce, profile; for SAML the AuthnRequest, the signed Response
# posted back, and its validation). The four OIDC/OAuth providers run with all
# five clients. SAML runs with the Go client only, because the other clients
# check state and PKCE parameters that a SAML redirect does not carry. What it
# does NOT prove: that a real tenant or IdP accepts your configuration. That
# needs your tenant and a browser (see Docs/*-SSO-Setup.md).
#
# Every provider x client pair must pass. A missing toolchain is a failure, not
# a skip, unless E2E_ALLOW_SKIP=1.
#
# Usage: bash tests/e2e.sh        (builds into .run/e2e, uses port E2E_PORT, default 18931)
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT="$PWD"
PORT="${E2E_PORT:-18931}"
BASE="http://127.0.0.1:$PORT"
OUT="$ROOT/.run/e2e"
PROVIDERS=(okta auth0 azure oauth2 mock)
RC=0; PASS=0; FAIL=0; SKIP=0
SSOD_PID=""
BUILD_FAILED=()
mkdir -p "$OUT"

DOTNET_LOCAL="${DOTNET_LOCAL:-$HOME/.local/share/dotnet-universal-sso}"
if ! command -v dotnet >/dev/null 2>&1 && [ -x "$DOTNET_LOCAL/dotnet" ]; then
  export DOTNET_ROOT="$DOTNET_LOCAL" PATH="$DOTNET_LOCAL:$PATH"
fi
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1

cleanup() { [ -n "$SSOD_PID" ] && kill "$SSOD_PID" 2>/dev/null; wait 2>/dev/null; }
trap cleanup EXIT

build() { # label, tool, dir, command...
  local label="$1" tool="$2" dir="$3"; shift 3
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "!! $tool is not installed"; BUILD_FAILED+=("$label"); return
  fi
  ( cd "$dir" && "$@" ) >"$OUT/build-$label.log" 2>&1 || {
    echo "!! build failed: $label (see $OUT/build-$label.log)"; BUILD_FAILED+=("$label"); }
}

echo "== building"
command -v go >/dev/null 2>&1 || { echo "!! go is not installed"; exit 1; }
go build -tags e2e -o "$OUT/ssod-e2e" ./cmd/ssod || exit 1
build go     go      "$ROOT/examples/saml2-go"        go build -o "$OUT/saml2-go" .
build rust   cargo   "$ROOT/examples/oauth2-rust"     cargo build --release --quiet
build java   mvn     "$ROOT/examples/okta-java"       mvn -q -B package -DskipTests
build csharp dotnet  "$ROOT/examples/azure-ad-csharp" dotnet build -c Release src --nologo -v q
build python python3 "$ROOT/examples/auth0-python"    python3 -c "import sso_client.cli"

# Throw-away configuration. Nothing here is a credential for a real service.
export SSO_STATE_SECRET
SSO_STATE_SECRET="$(openssl rand -base64 48)"
export SSO_SERVER_HOST=127.0.0.1 SSO_SERVER_PORT="$PORT" SSO_SERVER_BASE_URL="$BASE"
export SSO_PROVIDERS_OKTA_CLIENT_ID=e2e-okta SSO_PROVIDERS_OKTA_CLIENT_SECRET=e2e-value
export SSO_PROVIDERS_OKTA_ISSUER_URL="$BASE/idp/okta/oauth2/default"
export SSO_PROVIDERS_AUTH0_CLIENT_ID=e2e-auth0 SSO_PROVIDERS_AUTH0_CLIENT_SECRET=e2e-value
export SSO_PROVIDERS_AUTH0_ISSUER_URL="$BASE/idp/auth0"
export SSO_PROVIDERS_AZURE_CLIENT_ID=e2e-azure SSO_PROVIDERS_AZURE_CLIENT_SECRET=e2e-value
export SSO_PROVIDERS_AZURE_TENANT_ID=11111111-1111-1111-1111-111111111111
export SSO_PROVIDERS_AZURE_AUTHORITY="$BASE/idp/azure"
export SSO_PROVIDERS_OAUTH2_CLIENT_ID=e2e-oauth2 SSO_PROVIDERS_OAUTH2_CLIENT_SECRET=e2e-value
export SSO_PROVIDERS_OAUTH2_AUTH_URL="$BASE/idp/oauth2/authorize"
export SSO_PROVIDERS_OAUTH2_TOKEN_URL="$BASE/idp/oauth2/token"
export SSO_PROVIDERS_OAUTH2_USERINFO_URL="$BASE/idp/oauth2/user"
export SSO_PROVIDERS_OAUTH2_SCOPES="read:user user:email"
export SSO_PROVIDERS_SAML_SP_ENTITY_ID="$BASE/auth/saml/metadata"
export SSO_PROVIDERS_SAML_IDP_METADATA_URL="$BASE/idp/saml/metadata"

"$OUT/ssod-e2e" >"$OUT/ssod.log" 2>&1 &
SSOD_PID=$!
for _ in $(seq 1 50); do curl -fs "$BASE/healthz" >/dev/null 2>&1 && break; sleep 0.1; done
if ! curl -fs "$BASE/healthz" >/dev/null 2>&1; then
  echo "!! ssod did not start, log:"; cat "$OUT/ssod.log"; exit 1
fi
echo "== ssod up: $(curl -s "$BASE/providers")"

failed_build() { local l; for l in ${BUILD_FAILED[@]+"${BUILD_FAILED[@]}"}; do [ "$l" = "$1" ] && return 0; done; return 1; }

run_client() { # label, command...
  local label="$1"; shift
  local p out status
  for p in "${PROVIDERS[@]}"; do
    if failed_build "$label"; then
      if [ "${E2E_ALLOW_SKIP:-0}" = 1 ]; then echo "SKIP $label x $p"; SKIP=$((SKIP+1))
      else echo "FAIL $label x $p (toolchain or build unavailable)"; FAIL=$((FAIL+1)); RC=1; fi
      continue
    fi
    out="$(SSO_GATEWAY_URL="$BASE" SSO_PROVIDER="$p" "$@" 2>&1)"; status=$?
    # The signed-in line must name the provider we asked for.
    if [ "$status" -eq 0 ] && grep -qi "signed in via $p" <<<"$out"; then
      echo "PASS $label x $p: $out"; PASS=$((PASS+1))
    else
      echo "FAIL $label x $p (exit $status): $out"; FAIL=$((FAIL+1)); RC=1
    fi
  done
}

echo "== signing in"
run_client go     "$OUT/saml2-go" login -follow
run_client rust   "$ROOT/examples/oauth2-rust/target/release/oauth2-rust" login --follow
run_client python bash -c "cd '$ROOT/examples/auth0-python' && python3 -m sso_client.cli login --follow"
run_client java   bash -c "cd '$ROOT/examples/okta-java' && java -cp 'target/classes:target/lib/*' com.universalsso.client.Main login --follow"
run_client csharp dotnet "$ROOT/examples/azure-ad-csharp/src/bin/Release/net8.0/azure-ad-csharp.dll" login --follow

# SAML 2.0: Go client only (see the header).
PROVIDERS=(saml)
run_client go     "$OUT/saml2-go" login -follow

echo "== negative checks (the gateway must refuse these)"
neg() { # description, expected-status, url
  local got; got="$(curl -s -o /dev/null -w '%{http_code}' "$3")"
  if [ "$got" = "$2" ]; then echo "PASS $1 ($got)"; PASS=$((PASS+1)); else echo "FAIL $1: got $got, want $2"; FAIL=$((FAIL+1)); RC=1; fi
}
neg "callback with a forged state"  400 "$BASE/auth/okta/callback?code=x&state=forged"
neg "callback without state"        400 "$BASE/auth/okta/callback?code=x"
neg "unknown provider"              404 "$BASE/auth/nope/login"
# A code the IdP never issued must be rejected at the token endpoint, never become a session.
loc="$(curl -s -o /dev/null -w '%{redirect_url}' "$BASE/auth/azure/login")"
state="$(sed -n 's/.*[?&]state=\([^&]*\).*/\1/p' <<<"$loc")"
neg "callback with a code the IdP never issued" 401 "$BASE/auth/azure/callback?code=never-issued&state=$state"

# SAML posts the Response, so the same refusals are checked on POST.
negpost() { # description, expected-status, url, form body
  local got; got="$(curl -s -o /dev/null -w '%{http_code}' --data "$4" "$3")"
  if [ "$got" = "$2" ]; then echo "PASS $1 ($got)"; PASS=$((PASS+1)); else echo "FAIL $1: got $got, want $2"; FAIL=$((FAIL+1)); RC=1; fi
}
negpost "SAML POST with a forged RelayState" 400 "$BASE/auth/saml/callback" "SAMLResponse=AAAA&RelayState=forged"
negpost "SAML POST without any RelayState"   400 "$BASE/auth/saml/callback" "SAMLResponse=AAAA"

echo "== result: $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ] || RC=1
exit "$RC"
