#!/usr/bin/env bash
# Validate the gateway settings for one adapter before you try to sign in.
# This is the Okta / Auth0 / Entra / generic OAuth 2.0 counterpart of `make google-check`.
#
# Usage:   scripts/provider-check.sh <okta|auth0|azure|oauth2> [--env FILE] [--online]
#   --env FILE   env file to read (default: .env in the project root)
#   --online     also fetch the provider's OpenID discovery document (needs network).
#                oauth2 has no discovery document, so --online checks nothing for it.
#
# Prerequisites: bash, grep, sed. curl only for --online.
# Reads (never prints secret values): SSO_STATE_SECRET, SSO_SERVER_*, and for the chosen
# provider SSO_PROVIDERS_<OKTA|AUTH0|AZURE|OAUTH2>_{CLIENT_ID,CLIENT_SECRET,REDIRECT_URL,...}.
# See .env.example and Docs/<Okta|Auth0|Azure-AD|OAuth2>-SSO-Setup.md.
#
# Read-only and idempotent: it changes nothing. Exit: 0 ready, 1 at least one FAIL, 2 bad usage.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/sso-common.sh
. "$ROOT/scripts/sso-common.sh"

usage() { echo "usage: provider-check.sh <okta|auth0|azure|oauth2> [--env FILE] [--online]" >&2; exit 2; }

PROVIDER="${1:-}"; [ $# -gt 0 ] && shift
ENV_FILE="$ROOT/.env"; ONLINE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --env) [ $# -ge 2 ] || usage; ENV_FILE="$2"; shift 2 ;;
    --online) ONLINE=1; shift ;;
    -h | --help) usage ;;
    *) echo "unknown option: $1" >&2; usage ;;
  esac
done
case "$PROVIDER" in
  okta) PREFIX=SSO_PROVIDERS_OKTA; LABEL=Okta; GUIDE=Docs/Okta-SSO-Setup.md ;;
  auth0) PREFIX=SSO_PROVIDERS_AUTH0; LABEL=Auth0; GUIDE=Docs/Auth0-SSO-Setup.md ;;
  azure) PREFIX=SSO_PROVIDERS_AZURE; LABEL="Microsoft Entra ID"; GUIDE=Docs/Azure-AD-SSO-Setup.md ;;
  oauth2) PREFIX=SSO_PROVIDERS_OAUTH2; LABEL="generic OAuth 2.0"; GUIDE=Docs/OAuth2-SSO-Setup.md ;;
  *) usage ;;
esac

FAILS=0
ok() { printf '[OK  ] %s\n' "$1"; }
warn() { printf '[WARN] %s\n' "$1"; [ -n "${2:-}" ] && printf '       fix: %s\n' "$2"; return 0; }
fail() { printf '[FAIL] %s\n' "$1"; [ -n "${2:-}" ] && printf '       fix: %s\n' "$2"; FAILS=$((FAILS + 1)); }
get() { envget "$ENV_FILE" "$1"; }

if [ ! -f "$ENV_FILE" ]; then
  echo "cannot read $ENV_FILE" >&2
  echo "Create it with: cp .env.example .env   (then fill in the $LABEL values, see $GUIDE)" >&2
  exit 1
fi
echo "Checking $LABEL ($PROVIDER) in ${ENV_FILE#"$ROOT"/}"

# --- gateway-wide settings ---
SECRET="$(get SSO_STATE_SECRET)"
if [ -z "$SECRET" ]; then
  fail "SSO_STATE_SECRET is not set" "openssl rand -base64 48, then put it in SSO_STATE_SECRET"
elif [[ "$SECRET" == change-this* ]]; then
  fail "SSO_STATE_SECRET still holds the public example value" "openssl rand -base64 48"
elif [ "${#SECRET}" -lt 32 ]; then
  fail "SSO_STATE_SECRET is shorter than 32 bytes (${#SECRET})" "openssl rand -base64 48"
else
  ok "SSO_STATE_SECRET is set (${#SECRET} bytes, value not shown)"
fi

PORT="$(get SSO_SERVER_PORT)"; PORT="${PORT:-8080}"
if [ "$PORT" = 5000 ] && [ "$(uname -s)" = Darwin ]; then
  fail "SSO_SERVER_PORT is 5000, reserved for AirDrop on macOS" "choose another port, for example 8080"
else
  ok "SSO_SERVER_PORT is $PORT"
fi

# --- provider credentials ---
CID="$(get "${PREFIX}_CLIENT_ID")"
CSEC="$(get "${PREFIX}_CLIENT_SECRET")"
if is_placeholder "$CID"; then
  fail "${PREFIX}_CLIENT_ID is empty or a sample value: the gateway keeps $PROVIDER switched off" \
    "paste the client id from your $LABEL application ($GUIDE)"
else
  ok "${PREFIX}_CLIENT_ID is set"
fi
if is_placeholder "$CSEC"; then
  fail "${PREFIX}_CLIENT_SECRET is empty or a sample value" "paste the client secret from $LABEL (value is never printed here)"
else
  ok "${PREFIX}_CLIENT_SECRET is set (value not shown)"
fi

# secure_url NAME VALUE: https, or http only for loopback (matches oidc.ValidateURL).
secure_url() {
  local name="$1" v="$2" host
  case "$v" in
    https://?*) return 0 ;;
    http://?*)
      host="${v#http://}"; host="${host%%[/:]*}"
      case "$host" in localhost | 127.* | "[::1]") return 0 ;; esac ;;
  esac
  fail "$name must be an https URL (http only for localhost), got: ${v:-<empty>}" "see $GUIDE"
  return 1
}

DISCOVERY=""
case "$PROVIDER" in
  okta)
    ISS="$(get "${PREFIX}_ISSUER_URL")"
    if [ -z "$ISS" ]; then
      fail "${PREFIX}_ISSUER_URL is not set" "for example https://<org>.okta.com/oauth2/default"
    elif [[ "$ISS" == *example.okta.com* ]]; then
      fail "${PREFIX}_ISSUER_URL is still the sample host" "use your own Okta org host"
    elif secure_url "${PREFIX}_ISSUER_URL" "$ISS"; then
      ok "${PREFIX}_ISSUER_URL is a valid URL"
      DISCOVERY="${ISS%/}/.well-known/openid-configuration"
    fi
    ;;
  auth0)
    ISS="$(get "${PREFIX}_ISSUER_URL")"
    if [ -z "$ISS" ]; then
      fail "${PREFIX}_ISSUER_URL is not set" "for example https://<tenant>.<region>.auth0.com/"
    elif [[ "$ISS" == *example.us.auth0.com* ]]; then
      fail "${PREFIX}_ISSUER_URL is still the sample host" "use your own Auth0 tenant domain"
    elif secure_url "${PREFIX}_ISSUER_URL" "$ISS"; then
      ok "${PREFIX}_ISSUER_URL is a valid URL (the adapter adds the trailing slash Auth0 puts in iss)"
      DISCOVERY="${ISS%/}/.well-known/openid-configuration"
    fi
    ;;
  azure)
    TENANT="$(get "${PREFIX}_TENANT_ID")"
    GUID='^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$'
    AUTH="$(get "${PREFIX}_AUTHORITY")"; AUTH="${AUTH:-https://login.microsoftonline.com}"
    if [ -z "$TENANT" ]; then
      fail "${PREFIX}_TENANT_ID is not set" "a tenant GUID, a tenant domain, or common / organizations / consumers"
    elif [[ "$TENANT" =~ $GUID ]]; then
      ok "${PREFIX}_TENANT_ID is a tenant GUID (single tenant, issuer pinned)"
    elif [[ "$TENANT" =~ ^(common|organizations|consumers)$ ]]; then
      ALLOWED="$(get "${PREFIX}_ALLOWED_TENANTS")"
      if [ -z "$ALLOWED" ]; then
        warn "tenant '$TENANT' is multi-tenant and ${PREFIX}_ALLOWED_TENANTS is empty: any tenant the endpoint admits can sign in" \
          "list the allowed tenant GUIDs, comma separated"
      else
        ok "multi-tenant '$TENANT' limited to ${PREFIX}_ALLOWED_TENANTS"
      fi
    elif [[ "$TENANT" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}$ ]]; then
      ok "${PREFIX}_TENANT_ID is a tenant domain"
    else
      fail "${PREFIX}_TENANT_ID '$TENANT' is not a GUID, a domain or common/organizations/consumers" "see $GUIDE"
    fi
    if [ -n "$(get "${PREFIX}_ALLOWED_TENANTS")" ]; then
      bad=0
      IFS=', ' read -r -a ids <<<"$(get "${PREFIX}_ALLOWED_TENANTS")"
      for t in "${ids[@]}"; do [ -n "$t" ] && ! [[ "$t" =~ $GUID ]] && bad=1; done
      [ "$bad" -eq 1 ] && fail "${PREFIX}_ALLOWED_TENANTS must contain tenant GUIDs only" "comma separated GUIDs"
    fi
    if secure_url "${PREFIX}_AUTHORITY" "$AUTH" && [ -n "$TENANT" ]; then
      DISCOVERY="${AUTH%/}/$TENANT/v2.0/.well-known/openid-configuration"
    fi
    ;;
  oauth2)
    for v in AUTH_URL TOKEN_URL USERINFO_URL; do
      val="$(get "${PREFIX}_$v")"
      if [ -z "$val" ]; then
        fail "${PREFIX}_$v is not set" "copy it from the provider's OAuth documentation ($GUIDE)"
      elif [[ "$val" == *example.com* || "$val" == *example.org* || "$val" == *-placeholder* ]]; then
        fail "${PREFIX}_$v is still a sample value" "use your provider's real endpoint"
      elif secure_url "${PREFIX}_$v" "$val"; then
        ok "${PREFIX}_$v is a valid URL"
      fi
    done
    STYLE="$(get "${PREFIX}_AUTH_STYLE")"
    case "$STYLE" in
      "" | basic | post) ok "${PREFIX}_AUTH_STYLE is ${STYLE:-basic (default)}" ;;
      *) fail "${PREFIX}_AUTH_STYLE must be basic or post, got: $STYLE" "see $GUIDE" ;;
    esac
    [ -z "$(get "${PREFIX}_SCOPES")" ] && warn "${PREFIX}_SCOPES is empty: the provider's default scope applies" "list the scopes your profile endpoint needs"
    ;;
esac

# --- redirect URI: must match the IdP console exactly ---
BASE="$(get SSO_SERVER_BASE_URL)"
REDIRECT="$(get "${PREFIX}_REDIRECT_URL")"
EXPECT_PATH="/auth/$PROVIDER/callback"
if [ -z "$REDIRECT" ]; then
  if [ -z "$BASE" ]; then
    fail "set ${PREFIX}_REDIRECT_URL or SSO_SERVER_BASE_URL" "for example http://localhost:$PORT$EXPECT_PATH"
  else
    REDIRECT="${BASE%/}$EXPECT_PATH"
    ok "redirect URI defaults to $REDIRECT"
  fi
else
  if [[ "$REDIRECT" != *"$EXPECT_PATH" ]]; then
    warn "${PREFIX}_REDIRECT_URL does not end in $EXPECT_PATH, the path the gateway serves" "use $EXPECT_PATH"
  elif secure_url "${PREFIX}_REDIRECT_URL" "$REDIRECT"; then
    ok "${PREFIX}_REDIRECT_URL ends in $EXPECT_PATH"
  fi
  if [ -n "$BASE" ] && [[ "$REDIRECT" != "${BASE%/}"/* ]]; then
    warn "redirect URI host differs from SSO_SERVER_BASE_URL ($BASE)" "they should point at the same gateway"
  fi
fi
[ -n "$REDIRECT" ] && echo "       register this exact redirect URI in $LABEL: $REDIRECT"

# --- optional network check ---
if [ "$ONLINE" -eq 1 ]; then
  if [ "$PROVIDER" = oauth2 ]; then
    warn "--online has nothing to check for oauth2: it has no discovery document"
  elif [ -z "$DISCOVERY" ]; then
    warn "skipped the discovery check: the issuer settings above are not usable yet"
  elif ! command -v curl >/dev/null 2>&1; then
    fail "--online needs curl, which is not installed" "install curl or drop --online"
  else
    if body="$(curl -fsS --max-time 10 "$DISCOVERY" 2>&1)" && grep -q '"authorization_endpoint"' <<<"$body"; then
      ok "discovery document reachable at ${DISCOVERY%%/.well-known*}/..."
    else
      fail "could not fetch a discovery document from ${DISCOVERY%%/.well-known*}/..." "check the issuer / tenant spelling and your network"
    fi
  fi
fi

echo
if [ "$FAILS" -eq 0 ]; then
  echo "$LABEL settings look ready. This checks configuration only: it does not prove a sign-in works."
  echo "Next: scripts/run-example.sh python --mode real --provider $PROVIDER"
  exit 0
fi
echo "$FAILS problem(s) found. Fix them, then run: scripts/provider-check.sh $PROVIDER" >&2
exit 1
