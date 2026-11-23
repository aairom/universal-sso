#!/usr/bin/env bash
# Launch one example client against a gateway and verify that the sign-in flow is ready.
# Counterpart of the Google helper flow (make google-check / google-url) for the five examples.
#
# Usage:
#   scripts/run-example.sh <rust|go|python|java|csharp> [--mode mock|e2e|real] [--provider ID]
#                          [--port N] [--keep-running] [--open] [--check-only]
#   scripts/run-example.sh --list
#
# Modes
#   mock  (default) Needs no credentials. Builds ssod, starts a throw-away gateway with only the
#                   mock provider, builds the client and completes a full sign-in with --follow.
#   e2e             Same, but ssod is built with -tags e2e and serves in-process FAKE Okta, Auth0
#                   and Entra servers. Proves the adapters and the client work together. It does
#                   NOT prove your real tenant works. --provider: okta, auth0, azure or mock.
#   real            Uses YOUR .env: validates it (provider-check.sh / ssoctl), starts the project
#                   gateway through scripts/start.sh, builds the client and prints the browser URL.
#                   You finish the sign-in in a browser; the callback shows your profile as JSON.
#
# Default provider per example: rust=oauth2, go=saml, python=auth0, java=okta, csharp=azure.
# SAML and generic OAuth 2.0 adapters do not exist yet, so for rust and go pass --provider
# (okta, auth0, azure, google or mock) in e2e and real mode.
#
# Prerequisites (checked before anything is built):
#   all     bash, curl, Go (builds ssod; go.mod sets the version)
#   rust    cargo            go     Go 1.22+          python  Python 3.9+ (standard library only)
#   java    JDK 21+ and mvn  csharp .NET 8 SDK (or the per-user SDK in ~/.local/share/dotnet-universal-sso)
# Environment (all optional): SSO_GATEWAY_URL, SSO_EXPECTED_IDP_HOST, SSO_HTTP_TIMEOUT_SECONDS,
#   DOTNET_LOCAL. In real mode the gateway reads .env (see .env.example); this script never prints
#   secret values. SSO_EXPECTED_IDP_HOST is derived from your issuer or authority unless you set it
#   (set it empty to switch pinning off).
#
# Idempotent: re-running rebuilds only what changed (go, cargo, mvn and dotnet are incremental),
# replaces a previous throw-away gateway, and reuses a project gateway that is already running.
# Files written: .run/examples/ (ignored by git). Exit: 0 ok, 1 failure, 2 bad usage or configuration.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/sso-common.sh
. "$ROOT/scripts/sso-common.sh"
cd "$ROOT" || die "cannot enter $ROOT"

usage() { sed -n '2,32p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 2; }
fail_usage() { echo "ERROR: $1" >&2; echo "Run scripts/run-example.sh --help for usage." >&2; exit 2; }

EX=""; MODE=mock; PROVIDER=""; PORT=18932; KEEP=0; OPEN=0; CHECK_ONLY=0
case "${1:-}" in
  --list)
    printf '%-8s %-24s %-10s %s\n' example directory provider toolchain
    printf '%-8s %-24s %-10s %s\n' rust examples/oauth2-rust oauth2 cargo
    printf '%-8s %-24s %-10s %s\n' go examples/saml2-go saml go
    printf '%-8s %-24s %-10s %s\n' python examples/auth0-python auth0 python3
    printf '%-8s %-24s %-10s %s\n' java examples/okta-java okta 'JDK 21 + mvn'
    printf '%-8s %-24s %-10s %s\n' csharp examples/azure-ad-csharp azure 'dotnet 8'
    exit 0 ;;
  -h | --help | "") usage ;;
esac
EX="$1"; shift
while [ $# -gt 0 ]; do
  case "$1" in
    --mode) [ $# -ge 2 ] || fail_usage "--mode needs a value"; MODE="$2"; shift 2 ;;
    --provider) [ $# -ge 2 ] || fail_usage "--provider needs a value"; PROVIDER="$2"; shift 2 ;;
    --port) [ $# -ge 2 ] || fail_usage "--port needs a value"; PORT="$2"; shift 2 ;;
    --keep-running) KEEP=1; shift ;;
    --open) OPEN=1; shift ;;
    --check-only) CHECK_ONLY=1; shift ;;
    -h | --help) usage ;;
    *) fail_usage "unknown option: $1" ;;
  esac
done

case "$EX" in
  rust) DIR=examples/oauth2-rust; DEFAULT_PROVIDER=oauth2 ;;
  go) DIR=examples/saml2-go; DEFAULT_PROVIDER=saml ;;
  python) DIR=examples/auth0-python; DEFAULT_PROVIDER=auth0 ;;
  java) DIR=examples/okta-java; DEFAULT_PROVIDER=okta ;;
  csharp) DIR=examples/azure-ad-csharp; DEFAULT_PROVIDER=azure ;;
  *) fail_usage "unknown example '$EX' (use rust, go, python, java or csharp)" ;;
esac
case "$MODE" in mock | e2e | real) ;; *) fail_usage "unknown mode '$MODE' (use mock, e2e or real)" ;; esac
[[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1024 ] && [ "$PORT" -le 65535 ] || fail_usage "--port must be 1024 to 65535"
[ "$PORT" = 5000 ] && fail_usage "port 5000 is reserved for AirDrop on macOS"

if [ "$MODE" = mock ]; then
  [ -z "$PROVIDER" ] || [ "$PROVIDER" = mock ] || fail_usage "mock mode only signs in through the mock provider (use --mode e2e or real)"
  PROVIDER=mock
else
  PROVIDER="${PROVIDER:-$DEFAULT_PROVIDER}"
  case "$PROVIDER" in
    okta | auth0 | azure | mock) ;;
    google) [ "$MODE" = real ] || fail_usage "google exists only in real mode (the e2e gateway has no fake Google)" ;;
    saml | oauth2) fail_usage "the gateway has no '$PROVIDER' adapter yet (planned, see Docs/Architecture.md). Add --provider okta, auth0, azure, google or mock" ;;
    *) fail_usage "unknown provider '$PROVIDER'" ;;
  esac
fi

# ---------------------------------------------------------------- preflight
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is not installed. $2" 1; }
need curl "Install curl."
need go "Install Go from https://go.dev/dl/ (the gateway is built from source)."
use_local_dotnet
case "$EX" in
  rust) need cargo "Install Rust with rustup (https://rustup.rs)." ;;
  python)
    need python3 "Install Python 3.9 or newer."
    python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' || die "Python 3.9 or newer is required, found $(python3 --version 2>&1)" ;;
  java)
    need java "Install JDK 21 or newer."; need mvn "Install Maven 3.9 or newer."
    jm="$(java_major)"; [ -n "$jm" ] && [ "$jm" -ge 21 ] 2>/dev/null || die "JDK 21 or newer is required, found major version '${jm:-unknown}'" ;;
  csharp) need dotnet "Install the .NET 8 SDK, or see Docs/Examples.md for the per-user install." ;;
esac

OUT="$ROOT/.run/examples"; mkdir -p "$OUT" || die "cannot create $OUT"
GW_PID_FILE="$OUT/gateway-$PORT.pid"; GW_LOG="$OUT/gateway-$PORT.log"
STARTED_EPHEMERAL=0

stop_ephemeral() {
  [ -f "$GW_PID_FILE" ] || return 0
  local pid; pid="$(cat "$GW_PID_FILE")"
  if kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null
    for _ in $(seq 1 25); do kill -0 "$pid" 2>/dev/null || break; sleep 0.2; done
    kill -KILL "$pid" 2>/dev/null || true
  fi
  rm -f "$GW_PID_FILE"
}
cleanup() { if [ "$STARTED_EPHEMERAL" -eq 1 ] && [ "$KEEP" -eq 0 ]; then stop_ephemeral; fi; }
trap cleanup EXIT

wait_healthy() { # url pid-or-empty seconds
  local url="$1" pid="$2" secs="$3"
  for _ in $(seq 1 $((secs * 5))); do
    if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then return 2; fi
    curl -fsS -o /dev/null --max-time 2 "$url/healthz" 2>/dev/null && return 0
    sleep 0.2
  done
  return 1
}

providers_json() { curl -fsS --max-time 5 "$1/providers" 2>/dev/null; }

# ------------------------------------------------------------------ gateway
if [ "$MODE" = real ]; then
  ENV_FILE="$ROOT/.env"
  [ -f "$ENV_FILE" ] || die "$ENV_FILE not found. Create it with: cp .env.example .env, then fill in the $PROVIDER values (Docs/*-SSO-Setup.md)" 2
  case "$PROVIDER" in
    google) echo "== validating Google settings"; go run ./cmd/ssoctl google check || die "Google settings are not ready (see the fixes above)" ;;
    mock) ;;
    *) echo "== validating $PROVIDER settings"; bash "$ROOT/scripts/provider-check.sh" "$PROVIDER" || die "$PROVIDER settings are not ready (see the fixes above)" ;;
  esac
  HOST="$(envget "$ENV_FILE" SSO_SERVER_HOST)"; HOST="${HOST:-127.0.0.1}"
  GPORT="$(envget "$ENV_FILE" SSO_SERVER_PORT)"; GPORT="${GPORT:-8080}"
  GATEWAY_URL="${SSO_GATEWAY_URL:-http://$HOST:$GPORT}"
  [ "$CHECK_ONLY" -eq 1 ] && { echo "Settings validated (--check-only): nothing was started."; exit 0; }
  echo "== gateway (scripts/start.sh, reuses a running one)"
  bash "$ROOT/scripts/start.sh" || die "gateway did not start (see .run/app.log)"
else
  GATEWAY_URL="${SSO_GATEWAY_URL:-http://127.0.0.1:$PORT}"
  [ "$CHECK_ONLY" -eq 1 ] && { echo "Toolchain ok for $EX, mode $MODE (--check-only): nothing was built or started."; exit 0; }
  if [ -n "${SSO_GATEWAY_URL:-}" ] && [ "$SSO_GATEWAY_URL" != "http://127.0.0.1:$PORT" ]; then
    echo "note: ignoring SSO_GATEWAY_URL=$SSO_GATEWAY_URL, the throw-away gateway listens on http://127.0.0.1:$PORT"
  fi
  GATEWAY_URL="http://127.0.0.1:$PORT"
  BIN="$OUT/ssod-$MODE"
  echo "== building ssod ($MODE)"
  tags=(); [ "$MODE" = e2e ] && tags=(-tags e2e)
  go build ${tags[@]+"${tags[@]}"} -o "$BIN" ./cmd/ssod || die "ssod build failed"
  stop_ephemeral   # replace a previous run
  if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
    die "port $PORT is already in use by another program. Choose another with --port N" 1
  fi
  base="http://127.0.0.1:$PORT"
  # Throw-away configuration. Nothing here is a credential for a real service.
  state="$(head -c 48 /dev/urandom | base64 | tr -d '\n')"
  GW_ENV=(PATH="$PATH" HOME="$HOME" SSO_STATE_SECRET="$state" SSO_SERVER_HOST=127.0.0.1 SSO_SERVER_PORT="$PORT" SSO_SERVER_BASE_URL="$base")
  if [ "$MODE" = e2e ]; then
    GW_ENV+=(
      SSO_PROVIDERS_OKTA_CLIENT_ID=e2e-okta SSO_PROVIDERS_OKTA_CLIENT_SECRET=e2e-value SSO_PROVIDERS_OKTA_ISSUER_URL="$base/idp/okta/oauth2/default"
      SSO_PROVIDERS_AUTH0_CLIENT_ID=e2e-auth0 SSO_PROVIDERS_AUTH0_CLIENT_SECRET=e2e-value SSO_PROVIDERS_AUTH0_ISSUER_URL="$base/idp/auth0"
      SSO_PROVIDERS_AZURE_CLIENT_ID=e2e-azure SSO_PROVIDERS_AZURE_CLIENT_SECRET=e2e-value
      SSO_PROVIDERS_AZURE_TENANT_ID=11111111-1111-1111-1111-111111111111 SSO_PROVIDERS_AZURE_AUTHORITY="$base/idp/azure"
    ) # nosecret: throw-away values for the in-process fake IdPs
  fi
  echo "== starting throw-away gateway on $base"
  env -i "${GW_ENV[@]}" "$BIN" >"$GW_LOG" 2>&1 &
  echo $! >"$GW_PID_FILE"; STARTED_EPHEMERAL=1
  wait_healthy "$base" "$(cat "$GW_PID_FILE")" 10; rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "ERROR: gateway did not become healthy (log: ${GW_LOG#"$ROOT"/}):" >&2; tail -n 5 "$GW_LOG" >&2
    exit 1
  fi
fi

echo "== gateway ready at $GATEWAY_URL"
pj="$(providers_json "$GATEWAY_URL")" || die "gateway at $GATEWAY_URL does not answer /providers"
if ! grep -q "\"$PROVIDER\"" <<<"$pj"; then
  hint="check the settings with scripts/provider-check.sh $PROVIDER"
  [ "$MODE" = real ] && hint="$hint. If you edited .env after the gateway started, run: make restart"
  die "provider '$PROVIDER' is not registered in the gateway (registered: $pj). $hint"
fi
echo "   provider '$PROVIDER' is registered"

# ------------------------------------------------------------------- client
echo "== building the $EX client"
CLIENT_CWD="$ROOT/$DIR"; FOLLOW=--follow
case "$EX" in
  rust)
    (cd "$CLIENT_CWD" && cargo build --release --quiet) || die "cargo build failed in $DIR"
    CLIENT=("$CLIENT_CWD/target/release/oauth2-rust") ;;
  go)
    (cd "$CLIENT_CWD" && go build -o "$OUT/saml2-go" .) || die "go build failed in $DIR"
    CLIENT=("$OUT/saml2-go"); FOLLOW=-follow ;;
  python)
    (cd "$CLIENT_CWD" && python3 -c 'import sso_client.cli') || die "python client does not import in $DIR"
    CLIENT=(python3 -m sso_client.cli) ;;
  java)
    (cd "$CLIENT_CWD" && mvn -q -B package -DskipTests) || die "mvn package failed in $DIR"
    CLIENT=(java -cp "target/classes:target/lib/*" com.universalsso.client.Main) ;;
  csharp)
    (cd "$CLIENT_CWD" && dotnet build -c Release src --nologo -v q) || die "dotnet build failed in $DIR"
    CLIENT=(dotnet "$CLIENT_CWD/src/bin/Release/net8.0/azure-ad-csharp.dll") ;;
esac

# Pin the IdP host in real mode unless the caller decided (an explicit empty value turns it off).
IDP_PIN="${SSO_EXPECTED_IDP_HOST-}"
if [ "$MODE" = real ] && [ -z "${SSO_EXPECTED_IDP_HOST+x}" ]; then
  case "$PROVIDER" in
    okta) u="$(envget "$ENV_FILE" SSO_PROVIDERS_OKTA_ISSUER_URL)" ;;
    auth0) u="$(envget "$ENV_FILE" SSO_PROVIDERS_AUTH0_ISSUER_URL)" ;;
    azure) u="$(envget "$ENV_FILE" SSO_PROVIDERS_AZURE_AUTHORITY)"; u="${u:-https://login.microsoftonline.com}" ;;
    google) u="https://accounts.google.com" ;;
    *) u="" ;;
  esac
  IDP_PIN="${u#*://}"; IDP_PIN="${IDP_PIN%%[/:]*}"
  [ -n "$IDP_PIN" ] && echo "   pinning the IdP host to $IDP_PIN (override with SSO_EXPECTED_IDP_HOST)"
fi

run_client() { # args...
  (cd "$CLIENT_CWD" && env SSO_GATEWAY_URL="$GATEWAY_URL" SSO_PROVIDER="$PROVIDER" \
    SSO_EXPECTED_IDP_HOST="$IDP_PIN" "${CLIENT[@]}" "$@")
}

echo "== check: gateway reachable and provider registered"
run_client check || die "client check failed. The client and the gateway disagree about $GATEWAY_URL or '$PROVIDER'"

if [ "$MODE" != real ]; then
  echo "== sign-in with --follow ($MODE mode, no browser)"
  [ "$MODE" = e2e ] && echo "   NOTE: this uses an in-process FAKE identity provider, not a real tenant."
  out="$(run_client login "$FOLLOW" 2>&1)"; rc=$?
  echo "$out"
  if [ "$rc" -ne 0 ] || ! grep -qi "signed in via $PROVIDER" <<<"$out"; then
    die "sign-in did not complete (exit $rc). Gateway log: ${GW_LOG#"$ROOT"/}"
  fi
  echo "OK: $EX completed a sign-in ($MODE mode) via $PROVIDER."
  [ "$KEEP" -eq 1 ] && echo "Gateway left running (pid $(cat "$GW_PID_FILE")) at $GATEWAY_URL. Stop it with: kill \$(cat ${GW_PID_FILE#"$ROOT"/})"
  exit 0
fi

echo "== login URL"
out="$(run_client login 2>&1)"; rc=$?
echo "$out"
[ "$rc" -eq 0 ] || die "the client could not start a sign-in (exit $rc)"
url="$(grep -Eo -m1 'https?://[^[:space:]]+' <<<"$out" | head -n 1)"
[ -n "$url" ] || die "the client printed no sign-in URL"
if [ "$OPEN" -eq 1 ]; then
  if command -v open >/dev/null 2>&1; then open "$url"; elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$url" >/dev/null 2>&1; else echo "no browser opener found, open the URL yourself"; fi
fi
echo
echo "Ready. Sign in with the URL above. The identity provider returns your browser to the gateway,"
echo "which shows your profile as JSON. Stop the gateway with: make stop"
exit 0
