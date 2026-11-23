#!/usr/bin/env bash
# Runs the root Go tests and the test suite of every example under examples/.
# An example whose toolchain is not installed is reported as SKIPPED, loudly.
# Set REQUIRE_ALL=1 to turn a skipped example into a failure.
# Exit: 0 all executed suites passed, 1 a suite failed (or a skip with REQUIRE_ALL=1).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
ROOT="$PWD"
RC=0
SKIPPED=()

# A project-local .NET SDK (see Docs/Examples.md) is used when dotnet is not on PATH.
[ -x "$ROOT/_dotnet/sdk/dotnet" ] && ! command -v dotnet >/dev/null 2>&1 && export PATH="$ROOT/_dotnet/sdk:$PATH"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1

suite() { # name, required tool, directory, command...
  local name="$1" tool="$2" dir="$3"; shift 3
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "== $name: SKIPPED ($tool not installed)"; SKIPPED+=("$name"); return
  fi
  echo "== $name"
  ( cd "$dir" && "$@" ) || { echo "FAIL: $name"; RC=1; }
}

suite "root (go)"               go     "$ROOT"                          go test -race ./...
suite "examples/saml2-go"       go     "$ROOT/examples/saml2-go"        go test -race ./...
suite "examples/oauth2-rust"    cargo  "$ROOT/examples/oauth2-rust"     cargo test --quiet
suite "examples/auth0-python"   python3 "$ROOT/examples/auth0-python"   env PYTHONPATH=.:tests python3 -m unittest discover -s tests
suite "examples/okta-java"      mvn    "$ROOT/examples/okta-java"       mvn -q -B test
suite "examples/azure-ad-csharp" dotnet "$ROOT/examples/azure-ad-csharp/tests" dotnet test --nologo

if [ "${#SKIPPED[@]}" -gt 0 ]; then
  echo "SKIPPED suites: ${SKIPPED[*]}"
  [ "${REQUIRE_ALL:-0}" = 1 ] && RC=1
fi
exit "$RC"
