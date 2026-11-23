#!/usr/bin/env bash
# Shared helpers for provider-check.sh and run-example.sh. Source it, do not run it.
#
# Nothing here executes or prints the contents of an env file: values are read
# with grep, so a secret never reaches the terminal unless a caller prints it.

die() { # message [exit-code]
  echo "ERROR: $1" >&2
  exit "${2:-1}"
}

# envget FILE KEY: last assignment of KEY in FILE, quotes and inline comment removed.
# Prints nothing (and succeeds) when the key is absent.
envget() {
  local f="$1" k="$2" v
  [ -f "$f" ] || return 0
  v="$(grep -E "^[[:space:]]*(export[[:space:]]+)?${k}=" "$f" 2>/dev/null | tail -n 1)" || true
  v="${v#*=}"
  v="${v%$'\r'}"
  case "$v" in
    \"*\") v="${v#\"}"; v="${v%\"}" ;;
    \'*\') v="${v#\'}"; v="${v%\'}" ;;
    *) v="${v%% \#*}" ;;
  esac
  # trim trailing blanks
  v="${v%"${v##*[![:space:]]}"}"
  printf '%s' "$v"
}

# is_placeholder VALUE: empty, an unedited .env.example value, or the legacy Okta sample id.
# Mirrors isPlaceholder and legacyOktaSampleID in cmd/ssod.
is_placeholder() {
  case "$1" in
    "" | *-placeholder | 0oa123456789okta) return 0 ;;
  esac
  return 1
}

# A per-user .NET SDK outside the repository (see Docs/Examples.md) is used when dotnet is not on PATH.
use_local_dotnet() {
  local local_sdk="${DOTNET_LOCAL:-$HOME/.local/share/dotnet-universal-sso}"
  if ! command -v dotnet >/dev/null 2>&1 && [ -x "$local_sdk/dotnet" ]; then
    export DOTNET_ROOT="$local_sdk" PATH="$local_sdk:$PATH"
  fi
  export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
}

# java_major: prints the major version of the java on PATH, or nothing.
java_major() {
  command -v java >/dev/null 2>&1 || return 0
  java -version 2>&1 | sed -n 's/.*version "\([0-9]*\).*/\1/p' | head -n 1
}
