#!/usr/bin/env bash
# Build and launch the ssod gateway detached; print its URL once /healthz answers.
# Configuration comes from .env (see .env.example): SSO_SERVER_HOST, SSO_SERVER_PORT, SSO_STATE_SECRET.
# Idempotent: if already running, reports the existing process and exits 0.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Load .env (values are sourced, so keep it to KEY=VALUE lines).
if [ -f .env ]; then set -a; . ./.env; set +a; fi

SSO_SERVER_HOST="${SSO_SERVER_HOST:-127.0.0.1}"
SSO_SERVER_PORT="${SSO_SERVER_PORT:-8080}"
START_TIMEOUT="${START_TIMEOUT:-10}"
export SSO_SERVER_HOST SSO_SERVER_PORT

: "${SSO_STATE_SECRET:?Set SSO_STATE_SECRET (>= 32 bytes) in .env, e.g. openssl rand -base64 48}"
if [ "$SSO_SERVER_PORT" = "5000" ] && [ "$(uname -s)" = "Darwin" ]; then
  echo "ERROR: port 5000 is reserved for AirDrop on macOS; choose another SSO_SERVER_PORT" >&2; exit 1
fi
command -v go >/dev/null 2>&1 || { echo "ERROR: Go toolchain not found in PATH" >&2; exit 1; }

RUN_DIR="$ROOT/.run"; PID_FILE="$RUN_DIR/app.pid"; LOG_FILE="$RUN_DIR/app.log"; BIN="$RUN_DIR/ssod"
URL="http://$SSO_SERVER_HOST:$SSO_SERVER_PORT"
mkdir -p "$RUN_DIR"

if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  echo "Already running (pid $(cat "$PID_FILE")): $URL"; exit 0
fi
rm -f "$PID_FILE"   # clear any stale pid file

echo "Building ssod ..."
if ! go build -o "$BIN" ./cmd/ssod; then
  echo "ERROR: build failed" >&2; exit 1
fi

# exec so the recorded pid is the server itself and receives SIGTERM directly.
nohup bash -c 'exec "$0"' "$BIN" >"$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"
PID="$(cat "$PID_FILE")"

# Wait until the process answers /healthz, or fails.
for _ in $(seq 1 $((START_TIMEOUT * 5))); do
  if ! kill -0 "$PID" 2>/dev/null; then
    echo "ERROR: application exited during startup; last log lines:" >&2
    tail -n 5 "$LOG_FILE" >&2 || true
    rm -f "$PID_FILE"; exit 1
  fi
  if curl -fsS -o /dev/null "$URL/healthz" 2>/dev/null; then
    echo "Application started (pid $PID)"
    echo "URL: $URL"
    echo "Logs: $LOG_FILE"
    exit 0
  fi
  sleep 0.2
done

echo "ERROR: no healthy response from $URL/healthz within ${START_TIMEOUT}s; stopping" >&2
kill -TERM "$PID" 2>/dev/null || true
rm -f "$PID_FILE"
exit 1
