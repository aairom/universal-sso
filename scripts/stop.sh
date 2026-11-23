#!/usr/bin/env bash
# Gracefully stop ssod started by start.sh: SIGTERM, wait up to STOP_TIMEOUT seconds, then SIGKILL.
# Idempotent: exits 0 when nothing is running.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_FILE="$ROOT/.run/app.pid"
TIMEOUT="${STOP_TIMEOUT:-15}"

if [ ! -f "$PID_FILE" ]; then echo "Not running (no pid file)"; exit 0; fi
PID="$(cat "$PID_FILE")"
if ! kill -0 "$PID" 2>/dev/null; then echo "Not running (stale pid $PID)"; rm -f "$PID_FILE"; exit 0; fi

pkill -TERM -P "$PID" 2>/dev/null || true   # children, if any
kill -TERM "$PID" 2>/dev/null || true
for _ in $(seq 1 $((TIMEOUT * 5))); do
  if ! kill -0 "$PID" 2>/dev/null; then rm -f "$PID_FILE"; echo "Application stopped"; exit 0; fi
  sleep 0.2
done
echo "Graceful stop timed out after ${TIMEOUT}s; forcing" >&2
pkill -KILL -P "$PID" 2>/dev/null || true
kill -KILL "$PID" 2>/dev/null || true
rm -f "$PID_FILE"
echo "Application killed"
