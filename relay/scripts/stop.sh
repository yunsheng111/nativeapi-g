#!/usr/bin/env bash
# Stop GLM2API server.
# Usage: ./scripts/stop.sh
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -f ./.server.pid ]; then
  PID="$(cat ./.server.pid)"
  if kill -0 "$PID" 2>/dev/null; then
    echo "[stop] sending SIGTERM to PID $PID"
    kill "$PID" 2>/dev/null || true
    for _ in 1 2 3 4 5; do
      sleep 1
      kill -0 "$PID" 2>/dev/null || break
    done
    if kill -0 "$PID" 2>/dev/null; then
      echo "[stop] still alive, sending SIGKILL"
      kill -9 "$PID" 2>/dev/null || true
    fi
    echo "[stop] stopped"
  else
    echo "[stop] PID $PID not running"
  fi
  rm -f ./.server.pid
else
  echo "[stop] no PID file found"
fi
