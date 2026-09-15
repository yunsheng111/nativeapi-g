#!/usr/bin/env bash
# Show GLM2API server status.
# Usage: ./scripts/status.sh
set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${PORT:-8000}"

if [ -f ./.server.pid ]; then
  PID="$(cat ./.server.pid)"
  if kill -0 "$PID" 2>/dev/null; then
    echo "[status] server running, PID=$PID"
  else
    echo "[status] stale PID file (PID $PID not running)"
  fi
else
  echo "[status] no PID file"
fi

if curl -sf -m 3 "http://127.0.0.1:${PORT}/health" > /dev/null 2>&1; then
  echo "[status] /health: OK"
else
  echo "[status] /health: unreachable"
fi

if curl -sf -m 3 "http://127.0.0.1:${PORT}/v1/models" > /dev/null 2>&1; then
  echo "[status] /v1/models: OK"
else
  echo "[status] /v1/models: unreachable"
fi
