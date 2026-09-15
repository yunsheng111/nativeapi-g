#!/usr/bin/env bash
# Start GLM2API server in background.
# Usage: ./scripts/start.sh [port]
set -euo pipefail

cd "$(dirname "$0")/.."

PORT="${1:-8000}"
LOG_DIR="${GLM2API_LOG_DIR:-./log}"
mkdir -p "$LOG_DIR"

# Locate python (prefer .venv, fallback to system python3)
if [ -x ".venv/bin/python" ]; then
  PY=".venv/bin/python"
else
  PY="$(command -v python3)"
fi

LOG_FILE="$LOG_DIR/server.log"
echo "[start] launching GLM2API on port ${PORT}, log: $LOG_FILE"

export PORT
nohup "$PY" -m glm2api >> "$LOG_FILE" 2>&1 &
SERVER_PID=$!
echo $SERVER_PID > ./.server.pid
echo "[start] server PID: $SERVER_PID"
sleep 2

if curl -sf -m 3 "http://127.0.0.1:${PORT}/health" > /dev/null 2>&1; then
  echo "[start] OK - health check passed"
else
  echo "[start] WARN - health check failed; check $LOG_FILE"
  exit 1
fi
