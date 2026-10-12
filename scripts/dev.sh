#!/usr/bin/env bash
# Dev mode: backend on :8000 (with autoreload) + ng serve on :4200.
# The frontend proxies /api and /ws to the backend (see frontend/proxy.conf.json).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -x backend/.venv/bin/python ]]; then
  echo "No venv. Run scripts/setup.sh first." >&2
  exit 1
fi

cleanup() {
  echo
  echo "Stopping processes..."
  jobs -p | xargs -r kill 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "==> Backend  http://0.0.0.0:8000  (API docs: /docs)"
backend/.venv/bin/python -m uvicorn app.main:app \
  --app-dir backend --host 0.0.0.0 --port 8000 --reload &

echo "==> Frontend http://0.0.0.0:4200"
(cd frontend && npm start -- --host 0.0.0.0) &

wait
