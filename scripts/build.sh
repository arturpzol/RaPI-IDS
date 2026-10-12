#!/usr/bin/env bash
# Production build of the frontend. The backend detects the dist directory and
# serves the SPA from the same port 8000 - no ng serve needed then.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/frontend"

echo "==> Building frontend (takes ~1-2 min on a Pi 5)"
npm run build

echo
echo "Done: $ROOT/frontend/dist/rapi-panel/browser"
echo "Start the backend and open http://$(hostname -I | awk '{print $1}'):8000"
