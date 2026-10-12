#!/usr/bin/env bash
# Install project dependencies (backend venv + frontend node_modules).
# Touches no system configuration - that is scripts/install-service.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> Checking requirements"
command -v python3 >/dev/null || { echo "python3 missing"; exit 1; }
command -v npm     >/dev/null || { echo "npm missing (apt install nodejs npm)"; exit 1; }
command -v suricata >/dev/null || echo "WARNING: suricata missing - apt install suricata"
# Optional: without it the panel works, the alert map just stays empty. Take the
# backports build - the one in trixie/main is a 2019 snapshot of the data.
[[ -f /usr/share/GeoIP/GeoIP.dat ]] \
  || echo "WARNING: no geo database - the alert map will be empty" \
     "(apt install -t trixie-backports geoip-database)"

echo "==> Backend: venv + dependencies"
[[ -d backend/.venv ]] || python3 -m venv backend/.venv
backend/.venv/bin/pip install -q --upgrade pip
backend/.venv/bin/pip install -q -r backend/requirements.txt

echo "==> Frontend: npm ci"
(cd frontend && npm ci --no-audit --no-fund)

echo "==> Data directory"
mkdir -p data

echo
echo "Done. Dev mode:   scripts/dev.sh"
echo "Production:       scripts/build.sh && scripts/install-service.sh"
