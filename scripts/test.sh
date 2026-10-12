#!/usr/bin/env bash
# Run the test suite. Nothing here talks to the running panel: the backend tests
# write to a throwaway directory and the frontend tests run in a headless
# browser against stubs.
#
#   scripts/test.sh            both suites
#   scripts/test.sh backend    only the backend
#   scripts/test.sh frontend   only the frontend
#   scripts/test.sh backend tests.test_logdir       one module
#   scripts/test.sh backend tests.test_logdir.SetDirTest.test_the_directory_is_created
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WHAT="${1:-all}"
TARGET="${2:-}"
FAILED=0

run_backend() {
  echo "==> Backend"
  if [[ ! -x backend/.venv/bin/python ]]; then
    echo "No venv. Run scripts/setup.sh first." >&2
    return 1
  fi
  # A subshell rather than cd-and-cd-back. The old shape ended the function
  # with `cd "$ROOT"`, and a function's exit status is its last command: under
  # `run_backend || FAILED=1` errexit is suppressed inside the function, so a
  # failing suite did not abort it, the cd succeeded, and the function returned
  # 0. The script printed "Both suites passed" over a backend that had not even
  # imported. Here the subshell's status is the test runner's status, and
  # nothing can be appended after it that would mask one.
  (
    cd "$ROOT/backend"
    if [[ -n "$TARGET" ]]; then
      .venv/bin/python -m unittest -v "$TARGET"
    else
      .venv/bin/python -m unittest discover -s tests -t . "${VERBOSE:+-v}"
    fi
  )
}

run_frontend() {
  echo "==> Frontend"
  if [[ ! -d frontend/node_modules ]]; then
    echo "No node_modules. Run scripts/setup.sh first." >&2
    return 1
  fi
  # Karma needs a browser it can start without a display. Chromium comes from
  # the Debian repository like everything else here.
  local browser
  browser="${CHROME_BIN:-$(command -v chromium || command -v chromium-browser || true)}"
  if [[ -z "$browser" ]]; then
    echo "No chromium found (apt install chromium), skipping the frontend tests" >&2
    return 0
  fi
  # Same shape as run_backend above, and for the same reason.
  (
    cd "$ROOT/frontend"
    CHROME_BIN="$browser" npx ng test --watch=false --browsers=ChromeHeadless
  )
}

case "$WHAT" in
  backend)  run_backend ;;
  frontend) run_frontend ;;
  all)
    run_backend || FAILED=1
    echo
    run_frontend || FAILED=1
    echo
    if (( FAILED )); then
      echo "FAILED - see above"
      exit 1
    fi
    echo "Both suites passed."
    ;;
  *)
    echo "usage: $(basename "$0") [backend|frontend|all] [test-target]" >&2
    exit 2
    ;;
esac
