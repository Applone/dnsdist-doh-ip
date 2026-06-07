#!/usr/bin/env bash
# =============================================================================
# run_checks.sh — Install QA dependencies, lint with ruff, run pytest
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; }

# ── 1. Install QA dependencies ──────────────────────────────────────────────
info "Installing QA dependencies (ruff, pytest) ..."
if [ ! -d ".venv" ]; then
    uv venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
uv pip install --quiet ruff pytest
ok "QA dependencies installed."

# ── 2. Ruff lint ─────────────────────────────────────────────────────────────
echo
echo -e "${BOLD}── Ruff Lint ──${NC}"
if ruff check .; then
    ok "ruff check passed — no lint issues."
    LINT_OK=true
else
    fail "ruff check found issues (see above)."
    LINT_OK=false
fi

# ── 3. Pytest ────────────────────────────────────────────────────────────────
echo
echo -e "${BOLD}── Pytest ──${NC}"
if python3 -m pytest test_bind9_setup.py -v --tb=short; then
    ok "All tests passed."
    TEST_OK=true
else
    fail "Some tests failed (see above)."
    TEST_OK=false
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo
echo -e "${BOLD}══════════════════════════════════════${NC}"
$LINT_OK  && ok "Lint:  PASS" || fail "Lint:  FAIL"
$TEST_OK  && ok "Tests: PASS" || fail "Tests: FAIL"
echo -e "${BOLD}══════════════════════════════════════${NC}"

if $LINT_OK && $TEST_OK; then
    exit 0
else
    exit 1
fi
