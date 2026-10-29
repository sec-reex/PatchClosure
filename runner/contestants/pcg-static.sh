#!/usr/bin/env bash
# PCG static-core contestant: deterministic construction (pcg_method/pcg_core.py),
# zero LLM. Sourced by invoke.sh; defines run_contestant <pkg> <budget>.
run_contestant() {
  local pkg="$1" budget="$2"
  local REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  cd "$pkg"
  # static pre-analysis for the ledger (guide not needed by the core, but kept
  # for auditability of the run)
  python3 "$REPO/pcg_method/build_guide.py" "$pkg" >/dev/null 2>&1 || true
  # deterministic construction + live replay; writes residual_test.py on hit
  python3 "$REPO/pcg_method/pcg_core.py" "$pkg"
  return $?
}
