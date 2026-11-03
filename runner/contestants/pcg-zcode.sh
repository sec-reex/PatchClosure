#!/usr/bin/env bash
# PCG-guided contestant (ZCode CLI executor, start-plan GLM). Same deterministic
# pre-analysis as the other PCG adapters (pcg_method/build_guide.py); execution
# via the ZCode CLI headless runner.
ZCODE_CLI="/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs"
run_contestant() {
  # HARD GUARD: the zcode.cjs headless path resolves to the ACCOUNT default
  # model (GLM-5.3), not the desktop session model (GLM-5.3-Flash), and the
  # CLI has no --model flag to pin it. Until a pinning mechanism exists,
  # refuse to run so it cannot silently burn non-Flash quota.
  # Override with PCGZ_ALLOW_UNPINNED=1 only if you accept GLM-5.3 spend.
  if [ "${PCGZ_ALLOW_UNPINNED:-0}" != "1" ]; then
    echo "pcg-zcode: BLOCKED - headless zcode.cjs cannot pin GLM-5.3-Flash (see adapter guard)" >&2
    return 75
  fi
  local pkg="$1" budget="$2"
  local REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  cd "$pkg"
  # Block Docker/container CLIs: hide the real binaries from PATH
  local _sandbox="/tmp/_pcgz_sandbox_$$"
  mkdir -p "$_sandbox"
  for cmd in docker podman nerdctl orb docker-compose; do
    printf '#!/bin/sh\necho "BLOCKED: %s is not allowed in this sandbox" >&2\nexit 126\n' "$cmd" > "$_sandbox/$cmd"
    chmod +x "$_sandbox/$cmd"
  done
  export DOCKER_HOST="tcp://127.0.0.1:0"
  export PATH="$_sandbox:$HOME/.nvm/versions/node/v26.7.0/bin:$PATH"

  # Deterministic pre-analysis; never blocks the run on failure
  python3 "$REPO/pcg_method/build_guide.py" "$pkg" \
    || echo "pcg-zcode: guide build failed (continuing without guide)" >&2
  # deterministic readout-surface index (where can a planted value surface)
  python3 "$REPO/pcg_method/semantic_map.py" "$pkg" || true
  # plant facts: storage/page carrying the per-run marker (given materials)
  local CID="$(basename "$(dirname "$pkg")")"
  python3 "$REPO/pcg_method/plant_facts.py" "$REPO/benchmark/cases/$CID" "$pkg" || true
  # read-only endpoint surface map (live V1 is a given material)
  python3 "$REPO/pcg_method/probe_endpoints.py" "$pkg" || true

  local PFILE="/tmp/pcgz_prompt_${RANDOM}.md"
  {
    cat "$REPO/pcg_method/agent_prompt.md"
    printf '\n---\n\nThe task description and deliverable rules are in task.md in this directory. Read it now.\n'
  } > "$PFILE"

  timeout --kill-after=30 "${budget}m" "$ZCODE_CLI" \
    -p "$(cat "$PFILE")" \
    --cwd "$pkg" \
    --mode yolo \
    --verbose --json \
    --disallowed-tools "WebFetch,WebSearch"
  local rc=$?
  rm -f "$PFILE"
  rm -rf "$_sandbox"
  return $rc
}
