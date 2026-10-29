#!/usr/bin/env bash
# PCG-guided contestant (cursor-agent executor). Same deterministic pre-analysis as pcg.sh
# (pcg_method/build_guide.py), execution via `cursor-agent -p` (grok-4.7 backend).
run_contestant() {
  local pkg="$1" budget="$2"
  local REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  cd "$pkg"
  # Block Docker/container CLIs: hide the real binaries from PATH
  local _sandbox="/tmp/_pcgc_sandbox_$$"
  mkdir -p "$_sandbox"
  for cmd in docker podman nerdctl orb docker-compose; do
    printf '#!/bin/sh\necho "BLOCKED: %s is not allowed in this sandbox" >&2\nexit 126\n' "$cmd" > "$_sandbox/$cmd"
    chmod +x "$_sandbox/$cmd"
  done
  export DOCKER_HOST="tcp://127.0.0.1:0"
  export PATH="$_sandbox:$PATH"

  # Deterministic pre-analysis in neutral mode (zero security semantics);
  # never blocks the run on failure
  python3 "$REPO/pcg_method/build_guide.py" "$pkg" --neutral \
    || echo "pcg: guide build failed (continuing without guide)" >&2
  # belt-and-suspenders vocabulary pass (idempotent)
  python3 "$REPO/pcg_method/neutralize_guide.py" "$pkg/work/pcg_guide.md" || true
  # read-only endpoint surface map (live V1 is a given material)
  python3 "$REPO/pcg_method/probe_endpoints.py" "$pkg" || true

  local PFILE="/tmp/pcgc_prompt_${RANDOM}.md"
  {
    cat "$REPO/pcg_method/agent_prompt_cursor.md"
    printf '\n---\n\nThe task description and deliverable rules are in task.md in this directory. Read it now.\n'
  } > "$PFILE"

  # Preflight: the cursor backend intermittently refuses TLS at startup; ping
  # with backoff before burning the case slot (max ~5 min).
  local ok=1
  for i in 1 2 3 4 5; do
    if echo "Reply with OK" | timeout 90 cursor-agent -p --trust 2>/dev/null | grep -q "OK"; then
      ok=0; break
    fi
    echo "pcg-cursor: preflight attempt $i failed, backing off" >&2
    sleep 60
  done
  if [ "$ok" -ne 0 ]; then
    echo "pcg-cursor: backend unreachable after preflight; aborting this slot (retryable)" >&2
    rm -f "$PFILE"; rm -rf "$_sandbox"; return 75
  fi

  timeout --kill-after=30 "${budget}m" cursor-agent -p --trust "$(cat "$PFILE")"
  local rc=$?
  rm -f "$PFILE"
  rm -rf "$_sandbox"
  return $rc
}
