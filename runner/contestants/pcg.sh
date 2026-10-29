#!/usr/bin/env bash
# PCG-guided contestant adapter. Sourced by invoke.sh; defines run_contestant <pkg> <budget>.
# Deterministic pre-analysis (pcg_method/build_guide.py) first, then one guided agent run
# (opencode, model fixed to deepseek-v4.1-flash via the PCG-dedicated provider config).
run_contestant() {
  local pkg="$1" budget="$2"
  local REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  cd "$pkg"
  # Block Docker/container CLIs: hide the real binaries from PATH
  local _sandbox="/tmp/_pcg_sandbox_$$"
  mkdir -p "$_sandbox"
  for cmd in docker podman nerdctl orb docker-compose; do
    printf '#!/bin/sh\necho "BLOCKED: %s is not allowed in this sandbox" >&2\nexit 126\n' "$cmd" > "$_sandbox/$cmd"
    chmod +x "$_sandbox/$cmd"
  done
  export DOCKER_HOST="tcp://127.0.0.1:0"
  export PATH="$_sandbox:$PATH"

  # Deterministic PCG pre-analysis; never blocks the run on failure
  python3 "$REPO/pcg_method/build_guide.py" "$pkg" \
    || echo "pcg: guide build failed (continuing without guide)" >&2
  python3 "$REPO/pcg_method/probe_endpoints.py" "$pkg" || true

  # Guided agent run — dedicated provider config bypasses the shared opencode-go
  # config (broken npm pin); --standalone so the env config is actually read.
  export OPENCODE_CONFIG_CONTENT="$(cat "$REPO/pcg_method/oc_pcg.json")"
  local PFILE="/tmp/pcg_prompt_${RANDOM}.md"
  {
    cat "$REPO/pcg_method/agent_prompt.md"
    printf '\n---\n\nThe task description and deliverable rules are in task.md in this directory. Read it now.\n'
  } > "$PFILE"

  timeout --kill-after=30 "${budget}m" opencode run --standalone -m ocgo/deepseek-v4.1-flash "$(cat "$PFILE")"
  local rc=$?
  rm -f "$PFILE"
  rm -rf "$_sandbox"
  return $rc
}
