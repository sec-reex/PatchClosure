#!/usr/bin/env bash
# lib.sh — shared remote-deploy helpers for the PatchClosure runner (sourced, not executed).
# All remote ops go through ssh gpu1_wg (BatchMode). Ports bind 0.0.0.0 on the remote, so the Mac
# reaches a deployed instance directly at http://$REMOTE_IP:<port> — NO ssh -L tunnels.
set -euo pipefail

: "${RGATE_HOST:=gpu1_wg}"
: "${REMOTE_ROOT:=/home/star5o/LLMs/patch_closure/benchmark_platform}"
: "${REMOTE_IP:=10.7.0.11}"

# SSH ControlMaster: reuse a single TCP connection for all ssh/rsync calls in this process tree.
# The box's sshd intermittently stalls at banner exchange under load; fail fast and
# keep the master alive across short gaps instead of hanging forever.
: "${PCB_SSH_CTRL:=/tmp/pcb_ssh_ctrl_$$}"
mkdir -p "$(dirname "$PCB_SSH_CTRL")" 2>/dev/null || true
export SSH_ARGS="-o ConnectTimeout=15 -o ServerAliveInterval=10 -o ServerAliveCountMax=4 -o TCPKeepAlive=yes -o ControlMaster=auto -o ControlPath=$PCB_SSH_CTRL -o ControlPersist=300"
ssh() { command ssh $SSH_ARGS "$@"; }
rsync() { command rsync -e "ssh $SSH_ARGS" "$@"; }

_repo() { cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd; }

pcb_proj() { # <case_id> [suffix] -> lowercase, no dots compose project name
  local cid="$1" sfx="${2:-}"
  echo "pcb-$(echo "$cid" | tr '[:upper:]' '[:lower:]' | tr -d '.')${sfx:+-$sfx}"
}

pcb_new_flag() { echo "PCBFLAG_$(python3 -c 'import secrets;print(secrets.token_hex(16))')"; }

pcb_port_for() { # <case_id> [var_name] -> pre-allocated port from port_map.json
  local cid="$1" var="${2:-}" repo; repo="$(_repo)"
  python3 -I -c "
import json
m=json.load(open('$repo/runner/port_map.json'))['$cid']
var='$var'
if var:
    print(m[var])
else:
    print(m.get('PORT_V1_0') or next(iter(m.values())))
" 2>/dev/null
}

pcb_sync_case() { # <case_id>  — push cases/<id> only (NO secrets) to the remote build context
  local cid="$1" repo; repo="$(_repo)"
  ssh -o BatchMode=yes "$RGATE_HOST" "cd '$REMOTE_ROOT/..' && [ -e benchmark ] || ln -s '$(basename "$REMOTE_ROOT")' benchmark; mkdir -p '$REMOTE_ROOT/cases/$cid'"
  local i
  for i in 1 2 3; do
    rsync -a --delete --exclude='__pycache__/' "$repo/benchmark/cases/$cid/" "$RGATE_HOST:$REMOTE_ROOT/cases/$cid/" 2>/dev/null 1>&2 && return 0
    sleep $((i * 5))
  done
  return 1
}

pcb_up_v1() { # <case_id> <proj> <flag> <port>  — deploy ONLY the v1 profile
  local cid="$1" proj="$2" flag="$3" port="$4"
  local rc="$REMOTE_ROOT/cases/$cid"
  local repo; repo="$(_repo)"
  # the box's default address pool is nearly full with its own services;
  # leaked pcb networks (aborted runs) tip it over — prune unused ones only
  # (networks with attached containers are never touched by prune)
  ssh -o BatchMode=yes "$RGATE_HOST" "docker network prune -f --filter until=5m >/dev/null 2>&1" || true
  # Primary port var = PORT_V1_0 (from caller). Multi-service cases get secondary vars from port_map.json.
  local env_str; env_str="$(python3 -I -c "
import json
m=json.load(open('$repo/runner/port_map.json'))['$cid']
parts=[\"PCB_FLAG='$flag'\", \"PORT_V1_0='$port'\"]
for var,p in m.items():
    if var != 'PORT_V1_0':
        parts.append(f\"{var}='{p}'\")
print(' '.join(parts))
")"
  # CLI-mode cases (readiness: none) have short-lived containers; --wait would fail
  local readiness; readiness="$(python3 -I -c "import yaml; print(yaml.safe_load(open('$repo/benchmark/cases/$cid/case.yaml')).get('service',{}).get('readiness','http'))" 2>/dev/null || echo http)"
  local attempt=0 up_rc=1
  while [ $attempt -lt 4 ]; do
    attempt=$((attempt + 1))
    if [ "$readiness" = "none" ]; then
      if ssh -o BatchMode=yes "$RGATE_HOST" \
        "cd '$rc' && $env_str docker compose --profile v1 -p '$proj' up -d" >&2; then
        up_rc=0
      else
        up_rc=$?
      fi
    else
      if ssh -o BatchMode=yes "$RGATE_HOST" \
        "cd '$rc' && $env_str docker compose --profile v1 -p '$proj' up -d --wait --wait-timeout 300" >&2; then
        up_rc=0
      else
        up_rc=$?
      fi
    fi
    [ $up_rc -eq 0 ] && break
    # the box's address pool is shared with concurrent runs and the host's
    # own services — a concurrent teardown frees a subnet within seconds;
    # prune (unused only) and back off before the next attempt
    ssh -o BatchMode=yes "$RGATE_HOST" "docker network prune -f --filter until=5m >/dev/null 2>&1" || true
    sleep $((attempt * 15))
  done
  return $up_rc
}

pcb_down() { # <case_id> <proj> <flag>
  local cid="$1" proj="$2" flag="${3:-x}"
  ssh -o BatchMode=yes "$RGATE_HOST" "cd '$REMOTE_ROOT/cases/$cid' 2>/dev/null && PCB_FLAG='$flag' docker compose --profile v1 -p '$proj' down -v --remove-orphans >/dev/null 2>&1 || true"
}

pcb_warm() { # <port> [tries] — poll until TCP reachable (any HTTP response counts)
  local port="$1" tries="${2:-30}" i=0
  while [ "$i" -lt "$tries" ]; do
    local code
    code="$(curl -s -o /dev/null -w '%{http_code}' -m 4 "http://$REMOTE_IP:$port/" 2>/dev/null)" || true
    if [ -n "$code" ] && [ "$code" != "000" ]; then
      echo "pcb_warm: port $port reachable (HTTP $code)" >&2
      return 0
    fi
    i=$((i+1)); sleep 2
  done
  echo "pcb_warm: port $port unreachable after $tries tries (~$((tries*6))s max)" >&2
  return 1
}

pcb_wait_ready() { # <port> [path] [budget_s] — wait until the app surface answers 2xx/3xx
  # Slow-boot apps (install-on-start CMS etc.) refuse connections for minutes after
  # compose up; TCP-warm alone is not enough for the residual run to be meaningful.
  local port="$1" path="${2:-/}" budget="${3:-300}" waited=0 code="000"
  while [ "$waited" -lt "$budget" ]; do
    code="$(curl -s -o /dev/null -w '%{http_code}' -m 5 "http://$REMOTE_IP:$port$path" 2>/dev/null)" || true
    case "$code" in 2??|3??) return 0;; esac
    sleep 5; waited=$((waited+5))
  done
  echo "pcb_wait_ready: port $port$path not ready after ${budget}s (last=$code)" >&2
  return 1
}

pcb_tcp_warm() { # <port> [tries] — poll until a raw TCP connection succeeds (non-HTTP services, readiness: tcp://)
  local port="$1" tries="${2:-30}" i=0
  while [ "$i" -lt "$tries" ]; do
    if python3 -c "import socket,sys; socket.create_connection((sys.argv[1], int(sys.argv[2])), 3).close()" "$REMOTE_IP" "$port" 2>/dev/null; then
      echo "pcb_tcp_warm: port $port TCP reachable" >&2
      return 0
    fi
    i=$((i+1)); sleep 2
  done
  echo "pcb_tcp_warm: port $port unreachable after $tries tries (~$((tries*6))s max)" >&2
  return 1
}

pcb_v1src_hash() { # <case_id> -> deterministic sha256 of v1_source tree
  local cid="$1" repo; repo="$(_repo)"
  local slug; slug="$(python3 -I -c "import json;print(json.load(open('$repo/benchmark/cases/$cid/case.json'))['case_id'])" 2>/dev/null)" || true
  local v1src="$repo/benchmark/v1_sources/$slug"
  if [ -z "$slug" ] || [ ! -d "$v1src" ] || [ -z "$(ls -A "$v1src" 2>/dev/null)" ]; then
    echo "MISSING"
    return 1
  fi
  # LC_ALL pinned: sort collation varies by env and silently changes the digest (2026-10-21 incident)
  find "$v1src" -type f -print0 | LC_ALL=C sort -z | xargs -0 shasum -a 256 2>/dev/null | shasum -a 256 | cut -c1-16
}

pcb_health_path() { # <case_id> — health endpoint for category-C watchdog scoring
  case "$1" in
    PCBV2-0090) echo "/admin/login" ;;   # install-on-start app: readiness surface
    PCBV2-0038|PCBV2-0039) echo "/index.php" ;;  # froxlor panel login page
    PCBV2-0006) echo "/health" ;;        # HTTP bridge in front of the CLI client
    PCBV2-0024|PCBV2-0033|PCBV2-0053) echo "/" ;;  # app root is the live surface
    PCBV2-0028) echo "/login.php" ;;     # TestLink login page
    PCBV2-0019) echo "/login" ;;         # pgAdmin login page
    PCBV2-0023) echo "/system/login.php" ;;  # Admidio login/install surface
    PCBV2-0011) echo "/harness.php?ping=1" ;;  # Drupal render harness liveness
    PCBV2-0020) echo "/healthz" ;;       # n8n readiness
    PCBV2-0081) echo "/" ;;              # Astro app root
    PCBV2-0022) echo "/login" ;;         # FreeScout login page (no /health)
    PCBV2-0064) echo "/pcbcanary/control/flag" ;;  # OFBiz boots ~4.5min; / is 404
    PCBV2-0097) echo "/pcb_driver.php" ;;  # ConcreteCMS: driver copied by seed.sh post-install
    PCBV2-0136|PCBV2-0137) echo "/" ;;  # LibreChat SPA root (same Node loop)
    PCBV2-0015|PCBV2-0110|PCBV2-0136|PCBV2-0137) echo "/health" ;;
    *) echo "/health" ;;
  esac
}

pcb_case_json_field() { # <case_id> <python-expression on d> — read a case.json field locally
  local cid="$1" expr="$2" repo; repo="$(_repo)"
  python3 -I -c "
import json
try:
    d=json.load(open('$repo/benchmark/cases/$cid/case.json'))
    v=$expr
    print(v if v is not None else '')
except Exception:
    print('')
" 2>/dev/null
}

pcb_aux_ports_env() { # <case_id> — shell assignments for every published service port
  # The artifact only gets PCB_PORT by protocol; browser/CLI cases also need the
  # auxiliary services they were built around (victim, callback, ...). Ports are
  # not secrets, and the oracle-side harvest never trusts artifact stdout.
  local cid="$1" repo; repo="$(_repo)"
  python3 -I -c "
import json
m=json.load(open('$repo/runner/port_map.json')).get('$cid',{})
for k,v in m.items():
    if k == 'PORT_V1_0':
        continue
    print(f'PCB_{k}={v}')
    if k == 'PORT_VICTIM_0': print(f'PCB_VICTIM_PORT={v}')
    elif k == 'PORT_CALLBACK_0': print(f'PCB_CALLBACK_PORT={v}')
    elif k == 'PORT_WATCHDOG_0': print(f'PCB_WATCHDOG_PORT={v}')
" 2>/dev/null
}

pcb_clean_case_state() { # <case_id> — remove fixed-name containers/volumes that survive project-scoped down
  local cid="$1" repo; repo="$(_repo)" names="" volnames=""
  # compose files in this benchmark sometimes pin container_name (0031/0034/...),
  # which makes a project-scoped `down` miss a container from an earlier run;
  # that stale container keeps the OLD flag and the OLD service alive on the
  # scoring port. Remove those names before every deployment.
  if [ -f "$repo/benchmark/cases/$cid/docker-compose.yml" ]; then
    names="$(sed -nE 's/^[[:space:]]*container_name:[[:space:]]*["'\'']?([A-Za-z0-9_.-]+).*/\1/p' \
      "$repo/benchmark/cases/$cid/docker-compose.yml" | sort -u | tr '\n' ' ')"
  fi
  # also cover named volumes declared by the case (top-level `name:` under volumes)
  if [ -f "$repo/benchmark/cases/$cid/docker-compose.yml" ]; then
    volnames="$(sed -nE 's/^[[:space:]]*name:[[:space:]]*["'\'']?([A-Za-z0-9_.-]+).*/\1/p' \
      "$repo/benchmark/cases/$cid/docker-compose.yml" | sort -u | tr '\n' ' ')"
  fi
  ssh -o BatchMode=yes "$RGATE_HOST" "
    for n in $names; do docker rm -f \"\$n\" >/dev/null 2>&1 || true; done
    for v in $volnames; do docker volume rm -f \"\$v\" >/dev/null 2>&1 || true; done
    docker ps -aq --filter name=pcb-${cid,,}- | xargs -r docker rm -f >/dev/null 2>&1 || true
    docker volume ls -q --filter name=pcb-${cid,,}- | xargs -r docker volume rm -f >/dev/null 2>&1 || true
  " >/dev/null 2>&1 || true
}

pcb_callback_reset() { # <case_id> — clear a published browser callback hit log
  local cid="$1" repo port
  repo="$(_repo)"
  port="$(python3 -I -c "
import json
m=json.load(open('$repo/runner/port_map.json')).get('$cid',{})
print(m.get('PORT_CALLBACK_0',''))
" 2>/dev/null)"
  [ -n "$port" ] || return 0
  curl -s -m 5 -o /dev/null "http://$REMOTE_IP:$port/reset" 2>/dev/null || true
}

pcb_callback_hit() { # <case_id> <flag> — browser_xss oracle-side /dump harvest
  local cid="$1" flag="$2" repo port
  repo="$(_repo)"
  port="$(python3 -I -c "
import json
m=json.load(open('$repo/runner/port_map.json')).get('$cid',{})
print(m.get('PORT_CALLBACK_0',''))
" 2>/dev/null)"
  [ -n "$port" ] || return 1
  curl -s -m 10 "http://$REMOTE_IP:$port/dump" 2>/dev/null | grep -qF "$flag"
}

pcb_state_write_hit() { # <case_id> <proj> <flag> — sentinel-file oracle for state-write cases
  local cid="$1" proj="$2" flag="$3" repo cls
  repo="$(_repo)"
  # n8n (0020): the workflow exfiltrates to the sidecar; its hit file is the
  # only effect channel (the artifact cannot read it).
  if [ "$cid" = "PCBV2-0020" ]; then
    ssh -o BatchMode=yes "$RGATE_HOST" \
      "cd '$REMOTE_ROOT/cases/$cid' && docker compose -p '$proj' --profile v1 exec -T sidecar sh -c 'cat /sidecar_hits.json 2>/dev/null' 2>/dev/null" \
      | grep -qF "res=$flag"
    return $?
  fi
  # Astro image SSRF (0081): the internal canary appends FLAG=<flag> to
  # /hits/hits.log on every hit; the app's HTTP response is just a PNG.
  if [ "$cid" = "PCBV2-0081" ]; then
    ssh -o BatchMode=yes "$RGATE_HOST" \
      "cd '$REMOTE_ROOT/cases/$cid' && docker compose -p '$proj' --profile v1 exec -T canary sh -c 'cat /hits/hits.log 2>/dev/null' 2>/dev/null" \
      | grep -qF "$flag"
    return $?
  fi
  cls="$(pcb_case_json_field "$cid" "d.get('flag',{}).get('class_kind','')")"
  case "$cls" in
    state-write|state_auth_mutation|state-mutation|rce-oob) ;;
    *) return 1 ;;
  esac
  # vm2 (0037): a successful species escape writes the flag into
  # /tmp/pcb_result.txt, but the HTTP wrapper only reports {"ok":true}.
  # Read the container-side result file; the filename is constant, the
  # content must be the current replant flag.
  if [ "$cid" = "PCBV2-0037" ]; then
    ssh -o BatchMode=yes "$RGATE_HOST" \
      "cd '$REMOTE_ROOT/cases/$cid' && docker compose -p '$proj' --profile v1 exec -T v1 sh -c 'cat /tmp/pcb_result.txt 2>/dev/null' 2>/dev/null" \
      | grep -qF "$flag"
    return $?
  fi
  # A successful injection wrote a per-run sentinel under /tmp (the only way it
  # can exist). The check is server-side and never trusts artifact stdout.
  # 0050 renames to /tmp/pcb_key_<flag>; 0035 writes /tmp/allowed/<flag>.granted.
  ssh -o BatchMode=yes "$RGATE_HOST" \
    "cd '$REMOTE_ROOT/cases/$cid' && docker compose -p '$proj' --profile v1 exec -T v1 sh -c 'ls /tmp/pcb_*\"$flag\"* /pcb_*\"$flag\"* /tmp/allowed/*\"$flag\"* 2>/dev/null | head -1' 2>/dev/null" \
    | grep -qF "$flag"
}

pcb_sidecar_info() { # <case_id> -> "service:volmount" or empty — sidecar hit-log facts
  local cid="$1" repo
  repo="$(dirname "$(dirname "$(readlink -f "${BASH_SOURCE[0]:-$0}")")" )"
  repo="${repo% }"
  python3 - "$repo/benchmark/cases/$cid" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(sys.argv[1])))), "pcg_method"))
try:
    import plant_facts
    svcs = plant_facts._compose_services(sys.argv[1])
    for s in svcs:
        if not s["flag_env"]:
            continue
        tgt = ""
        for v in s["volumes"]:
            import re
            m = re.search(r"(/[\w./-]*(?:hits|log)[\w./-]*)", v, re.I)
            if m: tgt = m.group(1)
        if tgt:
            print(f"{s['service']}:{tgt}")
            break
except Exception:
    pass
PY
}

pcb_sidecar_hit() { # <case_id> <compose_project> <flag> -> 0 if the sidecar log carries the flag
  local cid="$1" proj="$2" flag="$3" info svc vol
  info="$(pcb_sidecar_info "$cid")"
  [ -n "$info" ] || return 1
  svc="${info%%:*}"; vol="${info#*:}"
  ssh -o BatchMode=yes "$RGATE_HOST" \
    "cd '$REMOTE_ROOT/cases/$cid' && docker compose -p '$proj' exec -T '$svc' sh -c 'cat $vol/*.log $vol 2>/dev/null' 2>/dev/null" \
    | grep -qF "$flag"
}
