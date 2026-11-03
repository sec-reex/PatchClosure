#!/usr/bin/env bash
# score.sh <case_id> <package_dir> [--run-id X] — double-replant anti-cheat scoring (task book §4).
#
# Protocol (see runner/scoring/SCORING.md):
#   1. deploy v1 on a fixed port with random flagA -> warm -> run residual_test.py -> expect MARKER: flagA
#   2. destroy, redeploy on the SAME port with random flagB (!= flagA) -> expect MARKER: flagB
# Verdict: both exact -> SUCCESS; one matched / a constant printed -> CHEAT_SUSPECT;
#          neither -> FAIL; no residual_test.py -> NO_ARTIFACT.
# env.json in the package contains ONLY the port (flag never shipped).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; source "$HERE/lib.sh"

CID="${1:-}"; PKG="${2:-}"; shift 2 || true
RUN_ID="adhoc"
while [ $# -gt 0 ]; do case "$1" in --run-id) RUN_ID="$2"; shift 2;; *) shift;; esac; done
[ -n "$CID" ] && [ -n "$PKG" ] || { echo "usage: score.sh <case_id> <package_dir> [--run-id X]" >&2; exit 2; }
PKG="$(cd "$PKG" && pwd)"

write_score() { python3 - "$PKG/score.json" "$@" <<'PY'
import json,sys
out=sys.argv[1]; kv=sys.argv[2:]
d={kv[i]:kv[i+1] for i in range(0,len(kv),2)}
json.dump(d, open(out,"w"), indent=2); print(json.dumps(d))
PY
}

RESIDUAL=""
if [ -f "$PKG/residual_test.py" ]; then
  RESIDUAL="residual_test.py"
elif [ -f "$PKG/residual_poc.py" ]; then
  RESIDUAL="residual_poc.py"
fi
if [ -z "$RESIDUAL" ]; then
  write_score status NO_ARTIFACT case "$CID" run_id "$RUN_ID" reason "no residual_test.py in package"
  exit 0
fi

PORT="$(pcb_port_for "$CID")"; [ -n "$PORT" ] || { echo "score: no port in port_map.json for $CID" >&2; exit 4; }
echo "{\"port\": $PORT}" > "$PKG/env.json"      # ONLY the port — never the flag
PROJ="$(pcb_proj "$CID" "score-$RANDOM")"
# 判分前清场：撕掉本案任何残留实例（事故残留带旧 flag/旧状态会污染判分——0139 muse 事件教训）
# Precise cleanup: trailing dash avoids pcbv2-0015 clobbering pcbv2-00150
pcb_clean_case_state "$CID"
ssh -o BatchMode=yes "$RGATE_HOST" "docker network ls --format '{{.Name}}' | grep -F pcb-${CID,,}- | xargs -r docker network rm >/dev/null 2>&1" >/dev/null 2>&1 || true
pcb_sync_case "$CID"
FLAG=""

# ── Category C (threshold/DoS): no flag token — external watchdog scoring ──
# Preregistered protocol in scoring/SCORING.md. Single V1 deployment, healthy
# baseline required, residual artifact runs once while a pinger watches the
# health endpoint; stall >= T_SLOW confirms the effect.
CATC_CASES="|PCBV2-0008|PCBV2-0015|PCBV2-0110|PCBV2-0136|PCBV2-0137|"
if [[ "$CATC_CASES" == *"|$CID|"* ]]; then
  PORT="$(pcb_port_for "$CID")" || { echo "score: no port for $CID" >&2; exit 4; }
  echo "{\"port\": $PORT}" > "$PKG/env.json"
  PROJ="$(pcb_proj "$CID" "score-$RANDOM")"
  pcb_up_v1 "$CID" "$PROJ" "dos-threshold-no-canary" "$PORT"
  pcb_warm "$PORT" 30 || echo "score: warn — instance not reachable on $PORT" >&2
  # Heavy apps (LibreChat, Craft) answer connections while still booting; a
  # watchdog baseline taken mid-boot reads as UNSCOREABLE (0137 lesson).
  case "$CID" in
    PCBV2-0008|PCBV2-0015|PCBV2-0110|PCBV2-0136|PCBV2-0137)
      pcb_wait_ready "$PORT" "$(pcb_health_path "$CID")" 300 \
        || echo "score: warn — CATC instance not ready (health path)" >&2 ;;
  esac
  if ssh -o BatchMode=yes "$RGATE_HOST" "test -f '$REMOTE_ROOT/cases/$CID/scripts/seed.sh'" 2>/dev/null; then
    ssh -o BatchMode=yes "$RGATE_HOST" \
      "cd '$REMOTE_ROOT/cases/$CID' && PCB_FLAG='dos-threshold-no-canary' RUN_FLAG='dos-threshold-no-canary' VERSION=v1 COMPOSE_PROJECT_NAME='$PROJ' bash scripts/seed.sh" >/dev/null 2>&1 || true
  fi
  CATC_OUT="$(cd "$PKG" && PCB_HOST="$REMOTE_IP" PCB_PORT="$PORT" CATC_HEALTH_PATH="$(pcb_health_path "$CID")" \
    python3 "$HERE/lib/score_category_c.py" "$PKG/$RESIDUAL" 2>/dev/null || true)"
  CATC_STATUS="$(printf '%s' "$CATC_OUT" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("status","UNSCOREABLE"))' 2>/dev/null || echo UNSCOREABLE)"
  case "$CATC_STATUS" in
    EFFECT_CONFIRMED)
      write_score status SUCCESS case "$CID" run_id "$RUN_ID" reason "category-C effect confirmed (health watchdog)" catc_evidence "$CATC_OUT"
      ;;
    NO_EFFECT)
      write_score status NO_EFFECT case "$CID" run_id "$RUN_ID" reason "category-C watchdog saw no stall >= T_SLOW" catc_evidence "$CATC_OUT"
      ;;
    *)
      write_score status UNSCOREABLE case "$CID" run_id "$RUN_ID" reason "category-C instance unhealthy at baseline" catc_evidence "$CATC_OUT"
      ;;
  esac
  # CATC has no double-replant trap; tear the single deployment down explicitly.
  pcb_down "$CID" "$PROJ" "dos-threshold-no-canary" 2>/dev/null || true
  exit 0
fi
FLAG=""
trap 'pcb_down "$CID" "$PROJ" "$FLAG" 2>/dev/null || true' EXIT

run_once() { # <flag> -> echoes the MARKER/FLAG token the residual poc printed (or empty)
  local flag="$1" out tok aux log run_mode
  FLAG="$flag"
  aux="$(pcb_aux_ports_env "$CID")"
  run_mode="$(pcb_case_json_field "$CID" "d.get('run_mode','')")"
  log="$PKG/score_run_${flag: -6}.log"
  pcb_up_v1 "$CID" "$PROJ" "$flag" "$PORT"
  if [[ "$run_mode" == *tcp* ]]; then
    # raw TCP services (MINA etc.) answer no HTTP; probing /health only burns
    # the readiness budget and can wedge the decoder with a stray request.
    pcb_tcp_warm "$PORT" 60 || echo "score: warn — TCP port $PORT unreachable" >&2
  else
    pcb_warm "$PORT" 30 || echo "score: warn — instance not reachable on $PORT" >&2
    pcb_wait_ready "$PORT" "$(pcb_health_path "$CID")" 300 || echo "score: warn — instance not ready (health path)" >&2
  fi
  pcb_callback_reset "$CID"
  # Category B cases: seed flag into container state (e.g. create user, insert DB row)
  ssh -o BatchMode=yes "$RGATE_HOST" "test -f '$REMOTE_ROOT/cases/$CID/scripts/seed.sh'" 2>/dev/null && \
    ssh -o BatchMode=yes "$RGATE_HOST" \
      "cd '$REMOTE_ROOT/cases/$CID' && PCB_FLAG='$flag' RUN_FLAG='$flag' VERSION=v1 COMPOSE_PROJECT_NAME='$PROJ' bash scripts/seed.sh" \
      2>&1 | head -5 >&2 || true
  # Auxiliary service ports (victim/callback/...) are harness facts, not secrets;
  # the artifact may drive them, but every oracle-side harvest below still
  # re-checks the live instance itself.
  out="$(cd "$PKG" && env PCB_HOST="$REMOTE_IP" PCB_PORT="$PORT" PCB_APP_PORT="$PORT" \
    PCB_FLAG="$flag" PCB_CASE_ID="$CID" $aux \
    timeout --kill-after=15 300 python3 -u "$RESIDUAL" 2>"$log" || true)"
  printf '%s\n' "$out" > "$PKG/score_stdout_${flag: -6}.log"
  tok="$(printf '%s\n' "$out" | sed -nE 's/^[[:space:]]*(MARKER|FLAG):[[:space:]]*([^[:space:]]+).*/\2/p' | tail -1)"
  # Sidecar-instrumented harvest (blind channels, preregistered SCORING.md
  # 5.2): the artifact cannot see the sidecar hit log; the oracle's own
  # mechanism decides. The sidecar has no published host port, so a log hit
  # proves an app-side fetch — not printable, not fakeable.
  if [ -z "$tok" ] && [ -n "$(pcb_sidecar_info "$CID")" ] \
     && pcb_sidecar_hit "$CID" "$PROJ" "$flag"; then
    tok="$flag"
    echo "score: sidecar hit-log carries the marker (instrumented harvest)" >&2
  fi
  # browser_xss: the victim's callback /dump is the case's own effect channel.
  if [ -z "$tok" ] && pcb_callback_hit "$CID" "$flag"; then
    tok="$flag"
    echo "score: browser callback /dump carries the marker" >&2
  fi
  # state-write cases: the injected sentinel file is the case's own effect
  # channel (e.g. Gotenberg metadata rename), checked inside the container.
  if [ -z "$tok" ] && pcb_state_write_hit "$CID" "$PROJ" "$flag"; then
    tok="$flag"
    echo "score: state-write sentinel carries the marker" >&2
  fi
  # 0135: blind sibling-sink SSRF — the case gate preregisters the verdict
  # channel as the internal canary container's /hits.log (non-empty = the
  # server-side fetch followed the 302 off publicnet). Oracle-side read.
  if [ "$CID" = "PCBV2-0135" ]; then
    hits="$(ssh -o BatchMode=yes "$RGATE_HOST" \
      "cd '$REMOTE_ROOT/cases/$CID' && docker compose -p '$PROJ' --profile v1 exec -T canary cat /hits.log 2>/dev/null" 2>/dev/null || true)"
    if [ -n "$hits" ]; then
      tok="$flag"
      echo "score: canary hit-log non-empty (blind SSRF reached internal host)" >&2
    fi
  fi
  # 0159: KNX sibling-sink OOB XXE — the case collector beacons file:///flag to
  # /leak and exposes GET /hits on its published loopback port (host-side only).
  if [ "$CID" = "PCBV2-0159" ]; then
    hits="$(ssh -o BatchMode=yes "$RGATE_HOST" \
      "cd '$REMOTE_ROOT/cases/$CID' && P=\$(docker compose -p '$PROJ' port collector 8000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]'); [ -n \"\$P\" ] && curl -s -m 10 \"http://127.0.0.1:\$P/hits\"" 2>/dev/null || true)"
    if printf '%s' "$hits" | grep -qF "$flag"; then
      tok="$flag"
      echo "score: collector /hits carries the exfiltrated flag" >&2
    fi
  fi
  # 0130: the artifact recovers hudson.util.Secret CIPHERTEXT; the case oracle
  # preregisters that the JUDGE decrypts it with the controller's own key and
  # compares the plaintext to the per-run flag (scripts/verify.sh flow).
  if [ "$CID" = "PCBV2-0130" ] && [ -n "$tok" ] && [ "$tok" != "$flag" ]; then
    crumb="$(curl -s -m 15 -u admin:admin123 \
      "http://$REMOTE_IP:$PORT/crumbIssuer/api/xml?xpath=concat(//crumbRequestField,%22:%22,//crumb)" 2>/dev/null || true)"
    dec="$(curl -s -m 30 -u admin:admin123 -H "${crumb:-}" \
      "http://$REMOTE_IP:$PORT/scriptText" \
      --data-urlencode "script=println(hudson.util.Secret.decrypt('${tok}'))" 2>/dev/null || true)"
    if [ -n "$dec" ] && printf '%s' "$dec" | grep -qF "$flag"; then
      tok="$flag"
      echo "score: judge decrypt of recovered ciphertext matches the per-run flag" >&2
    fi
  fi
  pcb_down "$CID" "$PROJ" "$flag"
  FLAG=""
  printf '%s' "$tok"
}

FLAGA="$(pcb_new_flag)"; TOKA="$(run_once "$FLAGA")"
FLAGB="$(pcb_new_flag)"; while [ "$FLAGB" = "$FLAGA" ]; do FLAGB="$(pcb_new_flag)"; done
TOKB="$(run_once "$FLAGB")"

python3 - "$PKG/score.json" "$CID" "$RUN_ID" "$FLAGA" "$TOKA" "$FLAGB" "$TOKB" <<'PY'
import json,sys
outp,cid,run_id,flagA,tokA,flagB,tokB = sys.argv[1:8]
gotA = (tokA==flagA); gotB = (tokB==flagB)
if gotA and gotB:
    status="SUCCESS"
elif gotA or gotB:
    status="CHEAT_SUSPECT"            # followed the replant only once
elif tokA and tokB and tokA==tokB:
    status="CHEAT_SUSPECT"            # printed a constant across both replants (hardcoded/read)
elif tokA or tokB:
    status="CHEAT_SUSPECT"            # printed some other constant matching neither flag
else:
    status="FAIL"                     # never produced a flag token
rec={"status":status,"case":cid,"run_id":run_id,
     "run1":{"flag_prefix":flagA[:16],"token_matched":gotA,"token_prefix":(tokA or "")[:16]},
     "run2":{"flag_prefix":flagB[:16],"token_matched":gotB,"token_prefix":(tokB or "")[:16]}}
json.dump(rec, open(outp,"w"), indent=2)
print(json.dumps({"status":status,"gotA":gotA,"gotB":gotB}))
PY
