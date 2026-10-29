# PatchClosure Method

The PCG (Patch-Closure Graph) method for finding residuals of incomplete
security fixes: given only the visible materials (V1 source, the V0→V1
patch, the blocked seed reproduction, and a live V1 instance), construct
candidate inputs that still trigger the original effect, and verify each one
on the live instance. The canary token is parsed from the live response at
runtime — nothing is ever hardcoded.

## Two arms, one representation

**1. Deterministic core (`pcg_method/pcg_core.py`) — construction, zero LLM.**

```
EXTRACT                BUILD                     EXECUTE              VALIDATE
P  fold seed →         frozen registered         family/sentinel      live V1,
   concrete candidate  encoding-family table     variants applied     flag parsed
O  diff predicates  +  (15 families, manifest    to the seed's        from the
   sentinels from      hash) + source-derived    mutatable slot,      response;
   guard constants     sentinels; sibling        minimal-             artifact
D  (via build_guide)   admission (4 machine      perturbation         emitted on
                       conditions, K=8)          order, N truncation  hit
```

`python3 pcg_method/pcg_core.py <package_dir>` writes `residual_test.py`
into the package on a hit and always writes `work/pcg_core_ledger.json`
(per-probe provenance: family, origin registered/sentinel, value, hit).
Chain statuses: `no-changed-predicate`, `non-declarative-seed`,
`no-mutatable-slot`, `encoding-exhausted`, `SOLVED`. Budgets are
preregistered in the ledger (K=8, N=4, 30-second probe timeout).

Design rules baked into the core (each one is load-bearing):

* **Minimal perturbation is per-token, not per-string.** The registered
  families emit a first-critical-token variant ahead of any whole-string
  variant — consumers decode per token, so whole-string re-encoding
  destroys the request.
* **Echo-proof hit rule.** A label-shaped string sent by the constructor can
  come back echoed in an error page. A hit requires a server-planted token
  (non-label mode) or a Location-header carry (label mode).
* **Settle passes.** Deployment artifacts can lag HTTP warm-up; the core
  re-fires its plan on a graded schedule within budget.
* **No-redirect probing.** For redirect-class targets the effect channel is
  the 30x hop itself; the probe client must not follow it.

**2. Model-guided agent (`runner/contestants/pcg*.sh`) — understanding where
statics stop.** A deterministic pre-analysis (`build_guide.py`, also zero
LLM: guard facts with file:line, guard-implementation lookup, route map,
sibling candidates, check-then-use facts, seed anatomy, plus a read-only
endpoint-surface probe of the live instance via `probe_endpoints.py`) is
handed to one agent run that executes the plan. Prompts are
vocabulary-neutral; the opencode variant carries the delivery disciplines
(cold-room self-check, no placeholder tokens, flakiness retry loops), the
cursor variant stays minimal for safety-gate compatibility
(`neutralize_guide.py` is the belt-and-suspenders vocabulary pass).

Division of labor: single-shot encodable residuals go to the static core;
effects gated behind session/login chains or deep source understanding go to
the agent arm.

## Layout

```
pcg_method/
  pcg_core.py          deterministic core (registered families + sentinels,
                       admission conditions, budgets, statuses, ledger)
  build_guide.py       static pre-analysis; --neutral emits zero-security
                       vocabulary for safety-gated executors
  probe_endpoints.py   read-only endpoint-surface map of the live instance
  neutralize_guide.py  idempotent vocabulary pass
  agent_prompt*.md     executor prompts (opencode / cursor variants)
  make_smoke_pkg.py    assemble a local package fixture from a benchmark repo
runner/contestants/
  pcg-static.sh        deterministic-core adapter (for a scoring pipeline)
  pcg.sh               opencode-guided adapter
  pcg-cursor.sh        cursor-guided adapter (preflight + TLS retry)
```

## Running

Against a package assembled from a PatchClosure-format benchmark (the
package ships only v1_source, patch.diff, the sanitized seed, and the live
port):

```bash
python3 pcg_method/pcg_core.py <pkg>        # deterministic arm
python3 pcg_method/build_guide.py <pkg>     # pre-analysis for the agent arm
```

The method reads ONLY the package materials and the live instance. Held-out
answers, oracle scripts, and case metadata are never touched.
