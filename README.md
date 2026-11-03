# PatchClosure Method

The PCG (Patch-Closure Graph) method for finding residuals of incomplete
security fixes: given only the visible materials (V1 source, the V0→V1
patch, the blocked seed reproduction, and a live V1 instance), construct
candidate inputs that still trigger the original effect, and verify each one
on the live instance. The canary token is parsed from the live response at
runtime — nothing is ever hardcoded.

## Pipeline (EXTRACT → BUILD → EXECUTE → VALIDATE)

The deterministic core implements the paper's four stages end to end.

```
EXTRACT   P  fold the seed PoC → concrete request, dangerous spans,
             assertion literals                       (pcg_core)
          O  changed predicates, symmetric over both diff
             sides; a changed line inside a guarded branch is
             attributed UP to the nearest enclosing
             if/while/switch/ternary node             (pcg_graph, tree-sitter)
          D  call graph + dispatch points (call site paired
             with a string literal) + unique name
             resolution; frozen CodeQL suite for
             function-level anchors, 10-min DB budget (pcg_graph,
                                                       tree-sitter + CodeQL)
BUILD     the Patch-Closure Graph: language overlay (input → guard
          predicates → normalizers → sink) + coverage overlay (duty ψ,
          carriers, shares-duty edges); every edge carries a provenance tag
          (tool-derived | model-proposed | hypothesized); machine-checked
          accounting counts tool-derived edges only. Serialized to
          work/pcg_graph.json with a content hash.
EXECUTE   the matched pattern's strategy (below)
VALIDATE  every surviving candidate on live V1; solved only when the
          marker appears AND the witness names the changed predicate it
          bypasses — a marker without a nameable predicate is recorded
          effect-only (counted separately). The replay artifact carries
          no session state.
```

## Strategies (per incompleteness pattern)

**B — encoding residuals.** Three tiers, each provenance-tagged:
1. *Registered families* — a frozen table of 15 encoding families
   (percent-single/double/u, case-fold, dot-inner, dot-slash-prefix,
   slash-dot-swap, overlong-UTF-8, null-suffix, HTML-entity, second-byte,
   tab-newline, userinfo, leading-control, leading-control-enc) with a
   manifest hash shipped per chain. Ranking principle: minimal perturbation —
   a single character of the smallest span first, whole-string variants last.
2. *Source-derived sentinels* — guard comparison constants and decoder
   literals from the delivered source, re-encoded the ways consumers decode.
3. *Model-proposed variants* — `work/model_variants.json`; each proposal
   gets a single live attempt and never enters machine-checked accounting.
Two bounded operators complete the tier-1 construction:
* *Slot migration* — re-attaches the dangerous span to one other RFC 3986
  component (host, userinfo, query, path) in that fixed order.
* *Guard follower* — fires only under strict polarity (the guard's
  rejecting branch must be a throw/raise/preregistered error return) and
  defeats the guard's own normalization: inputs its replace chain rewrites
  INTO the blocked form (`....//` for a `replace('../','')` guard), bounded
  to ≤8 candidates, simulated under both first-occurrence and global
  replace semantics before emission.

**A — coverage residuals (sibling replay).** Candidates come from dispatch
points of the call graph. Admission is machine-checked under four
conditions: the literal sits in a dispatch position (route value or
dynamic-lookup argument); the handler short name resolves to exactly one
project symbol; one-to-many matches are dropped; the budget holds (K=8
siblings, ≤10 live references). Admitted siblings are ranked by overlap
with the seed's literals descending, steps-to-sink ascending, file+line
tiebreak; the seed's credentials are replayed at each until the effect
appears. Model-proposed siblings (`work/model_siblings.json`) pass the same
conditions or stay hypothesized and are never executed.

**C — tails.** Resource exhaustion: candidates at increasing lengths beside
a benign control, with a watchdog that withholds the flag until health
checks fail. Timing/re-resolution: concurrent requests beside a
no-concurrency control, replayed until the effect appears.

`--strategy auto` (default) runs B → A → C(cue-gated) within budget;
`closure-within-bound` means the search bound was reached, never a proof
of completeness.

## Budgets (preregistered)

N=4 probes, 30-second probe timeout, K=8 siblings, at most ten references
per chain. `--probes` above N is an extended budget recorded as
`budget_mode: extended` in the ledger. CodeQL database build capped at ten
minutes per chain (`PCG_CODEQL_BUDGET`, default 240s; `PCG_CODEQL=0` skips).

## Hard-won execution rules baked into the core

* **Minimal perturbation is per-token, not per-string.** Consumers decode
  per token; whole-string re-encoding destroys the request.
* **Echo-proof hit rule.** A label-shaped string sent by the constructor
  can come back echoed in an error page. A hit requires a server-planted
  token (non-label mode) or a Location-header carry (label mode).
* **Settle passes.** Deployment artifacts can lag HTTP warm-up; the plan is
  re-fired on a graded schedule within budget.
* **No-redirect probing.** For redirect classes the effect channel is the
  30x hop itself; the probe client must not follow it.
* **Seed shape tolerance.** Nested candidate dicts are flattened
  (query/body/form → addressable slots, POST bodies sent as JSON); the
  seed's `__main__` self-test block is suppressed; imports the sandbox
  cannot satisfy are stubbed — `candidate()` itself is declarative.

## Two arms, one representation

**1. Deterministic core (`pcg_method/pcg_core.py` + `pcg_graph.py`) — zero
LLM.** Everything above. Writes `residual_test.py` into the package on a
hit and always writes `work/pcg_core_ledger.json` (per-probe provenance:
family, origin, value, hit; graph manifest and accounting) and
`work/pcg_graph.json`.

**2. Model-guided agent (`runner/contestants/pcg*.sh`) — understanding
where statics stop.** A deterministic pre-analysis (`build_guide.py`, also
zero LLM: guard facts with file:line, guard-implementation lookup, route
map, sibling candidates, check-then-use facts, seed anatomy, plus a
read-only endpoint-surface probe via `probe_endpoints.py`) is handed to one
agent run that executes the plan. The agent can feed the core's model tiers
(`work/model_edges.json`, `work/model_siblings.json`,
`work/model_variants.json`); every proposal passes the machine-checked
conditions or stays hypothesized. Prompts are vocabulary-neutral; the
opencode variant carries the delivery disciplines (cold-room self-check, no
placeholder tokens, flakiness retry loops), the cursor variant stays
minimal for safety-gate compatibility (`neutralize_guide.py` is the
belt-and-suspenders vocabulary pass).

Division of labor: single-shot encodable residuals and dispatch-adjacent
siblings go to the static core; effects gated behind session/login chains
or deep source understanding go to the agent arm.

## Usage

```bash
# full pipeline against a runner contestant package
python3 pcg_method/pcg_core.py <package_dir> --probes 32

# EXTRACT+BUILD only (no live probing; useful for CI)
python3 pcg_method/pcg_core.py <package_dir> --dry-run

# via the runner (deploy → package → invoke → score → archive)
runner/run.sh PCBV2-XXXX pcg-static --budget 30
```
