# Method (paper pipeline)

This tree implements the search in the paper's Design section.

## Inputs and output

Inputs: `V0`, `V1`, the first-fix diff, the seed blocked on `V1`, and
two live endpoints for the registered effect.

Output: a residual — another input under the seed's attacker model that
still produces that effect on `V1`.

`V2` is not an input. The method is answer-blind: it must not read
held-out residual payloads or `verify.sh --residual`.

## Patch-Closure Graph

A PCG is the CFG / DDG / call graph of `V0` and `V1` plus two overlays.

Overlay nodes: value, guard, interpreter, sink, obligation, carrier.

- A **guard** `g` is the predicate the first fix added. Its accepted set
  is a language `L_G`.
- An **interpreter** `φ` is a transform (parser, decoder, normalizer).
  We do not read `φ` from source comments; we **measure** it by
  execution, yielding `φ̂` and alphabet `Σ_φ`.
- A **sink** has a string-danger language `L_S` when danger is a
  predicate on the consumed string. Effect-defined sinks (authz sibling,
  state change) have no `L_S` and are judged only by the live oracle.

A **language gap** is a value guarded by `g` that still flows through
`φ` into `L_S`:

```text
r ∈ L_G ∩ T⁻¹(L_S),   |r| ≤ k
```

An **obligation gap** is an obligation `ψ` installed at carrier `X` and
missing at a sibling carrier `Y`.

## BUILD (paper §impl)

1. **Classical graph.** Joern CPG of `V0`/`V1` (CodeQL dataflow when
   `codeql` is on PATH). Two questions: is the nominated sink reachable
   from the attacker value, and which guard hunk is co-reachable with
   that sink (Jetty: path-segment check and `decodePath` on one flow).
2. **Patch overlay.** The unified diff is parsed; tree-sitter classifies
   added predicates and normalizers as guard nodes at those sites.
3. **Semantic overlay.** The LLM nominates the sink, interpreters,
   obligation, and sibling carriers. If the symbol does not exist,
   BUILD asks again with the functions that actually occur in the
   changed files (and overlay call names from the diff). A nomination
   whose sink is not reachable on the classical graph is dropped. When
   the graph ranks a co-reachable overlay symbol (`decodePath` on the
   Jetty flow), that name replaces a vague nomination (`URI`).
4. **Ground.** tree-sitter cuts the nominated `φ`. JS/Python run
   natively; PHP/Ruby/Go/Java/Rust run in a subprocess (container
   fallback). External interpreters (libc `strtol`, WHATWG `URL`) run
   as themselves. Up to 256 probes come from the slice's own literals
   and escape forms. The pairs are `φ̂`; a prefix-tree FST is fitted
   and checked on a held-out share.

## MATCH

- Language: a string-danger sink sits downstream of a measured `φ`.
- Obligation: the patch added a duty at some sites and not others.
- Unclear: keep both discharges; the live oracle drops the misses.

## DISPATCH (paper §impl)

Language gap: Z3 on the decidable string fragment (prefix, contains,
length, regular). If the fitted FST is not regular, or the constraint
is outside that fragment, execution-guided enumeration over `Σ_φ`
(shortest first, `k=64` bytes / `128` if the seed is already longer,
200k-candidate / ten-minute budget). SSRF/IP guards still enumerate
radix encodings of internal octets.

Obligation gap: Semgrep call-site and taint queries over the product
tree, plus routes / cmd names found in that tree, and field siblings
already present on the seed (e.g. a CRLF that the patch checks on
`path` but not on `host`). Rank by attacker reachability, then
`IssueIdentity` (replay the seed at sibling `Y`). `seed_exec.py` is
the live probe only — its `if op == ...` branches are not a sibling
catalog. A sibling that cannot be turned into a request is kept as
static evidence and is not counted as a residual.

## VALIDATE (paper Table tab:plant)

Issue every surviving candidate against live `V1` with the seed's
credentials. One generic checker per channel: disk file, environment /
gadget, internal sidecar, database cell, probe string, authz-gated
object, browser cookie, hang watchdog. Success is this trial's
`PCBFLAG_*` on that channel.

A candidate that never produces that effect is not a residual.
Not finding `r` is "not found within the budget", never a proof of
completeness.
