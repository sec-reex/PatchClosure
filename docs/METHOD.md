# Method

PatchClosure searches for a residual of an incomplete first fix. The
PCG may be built with classical graphs, symbolic / concrete execution,
and an LLM agent. Candidates come only from this case's patch, seed,
and measured interpreter — not from a bypass catalog.

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

## BUILD

1. **Classical graph (optional).** Joern CPG of `V0`/`V1`, or CodeQL
   dataflow when `codeql` is on PATH. Two questions: is the nominated
   sink reachable from the attacker value, and which guard hunk is
   co-reachable with that sink.
2. **Patch overlay.** The unified diff is parsed; tree-sitter classifies
   added predicates and normalizers as guard nodes at those sites.
3. **Semantic overlay.** The LLM nominates the sink, interpreters,
   obligation, and sibling carriers. If the symbol does not exist,
   BUILD asks again with the functions that actually occur in the
   changed files. A nomination whose sink is not reachable on the
   classical graph is dropped. A co-reachable overlay symbol can
   replace a vague nomination.
4. **Ground.** tree-sitter cuts the nominated `φ`. JS/Python run
   natively; PHP/Ruby/Go/Java/Rust run in a subprocess (container
   fallback). External interpreters (libc `strtol`, WHATWG `URL`) run
   as themselves. Probes come from the slice's own literals and escape
   forms. The pairs are `φ̂`; a prefix-tree FST is fitted and checked
   on a held-out share of those pairs.

## MATCH

- Language: a string-danger sink sits downstream of a measured `φ`.
- Obligation: the patch added a duty at some sites and not others.
- Unclear: keep both discharges; the live oracle drops the misses.

## DISPATCH

No CVE-named gadget table. Every candidate must be licensed by this
case's overlay, measured `φ`, seed shape, or the live probe's own API.

Language gap: Z3 on the decidable string fragment (prefix, contains,
length, regular). If the fitted FST is not regular, or the constraint
is outside that fragment, execution-guided enumeration over `Σ_φ`
(shortest first, `k=64` bytes / `128` if the seed is already longer).
SSRF/IP guards enumerate radix / mapped spellings of addresses that
already appear in the seed.

SE-lite on this instance: string literals the guard already writes;
case and slash respellings of a scheme that already sits in the seed;
a dummy head when the guard keys on the first segment; moving a seed
map onto another bag the probe already reads.

LLM agent: given the diff, overlay, measured pairs, seed, and probe
source, propose other field values under the same attacker model.
It must reuse tokens from those inputs (plus encodings of those
tokens). The live oracle still decides.

Obligation gap: Semgrep call-site and taint queries over the product
tree, plus routes / cmd names found in that tree, and field siblings
already present on the seed (e.g. a CRLF that the patch checks on
`path` but not on `host`). Then `IssueIdentity` (replay the seed at
sibling `Y`).

`seed_exec.py` is the live transport. DISPATCH may use the parameter
names and branch values that probe already exposes as an HTTP/API
surface. Those names are not a hidden residual file and not a
global catalog. A sibling that cannot be turned into a request is
kept as static evidence and is not counted as a residual.

## VALIDATE

Issue every surviving candidate against live `V1` with the seed's
credentials. One generic checker per channel: disk file, environment /
gadget, internal sidecar, database cell, probe string, authz-gated
object, browser cookie, hang watchdog. Success is this trial's
`PCBFLAG_*` on that channel.

A candidate that never produces that effect is not a residual.
Not finding `r` is "not found within the budget", never a proof of
completeness.
