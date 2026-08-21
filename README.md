# PatchClosure

Method that accompanies the NDSS 2027 submission
*PatchClosure: Residual Exploit Discovery in Incomplete Web Security Patches*.

Given a first-fixed product `V1`, the official first-fix diff, the seed
that `V1` now blocks, and two live endpoints, PatchClosure searches for a
**residual**: another input under the seed's attacker model that still
produces the registered effect on `V1`.

A later complete fix `V2` is not an input. Held-out residual PoCs and
operator notes are not inputs.

## What the method is allowed to see

The benchmark controller stages a workspace:

```text
workspace/
  v0/                 # unpatched source (when fetch produced a tree)
  v1/                 # first-patched source
  patch_real.diff     # official first fix for the seed
  exp/                # seed only (original_poc, seed_exec)
```

It does **not** copy residual PoCs, `verify.sh --residual`, or the
per-case operator README. Do not put those files into `work/` yourself.

Do **not** copy twenty full product trees into this repository. Fetch is
JIT: stage the diff and seed, then fetch `v0`/`v1` only for the cases
you are about to analyze, and delete the trees afterwards.

## Pipeline

Matches the paper Implementation section:

1. **BUILD** — diff overlay via tree-sitter plus LLM nominations, then
   Joern CPG (CodeQL on JS/Python/Go/Ruby) on a small source tree to
   drop or retarget symbols that are not on the attacker→sink flow;
   slice and execute `φ` (up to 256 branch probes); fit an FST. Set
   `PATCHCLOSURE_JOERN=0` / `PATCHCLOSURE_CODEQL=0` to skip a frontend.
2. **MATCH** — language gap vs obligation gap vs unclear.
3. **DISPATCH** — Z3 on the decidable string fragment, else enumeration
   over `Σ_φ` (`k=64`); Semgrep taint + `IssueIdentity` for siblings
   found in the product tree (not in `seed_exec.py` branch names).
4. **VALIDATE** — one generic checker per Table 1 effect channel.
   The LLM never decides that a residual succeeded.

Offline search is a **candidate generator**. Transcriptions of
`(admits, φ, danger)` are ensembled (`N=3`): keep `x` if **any** sample
admits it; `danger` only ranks. The first live candidate that produces
the registered effect (`PCBFLAG_*` on the effect channel) is the residual.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Optional: `pip install z3-solver semgrep`. Joern lives in `JOERN_HOME`
(default `~/joern/joern-cli`) and needs Java 17+. CodeQL is the
dataflow frontend for JavaScript / Python / Go / Ruby
(`brew install --cask codeql`; packs under `~/.codeql/packages`).

LLM (OpenAI-compatible):

```bash
export PATCHCLOSURE_LLM_BASE_URL=https://api.deepseek.com
export PATCHCLOSURE_LLM_API_KEY=...
export PATCHCLOSURE_LLM_MODEL=deepseek-chat
```

Benchmark controller (default `http://127.0.0.1:8787`):

```bash
export PCB_PLATFORM_URL=http://127.0.0.1:8787
export PCB_BENCHMARK_ROOT=/path/to/PatchClosure-benchmark
```

## Commands

```bash
# Copy diff + seed for the 20-case analysis list (no source trees).
python -m patchclosure stage

# Then fetch v0/v1 only for the cases you will analyze:
python -m patchclosure stage --cases PCBV2-0009,PCBV2-0029,PCBV2-0148 --fetch

# Offline BUILD → MATCH → DISPATCH (writes candidates.json).
python -m patchclosure analyze work/PCBV2-0029 --out out/PCBV2-0029.json

# Fire ranked candidates at a live V1 (seed_exec transport).
python -m patchclosure fire work/PCBV2-0029 --v1-base http://127.0.0.1:PORT

# Full session against a running controller.
python -m patchclosure session --case PCBV2-0029

# Interpreter / preimage unit checks (no LLM, no Docker).
python -m patchclosure selftest
```

## Worked examples

Both paper families have a live residual on V1 (controller + Docker,
answer-blind). Transcripts stay in `out/` and are gitignored — they
contain per-run `PCBFLAG_*` tokens.

| Family | Case | What discharged |
|---|---|---|
| language | PCBV2-0148 | radix encodings of an IP that already appears in the seed |
| language | PCBV2-0029 | Z3 on the overlay `\\r\\n` guard; lone CR |
| language | PCBV2-0154 | start-anchor (`^` in the guard) using an IP already in the seed |
| obligation | PCBV2-0016 | `IssueIdentity`: same CRLF tail, path field → host field |

`seed_exec.py` is the live probe only. Its `if op == ...` branches are
not a sibling catalog.

## Layout

```text
patchclosure/     pipeline (BUILD / MATCH / DISPATCH / VALIDATE)
configs/          operator case lists (not method inputs)
docs/             method and workspace contract
work/             gitignored staged workspaces
out/              gitignored live transcripts (flags)
```

## License

MIT. Product source fetched into `work/` stays under its upstream license.
