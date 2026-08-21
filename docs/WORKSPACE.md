# Workspace contract

The method reads one directory, the same shape the benchmark controller
stages for a session.

```text
<workspace>/
  v0/                 # optional; used when the guard must be compared
  v1/                 # first-patched source (required for BUILD)
  patch_real.diff     # official first-fix for the seed
  exp/                # seed only
    original_poc.*
    seed_exec.py      # optional transport
    seed.py           # optional; some seed_exec files import this
```

## Allowed copies

From a benchmark case directory, `patchclosure stage` copies:

- `patch_real.diff` (or `patch.diff` if that is the only diff)
- files under `poc/` whose names do **not** contain `residual` or `_heldout`

It does **not** copy:

- `README.md` (operator note, CVE-pair spoilers)
- `scripts/verify.sh` (contains the residual path)
- `INCOMPLETE_FIX_ANALYSIS.md`, `STATUS.md`, `reports/`
- `case.yaml` (may name the residual CVE)

## Fetching source

`fetch_source.sh --version v0|v1 --dest DIR` is JIT. Full product trees
do not belong in git. Stage twenty diffs and seeds if you want a reading
set; fetch `v0`/`v1` only for the cases you are about to run, then
delete those trees.

Docker-image cases (for example Jetty) may leave `v0/` / `v1/` empty:
the running image is the source carrier. BUILD then works from the
diff plus whatever the live process exposes.

## Live endpoints

VALIDATE talks to the process the platform already started. Set
`PCB_TARGET_BASE` / `--v1-base` so `seed_exec.run_probe` hits that
host. The method must not read the raw flag from `GET /runs/{id}`.
It observes `PCBFLAG_*` on the effect channel and, if it sees one,
submits that string as a flag.
