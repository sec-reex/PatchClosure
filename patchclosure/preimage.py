from __future__ import annotations

import itertools
import re
from collections.abc import Callable
from urllib.parse import unquote

from patchclosure import config
from patchclosure.alphabet import alphabet_from_interpreter


_OCTET = r"(?:0x[0-9a-f]+|0[0-7]{1,3}|[1-9]\d{0,2}|0)"
_IPV4 = re.compile(
    rf"\b(?:0x[0-9a-f]{{6,8}}|{_OCTET}(?:\.{_OCTET}){{1,3}})\b",
    re.I,
)
_IP6 = re.compile(r"\[(?:::[0-9a-fA-F:.]+)\]")


def seed_rewrites(seed: dict | None, pairs: list[tuple[str, str]] | None) -> list[dict]:
    """Other measured preimages of φ(seed-token). No pairs → nothing.

    If grounding never saw two inputs with the same output, this emits
    no candidates. It does not own a bypass catalog.
    """
    if not seed or not pairs:
        return []
    by_y: dict[str, list[str]] = {}
    for inp, out in pairs:
        if not inp:
            continue
        by_y.setdefault(str(out), []).append(inp)
    alts: dict[str, list[str]] = {}
    for _y, ins in by_y.items():
        uniq = list(dict.fromkeys(ins))
        if len(uniq) < 2:
            continue
        for w in uniq:
            alts[w] = [u for u in uniq if u != w]
    out: list[dict] = []
    seen: set[str] = set()
    from patchclosure.assemble import PAYLOAD_KEYS

    def _emit(rewritten: str, backend: str, key: str | None = None):
        mark = (key, rewritten)
        if mark in seen:
            return
        seen.add(mark)
        item = {"x": rewritten, "backend": backend}
        if key:
            cand = dict(seed)
            cand[key] = rewritten
            item["candidate"] = cand
        out.append(item)

    keys = [
        k for k in PAYLOAD_KEYS
        if isinstance(seed.get(k), str) and any(
            t in seed[k] for t in ("\\", "\r\n", "../", "%2e", "%2E")
        )
    ] or [k for k in PAYLOAD_KEYS if isinstance(seed.get(k), str)]
    for key in keys:
        text = seed.get(key)
        if not isinstance(text, str) or not text:
            continue
        for old, news in sorted(alts.items(), key=lambda kv: -len(kv[0])):
            if old not in text:
                continue
            for new in news:
                _emit(text.replace(old, new, 1), "phi-equivalent", key)
        # FST inverse the other way: a measured output that already sits
        # in the seed can be replaced by any preimage of that output.
        # Skip single alnum so we do not rewrite every "a".
        for y, ins in by_y.items():
            if not y or y.isalnum():
                continue
            if y not in text:
                continue
            for new in ins:
                if new == y:
                    continue
                _emit(text.replace(y, new, 1), "phi-inverse", key)
        # Unique 1-char erasers (space*n collapses to ' '). Boundary inserts
        # first: a leading trim is a no-op on any parser that also trims.
        erasers: list[str] = []
        for a, b in pairs or []:
            if b != "" or not a or a.isalnum():
                continue
            tok = a[0] if len(set(a)) == 1 else a
            if tok not in erasers:
                erasers.append(tok)
        erasers = erasers[:16]
        for i, ch in enumerate(text):
            if ch not in ":/\\@":
                continue
            for inp in erasers:
                _emit(text[: i + 1] + inp + text[i + 1 :], "phi-boundary", key)
        for inp in erasers[:4]:
            _emit(inp + text, "phi-eraser", key)
    return out


def ips_in_seed(seed: dict | None) -> list[str]:
    from patchclosure.assemble import PAYLOAD_KEYS
    from patchclosure.ip_enum import parse_ipv4

    found: list[str] = []
    for text in _seed_strings(seed, keys=PAYLOAD_KEYS):
        for m in list(_IPV4.finditer(text)) + list(_IP6.finditer(text)):
            tok = m.group(0)
            if "." not in tok and not tok.lower().startswith("0x") and "::" not in tok:
                continue
            if parse_ipv4(tok) and tok not in found:
                found.append(tok)
    return found


def _seed_strings(seed: dict | None, keys=None) -> list[str]:
    if not seed:
        return []
    vals: list[str] = []
    items = ((k, seed[k]) for k in keys if k in seed) if keys else seed.items()
    for _key, val in items:
        if isinstance(val, str):
            vals.append(val)
        elif isinstance(val, list):
            vals.extend(x for x in val if isinstance(x, str))
    return vals


def exec_bounded_preimage(
    admits: Callable[[str], bool],
    phi: Callable[[str], str],
    danger: Callable[[str], bool],
    *,
    alphabet: list[str] | None = None,
    kmax: int = 4,
    max_solutions: int = 12,
    budget: int | None = None,
) -> dict:
    """Bounded-complete search over Σ^{<=k}: admits(x) and danger(phi(x))."""
    if alphabet is None:
        alphabet = alphabet_from_interpreter(phi)
    budget = budget if budget is not None else min(config.ENUM_BUDGET, 60000)
    hits: list[str] = []
    tried = 0
    for k in range(0, kmax + 1):
        for combo in itertools.product(alphabet, repeat=k):
            tried += 1
            if tried > budget:
                return {
                    "alphabet": alphabet,
                    "witnesses": hits,
                    "shortest": min(hits, key=len) if hits else None,
                    "note": f"budget {budget} exhausted at k={k}",
                }
            x = "".join(combo)
            try:
                if not admits(x):
                    continue
                if danger(phi(x)):
                    hits.append(x)
                    if len(hits) >= max_solutions:
                        return {
                            "alphabet": alphabet,
                            "witnesses": hits,
                            "shortest": min(hits, key=len),
                        }
            except Exception:
                continue
        if hits:
            break
    return {
        "alphabet": alphabet,
        "witnesses": hits,
        "shortest": min(hits, key=len) if hits else None,
    }


def gen_language_candidates(samples: list[dict], *, kmax: int | None = None, cap: int | None = None) -> dict:
    """Ensemble generator: union of admits, danger only ranks."""
    kmax = kmax if kmax is not None else config.KMAX
    cap = cap if cap is not None else config.CANDIDATE_CAP
    alpha: list[str] = []
    for sample in samples:
        for tok in alphabet_from_interpreter(sample["phi"], sample["tr"].get("alphabet_hint")):
            if tok not in alpha:
                alpha.append(tok)
    scored: dict[str, tuple] = {}
    budget = 0
    for k in range(1, kmax + 1):
        for tup in itertools.product(alpha, repeat=k):
            budget += 1
            if budget > config.ENUM_BUDGET:
                break
            x = "".join(tup)
            if x in scored:
                continue
            admits_any = False
            danger_votes = 0
            phi_val = None
            for sample in samples:
                try:
                    if sample["admits"](x):
                        admits_any = True
                except Exception:
                    pass
                try:
                    y = sample["phi"](x)
                    if phi_val is None:
                        phi_val = y
                    if sample["danger"](y):
                        danger_votes += 1
                except Exception:
                    pass
            try:
                dec = unquote(x).replace("\\", "/")
                if dec != x and any(sep in dec for sep in ("/", "\r", "\n", "..")):
                    danger_votes += 1
            except Exception:
                pass
            if admits_any:
                scored[x] = (danger_votes, k, phi_val)
        if budget > config.ENUM_BUDGET:
            break
    ranked = sorted(scored.items(), key=lambda kv: (-kv[1][0], kv[1][1]))
    fragments = [
        {"x": x, "danger_votes": votes, "phi": phi_val}
        for x, (votes, _k, phi_val) in ranked[:cap]
    ]
    return {
        "alphabet": alpha,
        "n_samples": len(samples),
        "n_surviving": len(scored),
        "fragments": fragments,
        "predicates": [
            {k: s["tr"].get(k) for k in ("admits_py", "phi_py", "danger_py")}
            for s in samples
        ],
    }
