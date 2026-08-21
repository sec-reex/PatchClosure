"""Fit the smallest FST consistent with measured pairs.

Regular-within-k only if the fitted transducer reproduces every
observed pair and a held-out share. Inversion is exact relative to
that measured model; otherwise discharge falls to enumeration.
"""
from __future__ import annotations

from collections import defaultdict


def fit(pairs: list[tuple[str, str]], holdout: float = 0.2) -> dict:
    if len(pairs) < 4:
        return {"regular": False, "reason": "too few pairs", "pairs": len(pairs)}
    hold_n = max(1, int(len(pairs) * holdout))
    train, test = pairs[:-hold_n], pairs[-hold_n:]
    model = _fit_prefix_tree(train)
    if model is None:
        return {"regular": False, "reason": "no deterministic FST", "pairs": len(pairs)}
    if not all(_run(model, inp) == out for inp, out in train):
        return {"regular": False, "reason": "train mismatch", "pairs": len(pairs)}
    if not all(_run(model, inp) == out for inp, out in test):
        return {"regular": False, "reason": "held-out mismatch", "pairs": len(pairs)}
    return {
        "regular": True,
        "kind": model["kind"],
        "n_states": model.get("n_states"),
        "pairs": len(pairs),
        "model": model,
    }


def invert(model: dict, danger, alphabet: list[str], kmax: int = 8, cap: int = 20) -> list[str]:
    """BFS over the fitted FST for inputs whose output is dangerous."""
    if not model or not model.get("regular"):
        return []
    kind = (model.get("model") or {}).get("kind") or model.get("kind")
    spec = model.get("model") or model
    hits = []
    if kind == "identity":
        # any string in L_S; caller still intersects L_G by execution
        return []
    if kind == "percent_decode":
        from urllib.parse import unquote

        seeds = [tok for tok in alphabet if "%" in tok or tok in "/.\\"]
        from itertools import product

        for n in range(1, min(kmax, 4) + 1):
            for tup in product(seeds or alphabet[:8], repeat=n):
                x = "".join(tup)
                try:
                    y = unquote(_u_decode(x))
                except Exception:
                    continue
                try:
                    if danger(y):
                        hits.append(x)
                except Exception:
                    continue
                if len(hits) >= cap:
                    return hits
        return hits
    if kind == "char_map":
        inv = _invert_map(spec.get("mapping") or {})
        # emit mappings of a dangerous char if we know one
        for ch, alts in inv.items():
            hits.extend(alts[:3])
        return hits[:cap]
    return hits


def _u_decode(x: str) -> str:
    import re

    def repl(m):
        return chr(int(m.group(1), 16))

    return re.sub(r"%u([0-9A-Fa-f]{4})", repl, x)


def _fit_prefix_tree(pairs: list[tuple[str, str]]) -> dict | None:
    if all(a == b for a, b in pairs):
        return {"kind": "identity", "n_states": 1}
    from urllib.parse import unquote

    if all(_safe_unquote(a) == b for a, b in pairs):
        return {"kind": "percent_decode", "n_states": 2}
    mapping: dict[str, str] = {}
    ok = True
    for inp, out in pairs:
        if len(inp) != len(out):
            ok = False
            break
        for a, b in zip(inp, out):
            if a in mapping and mapping[a] != b:
                ok = False
                break
            mapping[a] = b
        if not ok:
            break
    if ok and mapping:
        return {"kind": "char_map", "mapping": mapping, "n_states": len(mapping) + 1}
    # Deterministic prefix-tree: each input prefix -> output so far
    trans = defaultdict(dict)  # state -> char -> (next, emit)
    states = {"": 0}
    for inp, out in pairs:
        pref = ""
        acc = ""
        # align greedily: emit remaining output on last char
        if not inp:
            continue
        for i, ch in enumerate(inp):
            nxt = pref + ch
            emit = ""
            if i == len(inp) - 1:
                emit = out[len(acc):]
            elif len(out) > len(acc) and out.startswith(acc):
                # emit one char if it stays a prefix of out
                if out[len(acc):len(acc) + 1]:
                    emit = out[len(acc)]
            src = states.setdefault(pref, len(states))
            dst = states.setdefault(nxt, len(states))
            prev = trans[src].get(ch)
            if prev and prev != (dst, emit):
                return None
            trans[src][ch] = (dst, emit)
            acc += emit
            pref = nxt
        if acc != out:
            return None
    return {"kind": "prefix_tree", "trans": {str(k): v for k, v in trans.items()}, "n_states": len(states)}


def _safe_unquote(x: str) -> str:
    from urllib.parse import unquote

    return unquote(_u_decode(x))


def _run(model: dict, inp: str) -> str | None:
    kind = model["kind"]
    if kind == "identity":
        return inp
    if kind == "percent_decode":
        return _safe_unquote(inp)
    if kind == "char_map":
        return "".join(model["mapping"].get(ch, ch) for ch in inp)
    if kind == "prefix_tree":
        state = 0
        out = []
        trans = {int(k): v for k, v in model["trans"].items()}
        for ch in inp:
            step = (trans.get(state) or {}).get(ch)
            if not step:
                return None
            state, emit = step
            out.append(emit)
        return "".join(out)
    return None


def _invert_map(mapping: dict[str, str]) -> dict[str, list[str]]:
    inv = defaultdict(list)
    for a, b in mapping.items():
        inv[b].append(a)
    return inv
