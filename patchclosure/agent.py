"""LLM + SE residual proposer. No CVE / bypass alias tables.

PCG nodes come from overlay + measured φ. Concrete mutations are either
(1) spellings/swaps of tokens that already appear in THIS patch or seed, or
(2) LLM proposals grounded in that same text. The live oracle decides.
"""
from __future__ import annotations

import re
from copy import deepcopy
from pathlib import Path

from patchclosure import llm
from patchclosure.prompts import PROPOSE


_GET = re.compile(
    r"""(?:candidate|cand)\.get\(\s*['\"](\w+)['\"]""",
)
_EQ = re.compile(r"""(\w+)\s*==\s*['\"]([^'\"]+)['\"]""")
_LIT = re.compile(
    r"""(?:===|==|!=|includes\(|startswith\(|startsWith\()\s*['\"]([^'\"]{1,64})['\"]"""
)


def field_names(seed: dict | None, probe: str = "") -> set[str]:
    names = {k for k in (seed or {}) if not str(k).startswith("_")}
    names.update(_GET.findall(probe or ""))
    return names


def probe_space(seed: dict | None, text: str, cap: int = 16) -> list[dict]:
    """Values the live probe already branches on, for keys it already reads."""
    if not seed or not text:
        return []
    keys = field_names(seed, text)
    out: list[dict] = []
    seen: set[str] = set()
    for key, name in _EQ.findall(text):
        if key not in keys or name in seen:
            continue
        if seed.get(key) == name:
            continue
        seen.add(f"{key}:{name}")
        cand = deepcopy(seed)
        cand[key] = name
        cand["_assemble"] = f"probe-space:{key}={name}"
        out.append({"x": name, "candidate": cand, "backend": "probe-space"})
        if len(out) >= cap:
            break
    return out[:cap]


def map_nest(seed: dict | None, cap: int = 8) -> list[dict]:
    """A map field may be checked only at the top level."""
    if not seed:
        return []
    out: list[dict] = []
    for key, val in seed.items():
        if not isinstance(val, dict) or not val:
            continue
        wrapped = {"x": val}
        cand = deepcopy(seed)
        cand[key] = wrapped
        cand["_assemble"] = f"map-nest:{key}"
        out.append({"x": f"nest:{key}", "candidate": cand, "backend": "map-nest"})
        flat = {f"x[{k}]": v for k, v in val.items()}
        cand2 = deepcopy(seed)
        cand2[key] = flat
        cand2["_assemble"] = f"map-nest-flat:{key}"
        out.append({"x": f"flat:{key}", "candidate": cand2, "backend": "map-nest"})
        if len(out) >= cap:
            break
    return out


def sibling_maps(seed: dict | None, probe: str = "") -> list[dict]:
    """Move a seed map onto another bag the probe already reads."""
    if not seed:
        return []
    maps = {k: v for k, v in seed.items() if isinstance(v, dict) and v}
    dests = [n for n in field_names(seed, probe) if n not in maps]
    out: list[dict] = []
    for src, val in maps.items():
        for dst in dests:
            cand = deepcopy(seed)
            cand[dst] = deepcopy(val)
            cand["_assemble"] = f"sibling-map:{src}->{dst}"
            out.append({"x": f"{src}->{dst}", "candidate": cand, "backend": "sibling-map"})
    return out[:12]


def _guard_text(guards) -> str:
    parts: list[str] = []
    for g in guards or []:
        if isinstance(g, dict):
            parts.append(str(g.get("code") or ""))
        else:
            parts.append(str(getattr(g, "code", "") or ""))
    return "\n".join(parts)


def _literals(*texts: str) -> list[str]:
    found: list[str] = []
    for text in texts:
        if not text:
            continue
        for tok in _LIT.findall(text):
            if tok not in found:
                found.append(tok)
    return found[:16]


def _spellings(tok: str) -> list[str]:
    """Case / extra-slash spellings of THIS token. No other vocabulary."""
    out: list[str] = []
    if any(ch.isalpha() for ch in tok):
        for neu in (tok.upper(), tok.lower(), tok[:1].upper() + tok[1:] if tok else tok):
            if neu and neu != tok:
                out.append(neu)
    if "://" in tok:
        extra = tok.replace("://", ":///", 1)
        if extra != tok:
            out.append(extra)
    return list(dict.fromkeys(out))


def _rewrite(val, tok: str, alt: str):
    if isinstance(val, list):
        if any(isinstance(x, str) and tok in x for x in val):
            return [x.replace(tok, alt) if isinstance(x, str) else x for x in val]
        return None
    if isinstance(val, str) and tok in val:
        return val.replace(tok, alt, 1)
    return None


def guard_token_shift(seed: dict | None, guards, diff: str = "") -> list[dict]:
    """Swap a seed token for another literal that THIS guard/diff already writes."""
    if not seed:
        return []
    lits = _literals(_guard_text(guards), diff)
    if not lits:
        return []
    out: list[dict] = []
    for key, val in seed.items():
        if key.startswith("_"):
            continue
        text = val if isinstance(val, str) else (
            ".".join(map(str, val)) if isinstance(val, list) else ""
        )
        if not text:
            continue
        present = [tok for tok in lits if tok in text or (
            isinstance(val, list) and tok in val
        )]
        for tok in present:
            alts = [m for m in lits if m != tok] + _spellings(tok)
            for alt in alts:
                neu = _rewrite(val, tok, alt)
                if neu is None or neu == val:
                    continue
                cand = deepcopy(seed)
                cand[key] = neu
                cand["_assemble"] = f"token-shift:{tok}->{alt}"
                out.append({"x": str(neu)[:80], "candidate": cand, "backend": "token-shift"})
    return out[:12]


def prefix_blocked_head(seed: dict | None, guards) -> list[dict]:
    """If THIS guard keys on the first segment, insert a dummy head from the seed."""
    if not seed:
        return []
    code = _guard_text(guards)
    if not re.search(r"\[0\]|\[1\]|pieces\[0\]|pointer\[1\]|first|startsWith|startswith", code, re.I):
        return []
    dummy = "x"
    out: list[dict] = []
    for key, val in seed.items():
        cand = deepcopy(seed)
        if isinstance(val, list) and val:
            cand[key] = [dummy] + list(val)
        elif isinstance(val, str) and val.startswith("/"):
            cand[key] = "/" + dummy + val
        elif isinstance(val, str) and "." in val:
            cand[key] = dummy + "." + val
        else:
            continue
        cand["_assemble"] = f"prefix-head:{key}"
        out.append({"x": str(cand[key])[:80], "candidate": cand, "backend": "prefix-head"})
    return out[:8]


def scheme_variants(seed: dict | None) -> list[dict]:
    """Respell a scheme that already sits in the seed (case, slash count)."""
    if not seed:
        return []
    out: list[dict] = []
    for key, val in seed.items():
        if not isinstance(val, str) or "://" not in val:
            continue
        scheme, rest = val.split("://", 1)
        for neu in (f"{scheme}:///{rest}", f"{scheme.upper()}://{rest}", f"{scheme}:///{rest.lstrip('/')}"):
            if neu == val:
                continue
            cand = deepcopy(seed)
            cand[key] = neu
            cand["_assemble"] = f"scheme:{neu[:40]}"
            out.append({"x": neu, "candidate": cand, "backend": "scheme"})
    return out[:8]


def propose(
    *,
    seed: dict | None,
    diff: str,
    guards: list,
    pairs: list | None,
    probe_text: str = "",
    cap: int = 12,
) -> list[dict]:
    if not seed:
        return []
    keys = field_names(seed, probe_text)
    structural = (
        probe_space(seed, probe_text, cap=cap)
        + map_nest(seed)
        + sibling_maps(seed, probe_text)
        + guard_token_shift(seed, guards, diff)
        + prefix_blocked_head(seed, guards)
        + scheme_variants(seed)
    )
    if not llm.available():
        return structural
    pair_s = "\n".join(f"{a!r} -> {b!r}" for a, b in (pairs or [])[:40]) or "(none)"
    guard_s = "\n".join(
        f"{getattr(g, 'path', '')}:{getattr(g, 'line', '')} {getattr(g, 'kind', '')} {getattr(g, 'code', '')}"
        if not isinstance(g, dict)
        else f"{g.get('path')}:{g.get('line')} {g.get('kind')} {g.get('code')}"
        for g in (guards or [])[:12]
    ) or "(none)"
    try:
        raw = llm.chat(
            [
                {
                    "role": "user",
                    "content": PROPOSE.format(
                        diff=(diff or "")[:7000],
                        guards=guard_s[:3000],
                        pairs=pair_s[:3000],
                        seed=str(seed)[:4000],
                        probe=(probe_text or "")[:6000],
                    ),
                }
            ],
            temperature=0.4,
            max_tokens=1800,
        )
        obj = llm.parse_json_object(raw)
    except Exception:
        return structural
    out: list[dict] = []
    for row in obj.get("candidates") or []:
        fields = row.get("fields") if isinstance(row, dict) else None
        if not isinstance(fields, dict) or not fields:
            continue
        cand = deepcopy(seed)
        changed = False
        for key, val in fields.items():
            if key.startswith("_") or key not in keys:
                continue
            if not isinstance(val, (str, int, float, bool, list, dict)):
                continue
            if cand.get(key) == val:
                continue
            cand[key] = val
            changed = True
        if not changed:
            continue
        cand["_assemble"] = f"agent:{row.get('why') or 'propose'}"
        x = next(
            (str(cand[k])[:80] for k in fields if k in cand),
            "",
        )
        out.append({"x": x, "candidate": cand, "backend": "agent"})
        if len(out) >= cap:
            break
    return structural + out


def probe_text(exp: Path | None) -> str:
    if not exp:
        return ""
    path = Path(exp) / "seed_exec.py"
    if not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""
