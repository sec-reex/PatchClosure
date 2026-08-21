from __future__ import annotations

import importlib.util
import inspect
import re
from copy import deepcopy
from pathlib import Path

PAYLOAD_KEYS = (
    "path", "to", "next", "value", "href", "host", "url", "uri",
    "filename", "file", "name", "target", "dest", "query",
    "spec", "pointer", "avatar", "path_route", "extra", "filter",
    "header_value", "payload", "template",
)
PLACEHOLDER = "__PCB_FLAG__"


def load_seed_candidate(exp_dir: Path | None) -> dict:
    if not exp_dir:
        return {}
    poc = None
    for name in ("original_poc.py", "seed.py"):
        path = exp_dir / name
        if path.is_file():
            poc = path
            break
    if poc is None:
        return {}
    spec = importlib.util.spec_from_file_location("pcb_seed_poc", poc)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    fn = getattr(mod, "candidate", None)
    if not callable(fn):
        return {}
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        params = {}
    try:
        if any(
            p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
            and p.default is inspect.Parameter.empty
            for p in params.values()
        ):
            cand = fn(PLACEHOLDER) or {}
        else:
            cand = fn() or {}
    except TypeError:
        try:
            cand = fn(PLACEHOLDER) or {}
        except Exception:
            cand = {}
    except Exception:
        cand = {}
    if isinstance(cand, dict) and "path" not in cand:
        src = poc.read_text(encoding="utf-8", errors="ignore")
        paths = re.findall(r'["\'](/[A-Za-z0-9_./%?&=-]{8,})["\']', src)
        if paths:
            cand = dict(cand)
            cand["path"] = paths[0]
    return cand if isinstance(cand, dict) else {}


def payload_key(cand: dict) -> str:
    scored: list[tuple[int, int, str]] = []
    for i, key in enumerate(PAYLOAD_KEYS):
        val = cand.get(key)
        if not isinstance(val, (str, list)):
            continue
        text = val if isinstance(val, str) else " ".join(str(x) for x in val)
        score = 0
        if any(tok in text for tok in ("\r\n", "\\", "../", "%2e", "%2E")):
            score += 2
        if key in {"to", "url", "href", "value", "filter", "header_value"}:
            score += 1
        scored.append((-score, i, key))
    if scored:
        scored.sort()
        return scored[0][2]
    for key, val in cand.items():
        if isinstance(val, str) and key not in {"probe_id", "method", "sink"}:
            return key
    return ""


def assemble_variants(seed: dict, fragment: str, *, tokens: list[str] | None = None) -> list[dict]:
    """Place a discharged fragment on the seed's payload field.

    Short witnesses (e.g. a lone CR) are spliced over tokens that already
    occur in the seed and were taken from the guard / measured φ domain.
    """
    if not seed:
        return [{"value": fragment, "probe_id": "fragment"}]
    key = payload_key(seed)
    variants = []
    seen = set()

    def add(cand: dict, how: str):
        blob = repr(sorted(cand.items()))
        if blob in seen:
            return
        seen.add(blob)
        item = deepcopy(cand)
        item["_assemble"] = how
        variants.append(item)

    if key:
        original = seed[key]
        if isinstance(original, list):
            cand = deepcopy(seed)
            cand[key] = fragment if isinstance(fragment, list) else [fragment]
            add(cand, f"replace-field:{key}")
        else:
            original = str(original)
            for tok in tokens or []:
                if tok and tok in original and str(fragment) != tok:
                    cand = deepcopy(seed)
                    cand[key] = original.replace(tok, str(fragment), 1)
                    add(cand, f"splice-token:{key}")
            if (
                fragment == original
                or original.startswith(fragment)
                or fragment.startswith(original[:8])
                or len(fragment) >= max(8, len(original) // 3)
            ):
                cand = deepcopy(seed)
                cand[key] = fragment
                add(cand, f"replace-field:{key}")
            if PLACEHOLDER in original:
                cand = deepcopy(seed)
                cand[key] = fragment
                add(cand, f"replace-keep-flag-field:{key}")
    else:
        add({"value": fragment}, "bare-value")
    return variants[:8]


def inject_flag_placeholder(cand: dict, flag: str) -> dict:
    out = deepcopy(cand)
    out.pop("_assemble", None)
    blob = json_ready(out)
    text = repr(blob)
    if PLACEHOLDER in text:
        return _rewrite(out, lambda s: s.replace(PLACEHOLDER, flag))
    return out


def _rewrite(obj, fn):
    if isinstance(obj, dict):
        return {k: _rewrite(v, fn) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_rewrite(v, fn) for v in obj]
    if isinstance(obj, str):
        return fn(obj)
    return obj


def json_ready(obj):
    if isinstance(obj, dict):
        return {k: json_ready(v) for k, v in obj.items() if not str(k).startswith("_")}
    if isinstance(obj, list):
        return [json_ready(v) for v in obj]
    return obj
