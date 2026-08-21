from __future__ import annotations

import importlib.util
import json
import os
import re
from pathlib import Path
from urllib.parse import unquote

from patchclosure.assemble import (
    PLACEHOLDER,
    assemble_variants,
    inject_flag_placeholder,
    json_ready,
    load_seed_candidate,
)
from patchclosure.oracle import check_channel, observe_flag

FLAG_RE = re.compile(r"PCBFLAG_[A-Za-z0-9_]+")
ATTACKER = "evil.pcb"


def load_seed_exec(path: Path):
    spec = importlib.util.spec_from_file_location("pcb_seed_exec", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def point_seed_exec(mod, base: str | None, port: int | None, port_map: dict | None = None) -> None:
    host, hp = "127.0.0.1", port
    port_map = port_map or {}
    if base:
        os.environ["PCB_TARGET_BASE"] = base
        from urllib.parse import urlparse
        parsed = urlparse(base if "://" in base else f"http://{base}")
        host = parsed.hostname or "127.0.0.1"
        hp = parsed.port or port
    nested = _nested_route_base(getattr(mod, "BASE", None))
    if nested:
        # Do not smash PCB_TARGET_PORT: _addr would then send every route to :80.
        os.environ.pop("PCB_TARGET_PORT", None)
        for route, entry in list(mod.BASE.items()):
            if not isinstance(entry, dict):
                continue
            cport = 8080 if "proxy" in str(route).lower() else 80
            mapped = port_map.get(cport) or port_map.get(str(cport)) or hp
            for ver in list(entry):
                old = entry[ver]
                if isinstance(old, (tuple, list)) and mapped:
                    entry[ver] = (host, int(mapped))
        return
    if hp:
        os.environ["PCB_TARGET_PORT"] = str(hp)
        if hasattr(mod, "BASE") and isinstance(mod.BASE, dict):
            for key in list(mod.BASE):
                val = mod.BASE[key]
                if isinstance(val, int):
                    mod.BASE[key] = int(hp)
                elif isinstance(val, str) and val.startswith("http"):
                    mod.BASE[key] = f"http://127.0.0.1:{int(hp)}"
    if host and hp and hasattr(mod, "HOSTPORT") and isinstance(mod.HOSTPORT, dict):
        for key in list(mod.HOSTPORT):
            mod.HOSTPORT[key] = (host, int(hp))


def _nested_route_base(base) -> bool:
    if not isinstance(base, dict) or not base:
        return False
    first = next(iter(base.values()))
    return isinstance(first, dict) and any(
        isinstance(v, (tuple, list)) or (isinstance(v, dict)) for v in first.values()
    )


def family_effect(result: dict, channel: str = "disk_file") -> tuple[bool, str]:
    if not isinstance(result, dict):
        result = {"raw": str(result)}
    return check_channel(channel, result, attacker=ATTACKER)


def _host_of(s: str) -> str:
    norm = s.replace("\\", "/").strip()
    match = re.match(r"[a-zA-Z][a-zA-Z0-9+.\-]*:", norm)
    if match:
        norm = norm[match.end():]
    if not norm.startswith("//"):
        return ""
    auth = re.split(r"[/?#]", norm[2:], maxsplit=1)[0]
    return auth.split("@")[-1].lower()


def _splice_tokens(extra: list[str] | None) -> list[str]:
    toks: list[str] = []
    for tok in extra or []:
        if tok and tok not in toks:
            toks.append(tok)
    return toks


def fire_candidates(
    ws_exp: Path | None,
    fragments: list[dict],
    *,
    v1_base: str | None,
    v1_port: int | None = None,
    port_map: dict | None = None,
    seed_exec_path: Path | None = None,
    max_tries: int = 80,
    channel: str = "disk_file",
    tokens: list[str] | None = None,
) -> dict:
    seed = load_seed_candidate(ws_exp)
    plant = os.environ.get("RUN_FLAG") or os.environ.get("PCB_FLAG") or ""
    if plant and seed:
        seed = inject_flag_placeholder(seed, plant)
    exec_path = seed_exec_path or (ws_exp / "seed_exec.py" if ws_exp else None)
    if not exec_path or not exec_path.is_file():
        return {"status": "no-seed-exec", "tried": 0, "residual": None}
    mod = load_seed_exec(exec_path)
    if not hasattr(mod, "run_probe"):
        return {"status": "no-run-probe", "tried": 0, "residual": None}
    point_seed_exec(mod, v1_base, v1_port, port_map=port_map)

    seed_result = None
    seed_blocked = None
    try:
        seed_cand = inject_flag_placeholder(seed, plant or PLACEHOLDER)
        seed_result = mod.run_probe(json_ready(seed_cand), version="v1")
        fired, why = family_effect(
            seed_result if isinstance(seed_result, dict) else {"raw": str(seed_result)},
            channel,
        )
        seed_blocked = not fired
    except Exception as exc:
        seed_blocked = None
        seed_result = {"error": str(exc)[:200]}

    tried = []
    residual = None
    n = 0
    for frag in fragments:
        x = frag.get("x") if isinstance(frag, dict) else str(frag)
        if plant and isinstance(x, str):
            x = x.replace(PLACEHOLDER, plant)
        ready = frag.get("candidate") if isinstance(frag, dict) else None
        if plant and isinstance(ready, dict):
            ready = inject_flag_placeholder(ready, plant)
        splice = _splice_tokens(tokens)
        variants = [ready] if isinstance(ready, dict) else assemble_variants(seed, str(x), tokens=splice)
        for cand in variants:
            if plant:
                cand = inject_flag_placeholder(cand, plant)
            n += 1
            if n > max_tries:
                break
            try:
                result = mod.run_probe(json_ready(cand), version="v1")
            except Exception as exc:
                tried.append({"x": x, "error": str(exc)[:160], "assemble": cand.get("_assemble")})
                continue
            payload = result if isinstance(result, dict) else {"raw": str(result)}
            fired, why = family_effect(payload, channel)
            flag = observe_flag(payload) if fired else None
            if fired and not flag:
                flag = observe_flag(payload)
            rec = {
                "x": x,
                "assemble": cand.get("_assemble"),
                "fired": fired,
                "why": why,
                "flag": flag,
            }
            tried.append(rec)
            if fired:
                residual = rec
                break
        if residual or n > max_tries:
            break
    return {
        "status": "ok" if residual else "not-found",
        "seed_blocked": seed_blocked,
        "seed_result": _brief(seed_result),
        "tried": len(tried),
        "attempts": tried,
        "residual": residual,
    }


def _brief(result):
    if not isinstance(result, dict):
        return {"raw": str(result)[:200]}
    keep = {k: result[k] for k in ("status", "location", "path", "error") if k in result}
    if "body" in result:
        keep["body"] = str(result["body"])[:200]
    return keep
