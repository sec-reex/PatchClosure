from __future__ import annotations

import re
from pathlib import Path

from patchclosure import diffparse, llm, overlay, source
from patchclosure.prompts import BUILD, BUILD_REFINE
from patchclosure.slice.treesitter import list_functions, locate_function
from patchclosure.workspace import Workspace


def _src_root(ws: Workspace) -> Path | None:
    return ws.v1 or ws.v0


def build_pcg(ws: Workspace) -> dict:
    """BUILD: overlay nodes from the diff + LLM nomination, then ground names."""
    diff = ws.diff_text
    files = diffparse.changed_source_files(diff)
    root = _src_root(ws)
    src_blob = source.source_blob(root, files) if root else ""
    if not src_blob and diff:
        src_blob = "\n".join(diffparse.added_lines(diff)[:200])
    pcg = None
    overlay_err = ""
    if llm.available() and (diff or src_blob):
        try:
            pcg = _nominate(diff, src_blob, ws)
            pcg = _refine_until_grounded(pcg, root, files, diff, src_blob)
        except Exception as exc:  # noqa: BLE001 — overlay-only BUILD if the model times out
            pcg = None
            overlay_err = str(exc)[:200]
    if not pcg:
        hunks = diffparse.guard_hunks(diff)
        first = hunks[0] if hunks else None
        nodes = overlay.overlay_guards(diff)
        interp_fn = "identity"
        locus = "in-product"
        skip = {"if", "return", "throw", "raise", "true", "false", "null"}
        for node in nodes:
            toks = [t for t in node.tokens if t.split(".")[-1] not in skip]
            if node.kind == "NORMALIZE" and toks:
                interp_fn = toks[0]
                if toks[0].split(".")[-1] in {"replace", "replaceAll", "toLowerCase"}:
                    locus = "stdlib"
                break
            if toks and interp_fn == "identity":
                interp_fn = toks[-1]
        pcg = {
            "guard": {
                "where": f"{nodes[0].path}:{nodes[0].line}" if nodes else (first.path if first else ""),
                "code": (nodes[0].code if nodes else "\n".join((first.added if first else [])[:12])),
                "reads": "attacker input",
                "kind": nodes[0].kind if nodes else "PREDICATE",
            },
            "sink": {"where": "", "op": "", "in_diff": False},
            "interpreter": {"fn": interp_fn, "where": "", "locus": locus},
            "gap_type": "unclear",
            "danger_target": "",
            "notes": overlay_err or "LLM unavailable; overlay + tree-sitter guard only",
        }
    pcg = ground(pcg, root, diff)
    pcg["_src_blob"] = src_blob
    pcg["_changed_files"] = files
    pcg["_src_root"] = str(root) if root else ""
    return pcg


def ground(pcg: dict, root: Path | None, diff: str) -> dict:
    notes = list(pcg.get("notes") or []) if isinstance(pcg.get("notes"), list) else []
    if isinstance(pcg.get("notes"), str) and pcg["notes"]:
        notes.append(pcg["notes"])
    interp = pcg.get("interpreter") or {}
    fn = str(interp.get("fn") or "")
    if fn and not re.match(r"^[A-Za-z_][A-Za-z0-9_.]*$", fn):
        toks = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", fn)
        skip = {"the", "and", "this", "that", "with", "from", "into", "for"}
        pick = next((t for t in toks if t.lower() not in skip), toks[0] if toks else fn)
        interp["fn"] = pick
        notes.append(f"interpreter fn reduced to {pick!r}")
    where = str(interp.get("where") or "")
    interp_file = where.split(":")[0] if where else ""
    if root and interp_file and not source.read_file(root, interp_file, limit=80):
        found = source.find_symbol_file(root, interp.get("fn", ""))
        if found:
            interp["where"] = str(found.relative_to(root))
            notes.append(f"relocated interpreter to {interp['where']}")
        else:
            notes.append(f"interpreter file {interp_file!r} not found")
    sink = pcg.get("sink") or {}
    op = str(sink.get("op") or "")
    token = op.split("(")[0].split(".")[-1].strip()
    added = "\n".join(diffparse.added_lines(diff))
    if token:
        sink["in_diff_actual"] = token in added
    pcg["interpreter"] = interp
    pcg["sink"] = sink
    pcg["ground_notes"] = notes
    return pcg


def _nominate(diff: str, src_blob: str, ws: Workspace) -> dict:
    raw = llm.chat(
        [
            {
                "role": "user",
                "content": BUILD.format(
                    diff=diff[:8000],
                    src=src_blob[:22000],
                    seed=ws.seed_text()[:4000] or "(no seed file)",
                ),
            }
        ],
        max_tokens=2000,
    )
    return llm.parse_json_object(raw)


def _fn_candidates(pcg: dict, diff: str) -> list[str]:
    names: list[str] = []
    fn = str((pcg.get("interpreter") or {}).get("fn") or "")
    if fn:
        names.append(fn)
    added = "\n".join(diffparse.added_lines(diff))
    for tok in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\s*\(", added):
        if tok[0].islower() or tok[:1].isupper():
            if tok not in names and tok[0].islower():
                names.append(tok)
    return names


def _groundable(root: Path | None, pcg: dict, diff: str) -> tuple[bool, str]:
    interp = pcg.get("interpreter") or {}
    locus = str(interp.get("locus") or "in-product")
    fn = str(interp.get("fn") or "")
    if locus in {"stdlib", "external"} and root:
        alts = _fn_candidates(pcg, diff)
        prefer = [n for n in alts if re.search(r"decodePath|urlDecode|unquote", n, re.I)]
        for alt in prefer:
            if locate_function(root, alt):
                interp["fn"] = alt
                interp["locus"] = "in-product"
                pcg["interpreter"] = interp
                notes = list(pcg.get("notes") or []) if isinstance(pcg.get("notes"), list) else []
                notes.append(f"overrode {locus} nomination with in-product {alt!r}")
                pcg["notes"] = notes
                return True, ""
        return True, ""
    if locus in {"stdlib", "external"}:
        return True, ""
    if not root:
        return False, "no source tree"
    alts = _fn_candidates(pcg, diff)
    prefer = [n for n in alts if re.search(r"decodePath|unquote|decodeURI|urlDecode", n, re.I)]
    if not prefer:
        prefer = [n for n in alts if re.search(r"^decode", n, re.I)]
    for alt in prefer + [fn] + [n for n in alts if n not in prefer and n != fn]:
        if not alt:
            continue
        if locate_function(root, alt):
            if alt != fn:
                interp["fn"] = alt
                pcg["interpreter"] = interp
                notes = list(pcg.get("notes") or []) if isinstance(pcg.get("notes"), list) else []
                notes.append(f"interpreter fn retargeted to existing {alt!r}")
                pcg["notes"] = notes
            return True, ""
    return False, f"symbol {fn!r} not found"


def _refine_until_grounded(pcg: dict, root: Path | None, files: list[str], diff: str, src_blob: str) -> dict:
    ok, err = _groundable(root, pcg, diff)
    if ok or not llm.available():
        return pcg
    symbols = list_functions(root, files) if root else []
    if not symbols and root:
        symbols = list_functions(root, None)
    prev = pcg
    for _round in range(2):
        try:
            raw = llm.chat(
                [
                    {
                        "role": "user",
                        "content": BUILD_REFINE.format(
                            error=err,
                            symbols=", ".join(symbols[:40]) or "(none listed)",
                            prev=str(prev)[:3000],
                            diff=diff[:6000],
                            src=src_blob[:12000],
                        ),
                    }
                ],
                max_tokens=1600,
            )
            nxt = llm.parse_json_object(raw)
        except Exception as exc:
            notes = list(prev.get("notes") or []) if isinstance(prev.get("notes"), list) else []
            notes.append(f"refine failed: {exc}"[:180])
            prev["notes"] = notes
            return prev
        ok, err = _groundable(root, nxt, diff)
        prev = nxt
        if ok:
            notes = list(nxt.get("notes") or []) if isinstance(nxt.get("notes"), list) else []
            notes.append("interpreter nominated after refine")
            nxt["notes"] = notes
            return nxt
    notes = list(prev.get("notes") or []) if isinstance(prev.get("notes"), list) else []
    notes.append(err)
    prev["notes"] = notes
    return prev


def apply_graph(pcg: dict, graph: dict, root: Path | None, diff: str) -> dict:
    """Retarget interpreter.fn to a symbol the classical graph put on the flow."""
    ranked = graph.get("ranked_guards") or []
    notes = list(pcg.get("notes") or []) if isinstance(pcg.get("notes"), list) else []
    if isinstance(pcg.get("notes"), str) and pcg["notes"]:
        notes.append(pcg["notes"])
    interp = pcg.get("interpreter") or {}
    current = str(interp.get("fn") or "")
    current_tok = current.split(".")[-1]
    strong = [r for r in ranked if r.get("co_reachable")]
    present = {
        re.split(r"[.(#:/\\]", str(r.get("guard") or ""))[-1]
        for r in ranked
        if r.get("present")
    }

    def _ok(tok: str) -> bool:
        return bool(tok) and (not root or locate_function(root, tok))

    pick = None
    for row in strong:
        tok = re.split(r"[.(#:/\\]", str(row.get("guard") or ""))[-1]
        if _ok(tok):
            pick = tok
            why = "co-reachable"
            break
    else:
        # Presence-only: drop a nomination that is not in the CPG, prefer
        # a decoder that is. Do not jump to the first random present name.
        if current_tok and present and current_tok not in present:
            prefer = [n for n in present if re.search(r"decode|unquote|canonical", n, re.I)]
            for tok in prefer + [n for n in present if n not in prefer]:
                if _ok(tok):
                    pick = tok
                    why = "present-in-cpg"
                    break
    if pick and pick != current:
        interp["fn"] = pick
        interp["locus"] = "in-product"
        notes.append(f"classical graph localized interpreter to {pick!r} ({why})")
        pcg["interpreter"] = interp
    elif strong and current_tok and current_tok not in {
        re.split(r"[.(#:/\\]", str(r.get("guard") or ""))[-1] for r in strong
    }:
        notes.append(f"nominated {current!r} not co-reachable; kept overlay fallback")
    pcg["notes"] = notes
    return pcg


def interpreter_source(ws: Workspace, pcg: dict) -> str:
    root = _src_root(ws)
    blob = pcg.get("_src_blob") or ""
    if not root:
        return blob
    interp = pcg.get("interpreter") or {}
    where = str(interp.get("where") or "")
    interp_file = where.split(":")[0]
    extra = source.read_file(root, interp_file, limit=12000) if interp_file else ""
    if not extra:
        found = source.find_symbol_file(root, interp.get("fn", ""))
        if found:
            extra = found.read_text(encoding="utf-8", errors="ignore")[:12000]
            interp_file = found.name
    if extra:
        return f"\n===== interpreter: {interp_file} =====\n{extra}\n" + blob
    return blob
