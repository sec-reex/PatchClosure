from __future__ import annotations

import os
import re
from pathlib import Path

from patchclosure import (
    agent,
    build,
    carriers,
    config,
    ip_enum,
    match,
    overlay,
    preimage,
    transcribe,
)
from patchclosure.assemble import load_seed_candidate
from patchclosure.discharge import smt
from patchclosure.graph import codeql, joern
from patchclosure.llm import LLMError, available as llm_available
from patchclosure.oracle import channel_for_family
from patchclosure.slice import fst as F
from patchclosure.slice.ground import ground_interpreter
from patchclosure.validate import fire_candidates
from patchclosure.workspace import Workspace, load_workspace


def analyze(ws: Workspace | str | Path) -> dict:
    if not isinstance(ws, Workspace):
        ws = load_workspace(ws)
    out: dict = {"workspace": str(ws.root), "warnings": list(ws.warnings)}
    diff = ws.diff_text
    guards = overlay.overlay_guards(diff)
    lang = overlay.primary_language(diff)
    out["overlay"] = {
        "language": lang,
        "guards": [g.__dict__ for g in guards],
    }

    pcg = build.build_pcg(ws)
    # Prefer tree-sitter overlay guard when the LLM did not pin a site.
    if guards and not (pcg.get("guard") or {}).get("code"):
        g0 = guards[0]
        pcg["guard"] = {"where": f"{g0.path}:{g0.line}", "code": g0.code, "kind": g0.kind}

    source_names = ["doGet", "doPost", "service", "call", "getRequestURI", "getPathInfo"]
    source_names += joern.identifiers([(pcg.get("guard") or {}).get("reads")])
    sink_names = joern.identifiers(
        [(pcg.get("sink") or {}).get("op"), (pcg.get("interpreter") or {}).get("fn")]
    )
    guard_names = joern.identifiers([g.tokens[0] for g in guards if g.tokens]) or [
        (pcg.get("guard") or {}).get("where"),
    ]
    graph = {"used": None}
    srcroot = ws.v1 or ws.v0
    changed = pcg.get("_changed_files") or []
    names = [n for n in guard_names if n][:2]
    for extra in build._fn_candidates(pcg, diff):
        if extra not in names:
            names.append(extra)
    names = names[:8]
    source_names = list(dict.fromkeys(source_names + names))[:10]
    nfiles = _source_file_count(srcroot)
    small = nfiles > 0 and nfiles <= 400
    want_codeql = (
        codeql.available()
        and lang in {"javascript", "typescript", "python", "go", "ruby"}
        and os.environ.get("PATCHCLOSURE_CODEQL", "").strip() not in {"0", "off"}
        and (small or os.environ.get("PATCHCLOSURE_CODEQL") == "1")
    )
    want_joern = joern.available() and (
        os.environ.get("PATCHCLOSURE_JOERN", "").strip() not in {"0", "off"}
    ) and (
        os.environ.get("PATCHCLOSURE_JOERN") == "1"
        or ((lang in {"java", "c"} or len(changed) > 1) and small)
    )
    if srcroot and lang and want_codeql:
        try:
            located = codeql.locate_guard(srcroot, lang, source_names, sink_names, names)
            graph = {"used": "codeql", **located}
            ranked = located.get("ranked_guards") or []
            if ranked and ranked[0].get("co_reachable"):
                pcg["guard"] = {**(pcg.get("guard") or {}), "localized": ranked[0]}
            pcg = build.apply_graph(pcg, located, srcroot, diff)
            if (
                ranked
                and ranked[0].get("sink_calls", 0) >= 1
                and not ranked[0].get("flows_src_to_sink")
            ):
                pcg["sink"] = {**(pcg.get("sink") or {}), "dropped": True}
                out["warnings"].append("nominated sink not reachable on the classical graph; dropped")
        except Exception as exc:
            graph = {"used": None, "tried": "codeql", "error": str(exc)[:300]}
            want_joern = want_joern or joern.available()
    if srcroot and lang and want_joern and graph.get("used") != "codeql":
        try:
            located = joern.locate_guard(srcroot, lang, source_names, sink_names, names)
            graph = {"used": "joern", **located}
            ranked = located.get("ranked_guards") or []
            if ranked and ranked[0].get("co_reachable"):
                pcg["guard"] = {**(pcg.get("guard") or {}), "localized": ranked[0]}
            pcg = build.apply_graph(pcg, located, srcroot, diff)
            reach = joern.co_reach(located.get("cpg"), source_names, source_names, sink_names)
            reach = {"reachable": bool(reach.get("flows_src_to_sink")), **reach}
            if reach.get("reachable") is False:
                pcg["sink"] = {**(pcg.get("sink") or {}), "dropped": True}
                out["warnings"].append("nominated sink not reachable on the classical graph; dropped")
        except Exception as exc:
            graph = {"used": "joern", "error": str(exc)[:300]}
    elif srcroot and lang and not graph.get("used"):
        graph = {"used": None, "note": "no classical-graph frontend ran; guard stays on the overlay hunk"}
    out["graph"] = {k: graph[k] for k in graph if k != "cpg"}
    out["graph"]["cpg"] = graph.get("cpg")

    seed = load_seed_candidate(ws.exp)
    grounded = ground_interpreter(srcroot, pcg, seed=seed)
    out["ground"] = {
        k: grounded[k]
        for k in grounded
        if k not in {"phi", "admits", "danger", "fst_model", "domain"}
    }
    if grounded.get("dropped"):
        out["warnings"].append(grounded.get("status"))

    verdict = match.classify(pcg, seed)
    out["pcg"] = {
        k: pcg[k]
        for k in (
            "guard", "sink", "interpreter", "gap_type",
            "danger_target", "obligation", "carriers", "ground_notes",
        )
        if k in pcg
    }
    out["match"] = verdict
    out["dispatch"] = _dispatch(ws, pcg, verdict, grounded, guards)
    return out


def _dispatch(ws, pcg, verdict, grounded, guards) -> dict:
    srcroot = ws.v1 or ws.v0
    seed = load_seed_candidate(ws.exp)
    phi_near = preimage.seed_rewrites(seed, grounded.get("pairs") or [])

    agent_frags = agent.propose(
        seed=seed,
        diff=ws.diff_text,
        guards=guards,
        pairs=grounded.get("pairs") or [],
        probe_text=agent.probe_text(ws.exp),
    )
    siblings = carriers.discover_siblings(srcroot, seed)
    if verdict["family"] == "obligation" or siblings:
        spec = {}
        try:
            spec = carriers.propose_carrier_patterns(
                ws.diff_text, build.interpreter_source(ws, pcg)
            ) if verdict["family"] == "obligation" else {}
        except Exception as exc:
            spec = {"error": str(exc)[:200]}
        enum = carriers.enumerate_carriers(srcroot, spec) if spec else {"unguarded": [], "guarded": []}
        fragments = []
        static = []
        for site in list(enum.get("unguarded") or []) + siblings:
            cand = carriers.issue_identity(seed, site)
            if cand:
                fragments.append({
                    "x": (
                        cand.get("url") if site.get("kind") == "component"
                        else cand.get("host") if site.get("kind") == "field"
                        else (cand.get("path") or cand.get("op") or cand.get("route") or site.get("path"))
                    ),
                    "candidate": cand,
                    "carrier": site,
                })
            else:
                static.append(site)
        if verdict["family"] == "obligation":
            # LLM often labels language gaps "obligation". Keep measured
            # φ-equivalent rewrites so a misclassified decode/unquote case
            # still discharges the interpreter we actually grounded.
            return {
                "kind": "obligation" if fragments else "language",
                **enum,
                "fragments": _uniq(agent_frags + phi_near + fragments)[: config.CANDIDATE_CAP],
                "static_evidence": static,
            }
        # keep sibling identities alongside the language/IP search
        obligation_frags = fragments
    else:
        obligation_frags = []

    if verdict["ip_family"]:
        samples = _maybe_ensemble(ws, pcg)
        if grounded.get("admits"):
            samples = list(samples) + [{"admits": grounded["admits"]}]
        targets = tuple(preimage.ips_in_seed(seed))
        gen = ip_enum.gen_ip_candidates(samples, targets=targets)
        wrapped = []
        for frag in gen.get("fragments") or []:
            x = frag.get("x")
            for text in (seed or {}).values():
                if not isinstance(text, str):
                    continue
                for ip in targets:
                    if ip in text and x:
                        wrapped.append({"x": text.replace(ip, x, 1), "backend": "ip-radix"})
            wrapped.append(frag)
        gen["fragments"] = _uniq(agent_frags + obligation_frags + phi_near + wrapped)[: config.CANDIDATE_CAP]
        gen["kind"] = "ssrf_ip"
        return gen

    # Language gap: SMT on the decidable fragment, else execution-guided enum.
    kmax = config.KMAX_BYTES
    payload_len = 0
    if isinstance(seed, dict):
        payload_len = max((len(v) for v in seed.values() if isinstance(v, str)), default=0)
    if payload_len > 64:
        kmax = 128
    guard_code = "\n".join(g.code for g in guards) or str((pcg.get("guard") or {}).get("code") or "")
    smt_hit = smt.try_smt(guard_code, str(pcg.get("danger_target") or ""), grounded.get("fst"), kmax=kmax)
    fragments = []
    if "^" in guard_code:
        for text in (seed or {}).values() if seed else []:
            if not isinstance(text, str) or len(text) < 8:
                continue
            for ip in preimage.ips_in_seed(seed):
                if ip in text and not text.lstrip().startswith(ip):
                    fragments.append({"x": ip + text, "backend": "anchor-prefix"})
    backend = "enum"
    if smt_hit and smt_hit.get("witnesses"):
        backend = "z3"
        fragments = [{"x": w, "backend": "z3"} for w in smt_hit["witnesses"]]
    if grounded.get("status") == "built" and grounded.get("phi"):
        inv = F.invert(
            grounded.get("fst_model") or {},
            grounded.get("danger"),
            grounded.get("alphabet") or [],
            kmax=min(8, kmax),
        )
        for x in inv:
            fragments.append({"x": x, "backend": "fst-invert"})
        enum = preimage.exec_bounded_preimage(
            grounded["admits"],
            grounded["phi"],
            grounded["danger"],
            alphabet=grounded.get("alphabet"),
            kmax=config.KMAX,
            max_solutions=config.CANDIDATE_CAP,
            budget=config.ENUM_BUDGET,
        )
        for w in enum.get("witnesses") or []:
            fragments.append({"x": w, "backend": "exec"})
        backend = backend if backend == "z3" else ("fst+exec" if grounded.get("fst", {}).get("regular") else "exec")
        return {
            "kind": "language",
            "backend": backend,
            "smt": {k: smt_hit[k] for k in smt_hit if k != "witnesses"} if smt_hit else None,
            "enum": {k: enum[k] for k in enum if k != "alphabet"},
            "alphabet": grounded.get("alphabet"),
            "fragments": _uniq(agent_frags + obligation_frags + phi_near + fragments)[: config.CANDIDATE_CAP],
            "kmax_bytes": kmax,
        }

    # Slice failed: still invert the overlay guard as identity φ (L_G
    # by executing the added predicate). Do not dump a transcribed wordlist.
    reject = _reject_literal(guard_code)
    if reject and grounded.get("danger"):
        enum = preimage.exec_bounded_preimage(
            lambda x, lit=reject: lit not in x,
            lambda x: x,
            grounded["danger"],
            alphabet=grounded.get("alphabet") or list(dict.fromkeys([*reject, "a", "\r", "\n", ".", "/"])),
            kmax=min(4, config.KMAX),
            max_solutions=config.CANDIDATE_CAP,
            budget=config.ENUM_BUDGET,
        )
        for w in enum.get("witnesses") or []:
            fragments.append({"x": w, "backend": "overlay-exec"})
    if fragments or phi_near:
        return {
            "kind": "language",
            "backend": "z3" if backend == "z3" else "overlay-exec",
            "smt": {k: smt_hit[k] for k in smt_hit if k != "witnesses"} if smt_hit else None,
            "fragments": _uniq(agent_frags + obligation_frags + phi_near + fragments)[: config.CANDIDATE_CAP],
            "note": grounded.get("status") or "no measured interpreter",
        }
    return {
        "kind": "obligation" if obligation_frags else "language",
        "backend": "issue-identity" if obligation_frags else None,
        "fragments": _uniq(agent_frags + obligation_frags)[: config.CANDIDATE_CAP],
        "note": grounded.get("status") or "no measured interpreter",
    }


def _source_file_count(root: Path | None) -> int:
    if not root or not Path(root).exists():
        return 0
    n = 0
    for path in Path(root).rglob("*"):
        if path.suffix in {".java", ".js", ".py", ".go", ".rb", ".php", ".c", ".h"}:
            n += 1
            if n > 400:
                return n
    return n


def _reject_literal(guard_code: str) -> str:
    raw = guard_code or ""
    if "\\r\\n" in raw or "\r\n" in raw:
        return "\r\n"
    if r"\.\./" in raw or "../" in raw:
        return "../"
    m = re.search(r"""(?:contains|includes|indexOf)\s*\(\s*['\"]([^'\"]+)['\"]""", raw)
    if m:
        return m.group(1)
    m = re.search(r"""=~\s*/((?:\\.|[^/])+)/""", raw)
    if m:
        tok = m.group(1).encode("utf-8").decode("unicode_escape")
        return tok
    return ""


def _maybe_ensemble(ws, pcg) -> list:
    if not llm_available():
        return []
    try:
        return transcribe.ensemble(pcg, build.interpreter_source(ws, pcg))
    except (LLMError, ValueError):
        return []


def _uniq(frags: list[dict]) -> list[dict]:
    seen, out = set(), []
    for frag in frags:
        cand = frag.get("candidate")
        x = ("c", repr(cand)) if cand else frag.get("x")
        if x in seen:
            continue
        seen.add(x)
        out.append(frag)
    return out


def fire(ws: Workspace | str | Path, report: dict, *, v1_base: str | None, v1_port: int | None = None, port_map: dict | None = None) -> dict:
    if not isinstance(ws, Workspace):
        ws = load_workspace(ws)
    fragments = (report.get("dispatch") or {}).get("fragments") or []
    channel = channel_for_family(
        None,
        (report.get("ground") or {}).get("danger_family"),
    )
    tokens: list[str] = []
    for guard in (report.get("overlay") or {}).get("guards") or []:
        tokens.extend(guard.get("tokens") or [])
        code = str(guard.get("code") or "")
        if "\\r\\n" in code or "\r\n" in code:
            tokens.append("\r\n")
        if r"\.\./" in code or "../" in code:
            tokens.append("../")
    for pair in (report.get("ground") or {}).get("pairs") or []:
        if isinstance(pair, (list, tuple)) and pair:
            tokens.append(str(pair[0]))
    live = fire_candidates(
        ws.exp, fragments, v1_base=v1_base, v1_port=v1_port, port_map=port_map, channel=channel, tokens=tokens
    )
    report["validate"] = live
    report["validate"]["channel"] = channel
    return report
