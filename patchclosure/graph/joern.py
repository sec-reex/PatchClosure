"""Classical graph via Joern CPG.

Answers: is the nominated sink reachable from the attacker value, and
which guard hunk sits on that same attacker-to-sink dataflow.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import uuid
from pathlib import Path

from patchclosure import config

LANG_FRONTEND = {
    "java": "javasrc",
    "javascript": "javascript",
    "typescript": "javascript",
    "python": "python",
    "go": "gosrc",
    "php": "php",
    "ruby": "rubysrc",
    "c": "c",
}


def _env() -> dict:
    env = dict(os.environ)
    java = Path(config.JAVA_HOME)
    if java.exists():
        env["JAVA_HOME"] = str(java)
        env["PATH"] = str(java / "bin") + os.pathsep + env.get("PATH", "")
    return env


def available() -> bool:
    home = Path(config.JOERN_HOME)
    return (home / "joern-parse").is_file() and (home / "joern").is_file()


def _bins() -> tuple[str, str]:
    home = Path(config.JOERN_HOME)
    return str(home / "joern-parse"), str(home / "joern")


def build_cpg(srcroot: Path, lang: str, out: Path | None = None, timeout: int = 900) -> Path:
    if not available():
        raise RuntimeError("Joern is not installed (set JOERN_HOME)")
    parse, _ = _bins()
    fe = LANG_FRONTEND.get(lang, "javasrc")
    out = Path(out or (Path(tempfile.mkdtemp(prefix="pc_cpg_")) / f"{uuid.uuid4().hex}.bin"))
    out.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        [parse, str(srcroot), "--language", fe, "-o", str(out)],
        capture_output=True,
        text=True,
        env=_env(),
        timeout=timeout,
        cwd=str(out.parent),
    )
    if not out.exists():
        raise RuntimeError(f"joern-parse failed: {(proc.stdout + proc.stderr)[-400:]}")
    return out


def identifiers(names) -> list[str]:
    """Keep method-like tokens; drop LLM prose ('URI path parsing (...)')."""
    skip = {"path", "file", "name", "type", "true", "false", "null", "this"}
    out: list[str] = []
    for name in names or []:
        s = str(name or "").strip()
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", s) and 2 < len(s) < 48 and s.lower() not in skip:
            if s not in out:
                out.append(s)
            continue
        for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", s):
            if tok[0].islower() and any(c.isupper() for c in tok[1:]) and tok not in out:
                out.append(tok)
    return out


def _names_regex(names) -> str:
    toks = [re.escape(t) for t in identifiers(names)]
    return "(" + "|".join(toks) + ")" if toks else "$^"


def co_reach(cpg, source_names, guard_names, sink_names, timeout: int = 600) -> dict:
    _, joern = _bins()
    src_re = _names_regex(source_names)
    guard_re = _names_regex(guard_names)
    sink_re = _names_regex(sink_names)
    if src_re == "$^" and guard_re == "$^":
        return {"error": "no identifier names", "co_reachable": False, "present": False}
    # Joern names its project after the CPG filename; isolate the workspace
    # so we do not write into the caller's cwd.
    work = Path(tempfile.mkdtemp(prefix="pc_joernws_"))
    script = f'''
importCpg("{Path(cpg).resolve()}")
val srcRe = "(?i).*{src_re}.*"
val guardRe = "(?i).*{guard_re}.*"
val sinkRe = "(?i).*{sink_re}.*"
val nSink = cpg.call.name(sinkRe).size
val nGuard = cpg.method.name(guardRe).size + cpg.call.name(guardRe).size
var fSink = 0
var fGuard = 0
try {{
  val srcParams = cpg.method.name(srcRe).parameter.l
  fSink = cpg.call.name(sinkRe).argument.reachableByFlows(srcParams).size
  fGuard = cpg.call.name(guardRe).argument.reachableByFlows(srcParams).size
}} catch {{ case _: Throwable => }}
println("PCG_JSON_START")
println(s"""{{"sink_calls":$nSink,"guard_methods":$nGuard,"flows_src_to_sink":$fSink,"flows_src_to_guard":$fGuard,"co_reachable":${{fSink > 0 && fGuard > 0}},"present":${{nGuard > 0}}}}""")
println("PCG_JSON_END")
'''
    path = work / "query.sc"
    path.write_text(script, encoding="utf-8")
    try:
        proc = subprocess.run(
            [joern, "--script", str(path)],
            capture_output=True,
            text=True,
            env=_env(),
            timeout=timeout,
            cwd=str(work),
        )
        blob = proc.stdout + proc.stderr
        match = re.search(r"PCG_JSON_START\s*(\{.*?\})\s*PCG_JSON_END", blob, re.S)
        if not match:
            return {"error": "no json", "log": blob[-500:], "present": False}
        return json.loads(match.group(1))
    finally:
        try:
            path.unlink()
        except OSError:
            pass


def locate_guard(srcroot, lang, source_names, sink_names, guard_candidates, timeout: int = 900) -> dict:
    """Rank guard candidates by source→sink co-reachability on the DDG."""
    cpg = build_cpg(Path(srcroot), lang, timeout=timeout)
    ranked = []
    for guard in guard_candidates:
        result = co_reach(cpg, source_names, [guard], sink_names, timeout=timeout)
        ranked.append(
            {
                "guard": guard,
                "flows_src_to_guard": result.get("flows_src_to_guard"),
                "flows_src_to_sink": result.get("flows_src_to_sink"),
                "co_reachable": result.get("co_reachable"),
                "present": result.get("present"),
                "guard_locs": result.get("guard_locs"),
                "error": result.get("error"),
            }
        )
    ranked.sort(
        key=lambda d: (
            not d.get("co_reachable"),
            not d.get("present"),
            -(d.get("flows_src_to_guard") or 0),
        )
    )
    return {"cpg": str(cpg), "ranked_guards": ranked}


def sink_reachable(srcroot, lang, source_names, sink_names, timeout: int = 900) -> dict:
    if not source_names or not sink_names:
        return {"reachable": None, "note": "missing source or sink name"}
    cpg = build_cpg(Path(srcroot), lang, timeout=timeout)
    result = co_reach(cpg, source_names, source_names, sink_names, timeout=timeout)
    return {
        "reachable": bool(result.get("flows_src_to_sink")),
        "flows": result.get("flows_src_to_sink"),
        "present": result.get("present"),
        "cpg": str(cpg),
        "error": result.get("error"),
    }
