"""CodeQL dataflow frontend (paper §impl).

Supplies the same two edges as Joern: attacker-value → sink reachability,
and whether a guard hunk sits on that dataflow.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

QL_DIR = Path(__file__).resolve().parent / "ql"
QLPACKS = Path(__file__).resolve().parent / "qlpacks"

PACK_KEY = {
    "javascript": "javascript",
    "typescript": "javascript",
    "tsx": "javascript",
    "python": "python",
    "java": "java",
    "go": "go",
    "ruby": "ruby",
}

EXTRACTOR = {
    "javascript": "javascript",
    "typescript": "javascript",
    "python": "python",
    "java": "java",
    "go": "go",
    "ruby": "ruby",
    "c": "cpp",
    "cpp": "cpp",
    "csharp": "csharp",
}


def available() -> bool:
    return shutil.which("codeql") is not None


def language_for(lang: str) -> str | None:
    return EXTRACTOR.get(lang)


def _names_regex(names) -> str:
    toks = []
    for name in names or []:
        last = re.split(r"[.(#:/\\]", str(name).split("::")[-1])[-1].strip()
        if last and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", last):
            toks.append(re.escape(last))
    return "(?i).*(" + "|".join(toks) + ").*" if toks else "$^"


def create_database(srcroot: Path, lang: str, dest: Path, timeout: int = 900) -> Path:
    ql = language_for(lang)
    if not ql:
        raise RuntimeError(f"CodeQL has no frontend for {lang}")
    dest = Path(dest)
    if dest.exists() and any(dest.glob("db-*")):
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        [
            "codeql", "database", "create", str(dest),
            f"--language={ql}",
            f"--source-root={srcroot}",
            "--overwrite",
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if proc.returncode != 0 or not dest.exists():
        raise RuntimeError(proc.stderr[-500:] or proc.stdout[-500:] or "database create failed")
    return dest


def _ql_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _render_query(lang: str, src_re: str, guard_re: str, sink_re: str) -> str:
    key = "javascript" if lang in {"javascript", "typescript", "tsx"} else lang
    tpl = QL_DIR / f"{key}.ql.tpl"
    if not tpl.is_file():
        raise RuntimeError(f"no CodeQL query template for {lang}")
    text = tpl.read_text(encoding="utf-8")
    return (
        text.replace("{src_re}", _ql_string(src_re))
        .replace("{guard_re}", _ql_string(guard_re))
        .replace("{sink_re}", _ql_string(sink_re))
    )


def _run_query(db: Path, lang: str, src_re: str, guard_re: str, sink_re: str, timeout: int = 600) -> dict:
    key = PACK_KEY.get(lang)
    if not key:
        raise RuntimeError(f"no CodeQL pack for {lang}")
    pack_src = QLPACKS / key
    if not (pack_src / "qlpack.yml").is_file():
        raise RuntimeError(f"missing qlpack at {pack_src}")
    work = Path(tempfile.mkdtemp(prefix="pc_ql_"))
    for name in ("qlpack.yml", "codeql-pack.lock.yml"):
        src = pack_src / name
        if src.is_file():
            (work / name).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    (work / "CoReach.ql").write_text(
        _render_query(lang, src_re, guard_re, sink_re), encoding="utf-8"
    )
    bqrs = work / "out.bqrs"
    run = subprocess.run(
        ["codeql", "query", "run", str(work / "CoReach.ql"), f"--database={db}", f"--output={bqrs}"],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if run.returncode != 0 or not bqrs.exists():
        raise RuntimeError((run.stderr or run.stdout)[-600:])
    dec = subprocess.run(
        ["codeql", "bqrs", "decode", "--format=json", str(bqrs)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if dec.returncode != 0:
        raise RuntimeError(dec.stderr[-400:])
    payload = json.loads(dec.stdout)
    tuples = (payload.get("#select") or {}).get("tuples") or []
    if not tuples:
        return {
            "sink_calls": 0, "guard_calls": 0,
            "flows_src_to_sink": 0, "flows_src_to_guard": 0,
            "co_reachable": False,
        }
    row = tuples[0]
    # each cell may be a bare int or {"n": int}
    def _n(cell):
        if isinstance(cell, dict):
            return int(next(iter(cell.values())))
        return int(cell)

    sink_calls, guard_calls, f_sink, f_guard = (_n(c) for c in row[:4])
    return {
        "sink_calls": sink_calls,
        "guard_calls": guard_calls,
        "flows_src_to_sink": f_sink,
        "flows_src_to_guard": f_guard,
        "co_reachable": f_sink > 0 and f_guard > 0,
    }


def co_reach(srcroot, lang, source_names, guard_names, sink_names, timeout: int = 900) -> dict:
    if not available():
        return {"error": "codeql not on PATH"}
    db = create_database(Path(srcroot), lang, Path(tempfile.mkdtemp(prefix="pc_qldb_")) / "db", timeout=timeout)
    try:
        result = _run_query(
            db, lang,
            _names_regex(source_names),
            _names_regex(guard_names),
            _names_regex(sink_names),
            timeout=timeout,
        )
        result["database"] = str(db)
        return result
    except Exception as exc:
        return {"error": str(exc)[:400], "database": str(db)}


def locate_guard(srcroot, lang, source_names, sink_names, guard_candidates, timeout: int = 900) -> dict:
    if not available():
        raise RuntimeError("codeql not on PATH")
    db = create_database(Path(srcroot), lang, Path(tempfile.mkdtemp(prefix="pc_qldb_")) / "db", timeout=timeout)
    ranked = []
    for guard in guard_candidates:
        result = _run_query(
            db, lang,
            _names_regex(source_names),
            _names_regex([guard]),
            _names_regex(sink_names),
            timeout=timeout,
        )
        ranked.append({"guard": guard, **result})
    ranked.sort(key=lambda d: (not d.get("co_reachable"), -(d.get("flows_src_to_guard") or 0)))
    return {"frontend": "codeql", "database": str(db), "ranked_guards": ranked}


def sink_reachable(srcroot, lang, source_names, sink_names, timeout: int = 900) -> dict:
    result = co_reach(srcroot, lang, source_names, source_names, sink_names, timeout=timeout)
    return {
        "reachable": bool(result.get("flows_src_to_sink")),
        "flows": result.get("flows_src_to_sink"),
        "error": result.get("error"),
        "frontend": "codeql",
    }
