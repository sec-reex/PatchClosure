#!/usr/bin/env python3
"""Semantic map of the V1 source — a deterministic, agent-consumable index.

Idea borrowed from codebase-understanding tools (per-unit facts + layered
views + question-driven search), adapted to the benchmark's real bottleneck:
the residual structure is usually found quickly, but the channel where the
planted marker SURFACES is not. This map answers exactly that question with
file:line facts, grouped by layer:

  1. observable-output sites  (the readout surface: where anything written /
     echoed / redirected / rendered reaches a response or a file)
  2. route table -> handler   (how to reach each site)
  3. session / auth sites     (how to get past a login to fire it)
  4. module neighborhood of the changed files (orientation)

Zero LLM, one bounded grep pass, fail-soft. Output: work/semantic_map.md.
"""
from __future__ import annotations

import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pcg_graph  # noqa: E402  (extraction substrate: detect_langs/_parser/dispatch)
from build_guide import detect_language, discover_routes, grep_source, walk_source  # noqa: E402

# Preregistered response-verb tables per language family (deterministic).
READOUT_RX = {
    "php": re.compile(
        r"(?i)\b(echo|print[_r]?|printf|var_dump|header\s*\(|setcookie\s*\(|"
        r"readfile\s*\(|fpassthru|file_put_contents\s*\()"),
    "javascript": re.compile(
        r"(?i)\b(res|response|reply|ctx|reply)\.(send|json|write|writeHead|"
        r"setHeader|end|redirect|render|download|sendFile|sendfile)\s*\(|"
        r"\breturn\s+(Response|NextResponse|new\s+Response)\b|"
        r"\b(console\.log)\s*\("),
    "python": re.compile(
        r"(?i)\b(jsonify|make_response|send_response|send_file|redirect|"
        r"render_template|render|write)\s*\(|"
        r"\b(Response|JSONResponse|PlainTextResponse|RedirectResponse)\s*\(|"
        r"\bself\.write\s*\(|\bhttp\.Error\b|\bopen\([^)]*,\s*['\"][wa]"),
    "go": re.compile(
        r"(?i)\bw\.(Write|WriteHeader)\s*\(|http\.Redirect\s*\(|"
        r"fmt\.Fprintf?\s*\(\s*w\b|c\.(String|JSON|HTML|Redirect|File)\s*\(|"
        r"os\.WriteFile\s*\(|ioutil\.WriteFile\s*\("),
    "java": re.compile(
        r"(?i)getWriter\s*\(\s*\)|\.print(ln)?\s*\(|sendRedirect\s*\(|"
        r"setHeader\s*\(|setContentType\s*\(|Files\.write\s*\("),
    "ruby": re.compile(
        r"(?i)\b(render|redirect_to|response\.headers|send_data|send_file|"
        r"File\.write|File\.open\([^)]*,\s*['\"][wa])"),
    "typescript": None,  # falls through to javascript table
}

AUTH_RX = re.compile(
    r"(?i)\b(login|logout|signin|sign_in|authenticate|middleware|session|"
    r"csrf|password|api[_-]?token|access[_-]?token|jwt|passport|guard)\b")

ROUTE_NEEDED_LANGS = {"php", "javascript", "typescript", "python", "go", "ruby"}


def _lang_table(lang: str):
    if lang in ("typescript", "javascript"):
        return READOUT_RX["javascript"]
    return READOUT_RX.get(lang)


def _near_changed(rel_path: str, changed_dirs: set) -> bool:
    d = os.path.dirname(rel_path)
    return d in changed_dirs or any(d.startswith(cd + "/") or cd.startswith(d + "/")
                                    for cd in changed_dirs)


_COMMENT_TEXT = re.compile(r"^\s*(//|/\*|\*|#|<!--|\*+)")	


def _is_comment(text: str) -> bool:
    return bool(_COMMENT_TEXT.match(text or ""))


def _changed_dirs_from_pkg(pkg_dir: str, facts: dict | None) -> set:
    dirs = set()
    for d in (facts or {}).get("diff_files", []):
        p = d.get("new_path", "")
        if p:
            dirs.add(os.path.dirname(p))
    if not dirs:
        diff_path = os.path.join(pkg_dir, "patch.diff")
        if os.path.isfile(diff_path):
            try:
                from build_guide import parse_unified_diff
                with open(diff_path, errors="replace") as f:
                    for d in parse_unified_diff(f.read()):
                        if d.new_path:
                            dirs.add(os.path.dirname(d.new_path))
            except Exception:
                pass
    return dirs


def build_semantic_map(pkg_dir: str, facts: dict | None = None) -> str | None:
    src = os.path.join(pkg_dir, "v1_source")
    if not os.path.isdir(src):
        return None
    t0 = time.time()
    tree = walk_source(src)
    lang = detect_language(tree)
    table = _lang_table(lang)
    changed_dirs = _changed_dirs_from_pkg(pkg_dir, facts)

    # ── 1. readout surface — on the pcg_graph substrate ────────────────
    # one tree-sitter call scan, callee names filtered by the readout verb
    # table (same class as the frozen CodeQL sink regexes). No per-language
    # line regexes here anymore.
    readout = []
    langs = pcg_graph.detect_langs(src)
    covered = [l for l in langs if pcg_graph._parser(l)]
    if covered:
        import re as _re
        verb = _re.compile(r"(?i)(send|json|write|writehead|setheader|end|redirect|"
                           r"render|download|sendfile|printf?|print_r|var_dump|header|"
                           r"setcookie|readfile|fpassthru|file_put_contents|jsonify|"
                           r"make_response|send_response|send_file|writefile)")
        dispatch, _fx, _ce = pcg_graph.scan_dispatch_points(src, covered, max_files=600)
        for d in dispatch:
            if d.get("call") and verb.search(d["call"]):
                readout.append({"file": d["file"], "line": d["line"],
                                "text": f"{d['call']}({d.get('literal') or ''})"[:160]})
    readout_near = [h for h in readout if _near_changed(h.get("file", ""), changed_dirs)]
    readout_near.sort(key=lambda h: (h.get("file", ""), h.get("line", 0)))
    readout_rest = [h for h in readout if h not in readout_near]
    readout_rest.sort(key=lambda h: (h.get("file", ""), h.get("line", 0)))

    # ── 2. routes (re-use build_guide's discovery) ─────────────────────
    routes = []
    if lang in ROUTE_NEEDED_LANGS:
        try:
            routes = discover_routes(src)
        except Exception:
            routes = []

    # ── 3. session/auth sites near the changed files ───────────────────
    auth_hits = []
    if changed_dirs:
        auth_hits = [h for h in grep_source(src, AUTH_RX.pattern, prod_only=True)
                     if _near_changed(h.get("file", ""), changed_dirs)][:30]

    # ── render ─────────────────────────────────────────────────────────
    L = []
    L.append("# Semantic map of the service source")
    L.append("")
    L.append("Deterministic index (no interpretation). Sections answer: where")
    L.append("does anything reach an output/file (readout surface), how is it")
    L.append("reached (routes), how does a session start (auth sites), and what")
    L.append("sits next to the changed files. Use this to locate the channel")
    L.append("where a planted value could surface BEFORE constructing inputs.")
    L.append("")
    L.append(f"## 1. Observable-output sites near the changed files ({len(readout_near)})")
    L.append("")
    if readout_near:
        L.append("These sites write to a response or a file. If a value is stored,")
        L.append("planted, or transformed by the code under review, it can only")
        L.append("become observable through sites like these — check each one that")
        L.append("is reachable from the changed code paths.")
        L.append("")
        for h in readout_near[:40]:
            L.append(f"- `{h.get('file')}:{h.get('line')}`  `{(h.get('text') or '').strip()[:110]}`")
    else:
        L.append("(none found near the changed files — widen the search yourself)")
    L.append("")
    L.append(f"## 2. Observable-output sites elsewhere in the service ({len(readout_rest)})")
    L.append("")
    for h in readout_rest[:30]:
        L.append(f"- `{h.get('file')}:{h.get('line')}`  `{(h.get('text') or '').strip()[:100]}`")
    if len(readout_rest) > 30:
        L.append(f"- … and {len(readout_rest) - 30} more (grep the pattern yourself)")
    L.append("")
    L.append(f"## 3. Route table ({len(routes)})")
    L.append("")
    for r in routes[:50]:
        L.append(f"- `{(r.get('path') or '').strip()}` → `{r.get('file')}:{r.get('line')}`")
    if len(routes) > 50:
        L.append(f"- … and {len(routes) - 50} more")
    L.append("")
    L.append(f"## 4. Session/auth sites near the changed files ({len(auth_hits)})")
    L.append("")
    for h in auth_hits[:20]:
        L.append(f"- `{h.get('file')}:{h.get('line')}`  `{(h.get('text') or '').strip()[:100]}`")
    L.append("")
    L.append(f"## 5. Module neighborhood of the changed files")
    L.append("")
    for d in sorted(changed_dirs)[:8]:
        sibs = [fn for fn in tree if os.path.dirname(fn) == d][:12]
        if sibs:
            L.append(f"- `{d}/`: " + ", ".join(f"`{os.path.basename(s)}`" for s in sibs))
    L.append("")
    L.append(f"_(built in {round(time.time() - t0, 1)}s; language guess: {lang})_")
    return "\n".join(L)


def main(pkg_dir: str):
    facts_path = os.path.join(pkg_dir, "work", "pcg_facts.json")
    facts = None
    if os.path.isfile(facts_path):
        try:
            import json
            facts = json.load(open(facts_path))
        except Exception:
            facts = None
    out = build_semantic_map(pkg_dir, facts)
    if out:
        work = os.path.join(pkg_dir, "work")
        os.makedirs(work, exist_ok=True)
        with open(os.path.join(work, "semantic_map.md"), "w") as f:
            f.write(out)
        print(f"pcg semantic map: written ({len(out)} bytes)")
    else:
        print("pcg semantic map: skipped (no v1_source)")


if __name__ == "__main__":
    main(sys.argv[1])
