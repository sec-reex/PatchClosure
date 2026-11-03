#!/usr/bin/env python3
"""The Patch-Closure Graph (paper §5.2) — language overlay + coverage overlay.

Nodes carry the program sites; edges carry one of the four relation types
(flows-to, interpreted-as, guarded-by, shares-duty) and a provenance tag
(tool-derived | model-proposed | hypothesized). Machine-checked accounting
counts tool-derived edges only; the model-proposed share is reported
separately (paper §5.2, priced by the ablation).

Extractors feeding the graph (paper §5.6 Extract):
  P  fold the seed PoC               (pcg_core.load_seed_candidate)
  O  changed predicates via tree-sitter over both diff sides   (this file)
  D  call graph / dispatch points via tree-sitter + frozen CodeQL
     queries for function-level dataflow (10-minute database budget) (here)

Also home of the two bounded construction operators (paper §5.4):
  slot migration    re-attach the dangerous span to another RFC 3986
                    component (host, userinfo, query, path) in fixed order
  guard follower    identify the rejecting branch by strict polarity and
                    defeat the guard's own normalization (FUXA ....// pattern)
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time

# ── language registry ────────────────────────────────────────────────────
# tree-sitter grammars present in this environment; languages outside the
# table fall back to the regex engine (recorded in provenance).
_TS_LANGS = {
    "python": "tree_sitter_python",
    "javascript": "tree_sitter_javascript",
    "typescript": "tree_sitter_typescript",
    "go": "tree_sitter_go",
    "php": "tree_sitter_php",
    "java": "tree_sitter_java",
    "c": "tree_sitter_c",
    "ruby": "tree_sitter_ruby",
    "rust": "tree_sitter_rust",
}
_EXT_LANG = {
    ".py": "python", ".js": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".jsx": "javascript", ".ts": "typescript",
    ".tsx": "typescript", ".go": "go", ".php": "php", ".java": "java",
    ".c": "c", ".h": "c", ".rb": "ruby", ".rs": "rust",
}
_SKIP_DIRS = {"node_modules", "vendor", ".git", "dist", "build", "target",
              "__pycache__", ".venv", "venv", "test", "tests", "spec",
              "fixtures", "testdata", "examples", "docs", "coverage"}

_CALL_NODE_TYPES = {"call", "call_expression", "function_call_expression",
                    "scoped_call_expression", "member_call_expression",
                    "method_invocation", "new_expression", "object_creation_expression"}
_FN_NODE_TYPES = {"function_definition", "function_declaration",
                  "method_definition", "method_declaration", "function_item",
                  "function", "method", "proc", "func_declaration"}
# broader function-like set for guard attribution (anonymous handlers count)
_FUNCTION_LIKE = _FN_NODE_TYPES | {"function_expression", "arrow_function",
                                   "generator_function", "generator_function_declaration",
                                   "lambda", "anonymous_function"}
_STR_NODE_TYPES = {"string", "string_literal", "interpreted_string_literal",
                   "raw_string_literal", "encapsed_string", "atom"}
_NAME_FIELD = ("function", "name", "method", "callee")

_PARSER_CACHE: dict = {}


def _parser(lang: str):
    """Lazily build a tree-sitter parser; None when the grammar is absent."""
    if lang in _PARSER_CACHE:
        return _PARSER_CACHE[lang]
    mod_name = _TS_LANGS.get(lang)
    p = None
    if mod_name:
        try:
            import importlib
            from tree_sitter import Language, Parser
            mod = importlib.import_module(mod_name)
            fn = getattr(mod, "language", None)
            if fn is None:  # multi-language packs expose language_<name>()
                fn = getattr(mod, f"language_{lang}", None) or \
                     getattr(mod, f"language_{lang.replace('typescript', 'typescript')}", None)
            if fn is None and lang == "typescript":
                fn = mod.language_typescript
            p = Parser(Language(fn())) if fn else None
        except Exception:
            p = None
    _PARSER_CACHE[lang] = p
    return p


def detect_langs(root: str, patch_text: str = "") -> list:
    """Languages present in V1 source ∪ touched by the patch."""
    langs = set()
    for line in patch_text.splitlines():
        if line.startswith("+++ b/"):
            langs.add(_EXT_LANG.get(os.path.splitext(line[6:])[1], ""))
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        if len(langs) > 4:
            break
        for fn in filenames[:200]:
            langs.add(_EXT_LANG.get(os.path.splitext(fn)[1], ""))
    return sorted(l for l in langs if l)


def _node_text(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _first_string_child(node, src: bytes):
    """First string literal within two levels of the call node — arguments
    are wrapped in an argument_list/arguments node in every grammar."""
    for ch in node.children:
        if ch.type in _STR_NODE_TYPES:
            return _node_text(ch, src).strip("\"'` ")
    for ch in node.children:
        for gc in ch.children:
            if gc.type in _STR_NODE_TYPES:
                return _node_text(gc, src).strip("\"'` ")
    return None


def _call_name(node, src: bytes):
    for field in _NAME_FIELD:
        ch = node.child_by_field_name(field)
        if ch is not None:
            return _node_text(ch, src).strip()
    for ch in node.children:
        if ch.type.endswith("identifier") or ch.type in ("identifier", "name", "attribute", "member_expression", "call"):
            return _node_text(ch, src).strip().split(".")[-1]
    return None


def _walk(node, src, fn_name=None, out=None, depth=0):
    """Yield (node, enclosing_function_name). Per-file node budget keeps
    vendored/monorepo files from dominating the scan."""
    if out is None:
        out = []
    if depth > 400 or len(out) > 150_000:
        return out
    fname = fn_name
    if node.type in _FN_NODE_TYPES:
        for field in ("name", "declarator", "id"):
            ch = node.child_by_field_name(field)
            if ch is not None and ch.type.endswith("identifier"):
                fname = _node_text(ch, src)
                break
        else:
            for ch in node.children:
                if ch.type.endswith("identifier"):
                    fname = _node_text(ch, src)
                    break
    out.append((node, fname))
    for ch in node.children:
        _walk(ch, src, fname, out, depth + 1)
    return out


# ═══════════════════════════════════════════════════════════════════════
# Extractor O — changed predicates, symmetric, tree-sitter
# ═══════════════════════════════════════════════════════════════════════

_DIFF_FILE_RE = re.compile(r"^\+\+\+ b/(\S+)", re.M)

_COND_KEY = ("if", "while", "switch", "ternary", "conditional", "unless", "case")


def _is_cond_node(t: str) -> bool:
    return any(k in t for k in _COND_KEY) and "identifier" not in t


def _cond_text(node, src: bytes):
    ch = node.child_by_field_name("condition")
    if ch is None:
        for c in node.children:
            if c.type in ("parenthesized_expression", "expression", "condition"):
                ch = c
                break
    return _node_text(ch, src).strip()[:200] if ch is not None else _node_text(node, src).strip()[:200]


def ast_predicates(patch_text: str, v1_dir: str):
    """Parse the diff's touched files with tree-sitter; collect changed
    predicates symmetrically (additions, changes, deletions). A changed line
    that is not itself a condition is attributed UP to the nearest enclosing
    if/while/switch/ternary node — patches routinely edit lines inside the
    guarded branch, leaving the condition line untouched in the context.
    Also records the guard's rejecting-branch polarity material."""
    touched = _DIFF_FILE_RE.findall(patch_text)
    added, removed = [], []
    cur = None
    new_line = 0
    old_line = 0
    for line in patch_text.splitlines():
        if line.startswith("+++ b/"):
            cur = line[6:]
        elif line.startswith("@@"):
            m = re.match(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
            if m:
                old_line = int(m.group(1))
                new_line = int(m.group(2))
        elif cur and line.startswith("+") and not line.startswith("+++"):
            added.append((cur, line[1:], new_line))
            new_line += 1
        elif cur and line.startswith("-") and not line.startswith("---"):
            removed.append((cur, line[1:], old_line))
            old_line += 1
        elif cur and not line.startswith("\\"):
            new_line += 1
            old_line += 1
    cond = re.compile(r"\b(if|elif|while|switch|case|unless)\b|[!=]==?|"
                      r"\.includes\(|\.contains\(|startsWith|endsWith|"
                      r"\.test\(|preg_match|in_array|strings?\.Contains")
    cond_cfg = re.compile(r"<filesmatch|<files\s|<directory|<location|"
                          r"rewriterule|rewritecond|require\s+(?:all|valid)|"
                          r"\bdeny\b|\ballow\b", re.I)
    preds, literals = [], []
    seen_pred = set()
    for fname, text, _ln in added + removed:
        if cond.search(text) or cond_cfg.search(text):
            key = (fname, text.strip()[:160])
            if key not in seen_pred:
                seen_pred.add(key)
                preds.append({"file": fname, "side": "diff-line",
                              "text": text.strip()[:200]})
        for m in re.finditer(r"""["'`]([^"'`\n]{2,80})["'`]""", text):
            v = m.group(1)
            if re.search(r"[./\\%:]", v) or len(v) >= 3:
                literals.append(v)
    # tree-sitter attribution pass over the touched files that exist in V1
    engine = "regex-fallback"
    guards = []
    for fname in dict.fromkeys(touched):
        lang = _EXT_LANG.get(os.path.splitext(fname)[1])
        if not lang or not _parser(lang):
            continue
        path = os.path.join(v1_dir, fname) if v1_dir else fname
        if not os.path.isfile(path):
            continue
        try:
            src = open(path, "rb").read()
        except OSError:
            continue
        engine = "tree-sitter"
        try:
            tree = _parser(lang).parse(src)
        except Exception:
            continue
        changed_lines = {ln for f2, _t, ln in added if f2 == fname and ln} | \
                        {ln for f2, _t, ln in removed if f2 == fname and ln}
        spans = [(n.start_point[0] + 1, n.end_point[0] + 1, n, fn)
                 for n, fn in _walk(tree.root_node, src)]
        for (s, e, node, fn) in spans:
            if not _is_cond_node(node.type):
                continue
            if not any(s <= l <= e for l in changed_lines):
                continue
            ctxt = _cond_text(node, src)
            key = (fname, ctxt[:160])
            if key in seen_pred:
                continue
            seen_pred.add(key)
            preds.append({"file": fname, "side": "enclosing-condition",
                          "text": ctxt, "line": s})
            # innermost function-like node enclosing this condition — the
            # guard body the follower inspects (anonymous handlers count)
            innermost = None
            for (s2, e2, n2, _fn2) in spans:
                if n2.type in _FUNCTION_LIKE and s2 <= s and e <= e2:
                    innermost = n2  # DFS pre-order: later match = innermost
            if innermost is not None:
                body = _fn_body(innermost)
                if body is not None:
                    guards.append({"file": fname, "function": fn or "",
                                   "body": _node_text(body, src)[:3000],
                                   "polarity": _strict_polarity(body, src)})
    return {"engine": engine, "predicates": preds[:16],
            "literals": sorted(set(literals))[:32], "guards": guards[:8]}


def _fn_body(fn_node):
    for field in ("body", "consequence", "block"):
        ch = fn_node.child_by_field_name(field)
        if ch is not None:
            return ch
    for ch in fn_node.children:
        if ch.type in ("block", "compound_statement", "statement_block", "suite"):
            return ch
    return None


_THROW_RE = re.compile(
    r"^\s*(throw|raise|return)\b.*(\b(4\d\d|5\d\d|error|Error|ERROR|err|"
    r"Forbidden|forbidden|Unauthorized|invalid|Invalid|denied|Denied|abort|Abort)\b|"
    r"['\"]\s*['\"]|\bnull\b|\bNone\b|\bnil\b|-\s*1\b|false|False)")


_ERROR_RETURN_RE = re.compile(
    r"(?im)(?:throw\s|raise\s|return\b[^\n]{0,40}(?:4\d\d|5\d\d|error|Error|"
    r"err|Forbidden|forbidden|Unauthorized|invalid|Invalid|denied|abort|Abort)|"
    r"res(?:ponse)?\.status\(\s*[45]\d\d\s*\)|reply\.code\(\s*[45]\d\d\s*\)|"
    r"http\.Error|c\.Abort|echo\.NewHTTPError|abortWithStatus|"
    r"sendError|writeHead\(\s*[45]\d\d)")


def _strict_polarity(body, src: bytes):
    """Paper §5.4 guard follower precondition: the rejecting branch must be
    identifiable — strict polarity (first statement throw/raise, or a
    preregistered error return in the body), or a filter guard (the reject
    branch is a loop `continue`/`next` skip whose successor is determined)."""
    stmts = [c for c in body.children if c.is_named] if body else []
    if not stmts:
        return "no-body"
    first = _node_text(stmts[0], src).strip()
    if _THROW_RE.match(first):
        return "strict"
    btxt = _node_text(body, src)
    if _ERROR_RETURN_RE.search(btxt):
        return "strict"
    if re.search(r"\b(continue|next)\b", btxt) and \
            re.search(r"\b(for|foreach|while|range|each)\b", btxt):
        return "filter"
    return "non-strict"


# ═══════════════════════════════════════════════════════════════════════
# Extractor D — dispatch points, name resolution, steps-to-sink
# ═══════════════════════════════════════════════════════════════════════

_ROUTE_VALUE_RE = re.compile(r"^/[A-Za-z0-9_\-./:*{}\[\]]*$")


def scan_dispatch_points(v1_dir: str, langs: list, max_files: int = 800):
    """Call sites paired with a string literal (paper §5.3 candidate source)
    + a function-definition index for unique-resolution checks. For each
    dispatch site the following identifier argument (the handler) is captured
    — the name the four admission conditions resolve. Files whose paths look
    like routing surface are scanned first so monorepos don't exhaust the
    file budget before the routers are seen."""
    dispatch, fn_index, call_edges = [], {}, []
    candidates = []
    for dirpath, dirnames, filenames in os.walk(v1_dir):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        rel_dir = os.path.relpath(dirpath, v1_dir)
        for fn in filenames:
            lang = _EXT_LANG.get(os.path.splitext(fn)[1])
            if not lang or lang not in langs or not _parser(lang):
                continue
            rel = os.path.normpath(os.path.join(rel_dir, fn))
            priority = 0 if re.search(
                r"(?i)(router|route|controller|handler|api|web|server|app|view|endpoint)",
                rel) else 1
            candidates.append((priority, rel, lang))
    candidates.sort()
    seen_files = 0
    for _, rel, lang in candidates:
        if seen_files >= max_files:
            break
        path = os.path.join(v1_dir, rel)
        try:
            src = open(path, "rb").read()
        except OSError:
            continue
        if len(src) > 1_500_000:
            continue
        seen_files += 1
        try:
            tree = _parser(lang).parse(src)
        except Exception:
            continue
        for node, fn_name in _walk(tree.root_node, src):
            if node.type in _FN_NODE_TYPES and fn_name:
                fn_index.setdefault(fn_name, []).append(rel)
            if node.type in _CALL_NODE_TYPES:
                lit = _first_string_child(node, src)
                if lit and 1 <= len(lit) <= 120:
                    handler = None
                    # the handler argument may sit one level down (an
                    # argument_list); prefer the first identifier that
                    # is not a well-known ambient parameter
                    probe = [c for c in node.children] + \
                            [gc for c in node.children for gc in c.children]
                    for ch in probe:
                        if ch.is_named and ch.type not in _STR_NODE_TYPES:
                            t = _node_text(ch, src).strip()
                            if re.fullmatch(r"[A-Za-z_]\w*", t or "") and \
                                    t.lower() not in ("err", "ctx", "req", "res", "w", "r", "c"):
                                handler = t
                                break
                    dispatch.append({"file": rel, "line": node.start_point[0] + 1,
                                     "call": _call_name(node, src) or "",
                                     "literal": lit, "lang": lang,
                                     "caller": fn_name or "",
                                     "handler": handler,
                                     "route_like": bool(_ROUTE_VALUE_RE.match(lit))})
                if fn_name and node.type in _CALL_NODE_TYPES:
                    call_edges.append((fn_name, (_call_name(node, src) or "").split(".")[-1]))
    return dispatch, fn_index, call_edges


_SPAN_CACHE = {}


def symbol_spans(path: str, lang: str):
    """THE single symbol substrate: tree-sitter function spans per file
    [(start_line, end_line, name)]. Memoized; empty for languages without an
    installed grammar (callers fall back to their quarantined regex)."""
    key = (path, lang)
    if key in _SPAN_CACHE:
        return _SPAN_CACHE[key]
    spans = []
    p = _parser(lang)
    if p and os.path.isfile(path):
        try:
            src = open(path, "rb").read()
            tree = p.parse(src)
            for node, fn in _walk(tree.root_node, src):
                if node.type in _FN_NODE_TYPES and fn:
                    spans.append((node.start_point[0] + 1, node.end_point[0] + 1, fn))
        except Exception:
            spans = []
    spans.sort()
    _SPAN_CACHE[key] = spans
    return spans


def enclosing_symbol(path: str, lang: str, line: int):
    """Innermost function whose span contains `line` — the tree-sitter
    replacement for per-language signature regexes."""
    best = None
    for (s, e, name) in symbol_spans(path, lang):
        if s <= line <= e and (best is None or s >= best[0]):
            best = (s, e, name)
    return {"name": best[2], "line": best[0]} if best else None


def resolve_name(name: str, fn_index: dict):
    """Paper §5.3 condition 2/3: short name resolves to exactly one project
    symbol; one-to-many is dropped."""
    hits = fn_index.get(name, [])
    if len(hits) == 1:
        return hits[0]
    return None if len(hits) != 1 else hits[0]


def steps_to_sink(call_edges: list, entry: str, sink_names: set, cap: int = 6):
    """BFS steps from a candidate entry toward the patched function / sink."""
    if not sink_names:
        return cap
    adj = {}
    for a, b in call_edges:
        adj.setdefault(a, set()).add(b)
    seen, frontier, steps = {entry}, [(entry, 0)], cap
    while frontier:
        node, d = frontier.pop(0)
        if d >= cap:
            continue
        if node in sink_names:
            return d
        for nxt in adj.get(node, ()):
            if nxt not in seen:
                seen.add(nxt)
                frontier.append((nxt, d + 1))
    return cap


# ═══════════════════════════════════════════════════════════════════════
# Extractor D (CodeQL) — frozen queries, function-level dataflow
# ═══════════════════════════════════════════════════════════════════════

CODEQL_BUDGET_S = 600  # paper §5.6: ten-minute database budget per chain
CODEQL_LANGS = {"javascript": "javascript", "typescript": "javascript",
                "python": "python", "go": "go", "php": "php", "ruby": "ruby",
                "java": "java", "c": "cpp", "rust": "rust"}

# Frozen per-language queries: dispatch (string literal in call-argument
# position) and sinks (dangerous-name calls). The text never changes between
# chains — per-chain specificity comes from post-filtering against the
# chain's own extracted guard/sink tokens.
_FROZEN_QUERIES = {
    "javascript": {
        "dispatch": """
import javascript
from CallExpr call, StringLiteral lit
where exists(int i | lit = call.getArgument(i))
select lit.getValue(), call.getCalleeName(), lit.getFile().getRelativePath(), lit.getLocation().getStartLine()
""",
        "sinks": """
import javascript
from CallExpr call
where call.getCalleeName().matches("%edirect%") or call.getCalleeName().matches("%ocation%") or call.getCalleeName().matches("%endFile%") or call.getCalleeName().matches("%riteFile%")
select call.getCalleeName(), call.getLocation().getFile().getRelativePath(), call.getLocation().getStartLine()
""",
    },
    "python": {
        "dispatch": """
import python
from Call call, StringLiteral lit
where lit = call.getAnArg()
select lit.getText(), call.getFunc().(Name).getId(), lit.getLocation().getFile().getRelativePath(), lit.getLocation().getStartLine()
""",
        "sinks": """
import python
from Call call
where call.getFunc().(Name).getId().regexpMatch("(?i).*(redirect|location|send_file|open|sendfile).*")
select call.getFunc().(Name).getId(), call.getLocation().getFile().getRelativePath(), call.getLocation().getStartLine()
""",
    },
    "go": {
        "dispatch": """
import go
from CallExpr call, StringLit lit
where lit = call.getAnArgument()
select lit.getValue(), call.getCalleeName(), lit.getFile().getRelativePath(), lit.getLocation().getStartLine()
""",
        "sinks": """
import go
from CallExpr call
where call.getCalleeName().matches("%edirect%") or call.getCalleeName().matches("%riteFile%") or call.getCalleeName().matches("%erveFile%")
select call.getCalleeName(), call.getLocation().getFile().getRelativePath(), call.getLocation().getStartLine()
""",
    },
    "php": {
        "dispatch": """
import php
from FunctionCall call, StrLit lit
where lit = call.getAnArg()
select lit.getValue(), call.getName(), lit.getFile().getRelativePath(), lit.getLocation().getStartLine()
""",
        "sinks": """
import php
from FunctionCall call
where call.getName().matches("%redirect%") or call.getName().matches("%header%") or call.getName().matches("%include%")
select call.getName(), call.getFile().getRelativePath(), call.getLocation().getStartLine()
""",
    },
    "ruby": {
        "dispatch": """
import ruby
from Call call, StringLiteral lit
where lit = call.getAnArgument()
select lit.getText(), call.getMethodName(), lit.getFile().getRelativePath(), lit.getLocation().getStartLine()
""",
        "sinks": """
import ruby
from Call call
where call.getMethodName().regexpMatch("(?i).*(redirect|send_file|send_data|render).*")
select call.getMethodName(), call.getFile().getRelativePath(), call.getLocation().getStartLine()
""",
    },
    "java": {
        "dispatch": """
import java
from MethodAccess call, StringLiteral lit
where lit = call.getAnArgument()
select lit.getValue(), call.getMethod().getName(), lit.getFile().getRelativePath(), lit.getLocation().getStartLine()
""",
        "sinks": """
import java
from MethodAccess call
where call.getMethod().getName().matches("%edirect%") or call.getMethod().getName().matches("%orward%") or call.getMethod().getName().matches("%endRedirect%")
select call.getMethod().getName(), call.getFile().getRelativePath(), call.getLocation().getStartLine()
""",
    },
}


def _write_frozen_suite(lang: str, workdir: str):
    """Materialize the frozen suite for a language (bytes are constant) with
    a dependency on the standard library pack."""
    d = os.path.join(workdir, "codeql_frozen", lang)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "qlpack.yml"), "w") as f:
        f.write(f"name: pcg-frozen-{lang}\nversion: 1.0.0\n"
                f"dependencies:\n  codeql/{lang}-all: \"*\"\n")
    for kind, q in _FROZEN_QUERIES[lang].items():
        with open(os.path.join(d, f"{kind}.ql"), "w") as f:
            f.write(q)
    return d


def _ts_free_copy(v1_dir: str, workdir: str) -> str:
    """The JS autobuild aborts on some .d.ts trees; database creation runs on
    a copy with TypeScript extensions excluded (TS itself stays on
    tree-sitter)."""
    import zlib
    copy = os.path.join(workdir, "codeql_src_js")
    copy = copy + "_" + format(zlib.crc32(v1_dir.encode()), "x")
    if os.path.isdir(copy):
        shutil.rmtree(copy)
    os.makedirs(copy)
    for dirpath, dirnames, filenames in os.walk(v1_dir):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        rel = os.path.relpath(dirpath, v1_dir)
        dst = os.path.join(copy, rel) if rel != "." else copy
        os.makedirs(dst, exist_ok=True)
        for fn in filenames:
            if fn.endswith((".ts", ".tsx")):
                continue
            try:
                shutil.copy2(os.path.join(dirpath, fn), os.path.join(dst, fn))
            except OSError:
                pass
    return copy


def codeql_extract(v1_dir: str, lang: str, workdir: str, budget_s: int = CODEQL_BUDGET_S):
    """Run the frozen CodeQL suite on V1 source. Returns (rows, note). Each
    row: {kind, value, callee, file, line, provenance: 'tool-derived:codeql'}.
    Failures degrade to a note — the graph keeps its tree-sitter edges."""
    ql = CODEQL_LANGS.get(lang)
    if ql not in _FROZEN_QUERIES:
        return [], f"codeql-unavailable:{lang}"
    t0 = time.time()
    db = os.path.join(workdir, f"codeql_db_{ql}")
    suite = _write_frozen_suite(ql, workdir)
    src_root = v1_dir
    if ql == "javascript":
        src_root = _ts_free_copy(v1_dir, workdir)
    try:
        subprocess.run(["codeql", "database", "create", db,
                        f"--language={ql}", "--overwrite", "--quiet"],
                       cwd=src_root, capture_output=True, timeout=budget_s,
                       check=True)
    except subprocess.TimeoutExpired:
        shutil.rmtree(db, ignore_errors=True)
        return [], "codeql-db-budget-exceeded"
    except Exception as e:
        shutil.rmtree(db, ignore_errors=True)
        return [], f"codeql-db-failed:{type(e).__name__}"
    rows = []
    notes = []
    subprocess.run(["codeql", "pack", "install", suite], capture_output=True,
                   timeout=120)
    for kind in _FROZEN_QUERIES[ql]:
        if time.time() - t0 > budget_s:
            notes.append("codeql-query-budget-exceeded")
            break
        qf = os.path.join(suite, f"{kind}.ql")
        try:
            r = subprocess.run(["codeql", "query", "run", qf, "--database", db,
                                "--output", os.path.join(workdir, f"{kind}.bqrs")],
                               capture_output=True, timeout=240)
            if r.returncode != 0:
                notes.append(f"codeql-compile-failed:{kind}")
                continue
            d = subprocess.run(["codeql", "bqrs", "decode",
                                os.path.join(workdir, f"{kind}.bqrs"),
                                "--format=csv"], capture_output=True, timeout=120)
            for line in d.stdout.decode("utf-8", "replace").splitlines()[1:]:
                parts = next(iter(list(__import__("csv").reader([line]))), [])
                if len(parts) >= 4:
                    rows.append({"kind": kind, "value": parts[0][:120],
                                 "callee": parts[1][:80], "file": parts[2],
                                 "line": parts[3], "lang": ql,
                                 "provenance": "tool-derived:codeql"})
        except Exception as e:
            notes.append(f"codeql-run-failed:{kind}:{type(e).__name__}")
    shutil.rmtree(db, ignore_errors=True)
    return rows, ("ok" if rows else "codeql-no-rows") + ("|" + "|".join(notes) if notes else "")


# ═══════════════════════════════════════════════════════════════════════
# Bounded operators (paper §5.4)
# ═══════════════════════════════════════════════════════════════════════

def slot_migration(value: str):
    """Re-attach the dangerous span to one other RFC 3986 component
    (host, userinfo, query, path) in that fixed order. Yields
    (component, variant)."""
    m = re.match(r"^(https?://)([^/@]*)(/[^?#]*)?(\?[^#]*)?(#.*)?$", value)
    if not m:
        return []
    scheme, auth, path, query, frag = m.groups()
    path = path or "/"
    span = re.search(r"[./\\]{1,4}", value)
    if not span:
        return []
    s = span.group(0)
    out = []
    # host
    out.append(("host", f"{scheme}{s}{(path or '')}"))
    # userinfo
    out.append(("userinfo", f"{scheme}x@s{path}"))
    # query
    if path:
        out.append(("query", f"{path}?next={s}target"))
    # path: span relocated to a deeper segment
    out.append(("path", path.rstrip("/") + "/" + s + "x"))
    return [(c, v) for c, v in out if v and v != value]


def _runs(s: str):
    out, i = [], 0
    while i < len(s):
        j = i
        while j < len(s) and s[j] == s[i]:
            j += 1
        out.append((s[i], j - i))
        i = j
    return out


def guard_follower_variants(dangerous: str, guard_body: str, lang: str):
    """Paper §5.4 guard follower. Preconditions: the guard's rejecting branch
    has strict polarity (checked by the caller) and the body contains an
    explicit normalization (replace chain). Emits inputs the guard's own
    normalization rewrites into the blocked form (FUXA ....// pattern);
    bounded to ≤8 candidates, simulated under BOTH first-occurrence and
    global-replace semantics before emission."""
    variants = []
    norm_pairs = []
    # a='..'  b=''                       (string-literal pairs, any language)
    for m in re.finditer(r"""\.replace(?:All)?\(\s*(['"`])(.+?)\1\s*,\s*(['"`])(.*?)\3\s*\)""",
                         guard_body):
        norm_pairs.append((m.group(2), m.group(4)))
    # a from new RegExp('..', 'g'), b = ''   (FUXA V1 form)
    for m in re.finditer(r"""new RegExp\(\s*(['"`])(.+?)\1[^)]*\)\s*,\s*(['"`])(.*?)\3\s*\)""",
                         guard_body):
        norm_pairs.append((m.group(2), m.group(4)))
    # regex-literal form .replace(/../g, '')
    for m in re.finditer(r"""\.replace(?:All)?\(\s*/((?:[^/\\\n]|\\.)+?)/[a-z]*\s*,\s*(['"`])(.*?)\2\s*\)""",
                         guard_body):
        norm_pairs.append((m.group(1).replace("\\/", "/"), m.group(3)))
    # Go: strings.ReplaceAll(s, "..", "")
    for m in re.finditer(r"""(?:strings\.)?Replace(?:All)?\(\s*\w+\s*,\s*"(.+?)"\s*,\s*"(.*?)"\s*\)""",
                         guard_body):
        norm_pairs.append((m.group(1), m.group(2)))
    for a, b in norm_pairs:
        a = a.replace("\\/", "/").replace("\\\\", "\\")
        if not a or b == a:
            continue
        cands = set()
        # double every maximal run at once ("....//" for '../') and per run
        cands.add("".join(ch * (n * 2) for ch, n in _runs(dangerous)))
        for ch, n in _runs(dangerous):
            cands.add(dangerous.replace(ch, ch * 2, 1))
        # splice the replacement into the span
        if b:
            for i in range(len(dangerous) + 1):
                cands.add(dangerous[:i] + b + dangerous[i:])
        scored = []
        for y in sorted(cands):
            sim_first = y.replace(a, b, 1)
            sim_all = y.replace(a, b)
            if a in sim_first or a in sim_all:
                # candidates without the raw blocked form first: they survive
                # check-then-normalize guards as well as normalize-only ones
                scored.append((a in y, y))
        scored.sort()
        variants.extend(y for _bad, y in scored)
        if len(variants) >= 8:
            break
    return variants[:8]


_CLEAN_GUARD_RE = re.compile(
    r"path\.(?:Clean|Join)|filepath\.(?:Clean|Join)|path\.normalize|"
    r"path\.resolve|\.normalize\(|url\.Parse|urlparse|URL\(")


def clean_collapse_variants(guard_body: str):
    """Guard follower for Clean-type guards: the guard normalizes the value
    with path/URL normalization (no replace chain). Emits normalizable
    prefixes the guard's own normalization collapses away —
    '/x/../' + value reconstructs any leading-scheme-relative form after
    one Clean pass (Gitea path.Clean pattern). Bounded to 2 prefixes."""
    if not _CLEAN_GUARD_RE.search(guard_body or ""):
        return []
    return ["/x/../", "/x/%2e%2e/"]


# ═══════════════════════════════════════════════════════════════════════
# Graph assembly
# ═══════════════════════════════════════════════════════════════════════

def build_graph(pkg: str, patch_text: str, O: dict, P: dict, dispatch: list,
                fn_index: dict, call_edges: list, codeql_rows: list,
                codeql_note: str, model_edges: list = None):
    """Assemble the PCG: language overlay (flows-to / interpreted-as /
    guarded-by) + coverage overlay (shares-duty), every edge provenance-
    tagged. Machine-checked accounting = tool-derived edges only."""
    nodes, edges = {}, []

    def node(key, kind, meta=None):
        if key not in nodes:
            nodes[key] = {"id": key, "kind": kind, **(meta or {})}
        return key

    def edge(kind, src, dst, prov, meta=None):
        edges.append({"type": kind, "src": src, "dst": dst,
                      "provenance": prov, **(meta or {})})

    inp = node("input:x", "input-value")
    # language overlay: x —guarded-by→ changed predicates; predicates sit at
    # guard sites; normalizers on the path; the sink carries the danger lang.
    pred_ids = []
    for i, p in enumerate(O.get("predicates", [])[:8]):
        g = node(f"guard:{p['file']}#{i}", "guard",
                 {"file": p["file"], "side": p["side"], "text": p["text"][:160]})
        e = ("guarded-by", inp, g, "tool-derived" if O.get("engine") == "tree-sitter"
             else "tool-derived:regex")
        edges.append({"type": e[0], "src": e[1], "dst": e[2],
                      "provenance": e[3], "text": p["text"][:160]})
        pred_ids.append(g)
    for i, lit in enumerate(O.get("literals", [])[:12]):
        n = node(f"normalizer:lit{i}", "normalizer", {"literal": lit})
        if pred_ids:
            edges.append({"type": "interpreted-as", "src": n, "dst": pred_ids[-1],
                          "provenance": "tool-derived"})
    sink = node("sink:S", "sink", {"danger_literals": O.get("literals", [])[:6]})
    if pred_ids:
        edges.append({"type": "flows-to", "src": inp, "dst": sink,
                      "provenance": "tool-derived:codeql" if codeql_rows else "tool-derived"})
    # coverage overlay: dispatch points are carriers sharing the patch's duty
    duty = node("duty:psi", "duty", {"named_by": "patch"})
    patched_fns = set()
    for p in O.get("predicates", []):
        patched_fns.update(re.findall(r"[A-Za-z_]\w{3,}", p["text"]))
    sinks = {row["callee"] for row in codeql_rows if row["kind"] == "sinks"} | patched_fns
    admitted = 0
    for d in dispatch[:40]:
        c = node(f"carrier:{d['file']}:{d['line']}", "carrier",
                 {"file": d["file"], "line": d["line"], "call": d["call"],
                  "literal": d["literal"][:80]})
        edges.append({"type": "shares-duty", "src": duty, "dst": c,
                      "provenance": "tool-derived",
                      "steps_to_sink": steps_to_sink(call_edges, d["caller"], sinks),
                      "route_like": d["route_like"]})
        admitted += 1
    for row in codeql_rows:
        c = node(f"codeql:{row['file']}:{row['line']}", "codeql-site",
                 {"kind": row["kind"], "value": row["value"][:80]})
        edges.append({"type": "flows-to" if row["kind"] == "sinks" else "interpreted-as",
                      "src": inp if row["kind"] == "sinks" else c,
                      "dst": sink if row["kind"] == "sinks" else pred_ids[-1] if pred_ids else sink,
                      "provenance": row["provenance"]})
    for me in (model_edges or []):
        edges.append({"type": me.get("type", "shares-duty"), "src": me.get("src", "duty:psi"),
                      "dst": me.get("dst", ""), "provenance": "model-proposed",
                      **{k: v for k, v in me.items() if k not in ("type", "src", "dst")}})
    graph = {
        "schema": "pcg-graph/1",
        "overlays": {
            "language": {"input": "input:x", "guards": [e["dst"] for e in edges if e["type"] == "guarded-by"],
                         "normalizers": [n for n in nodes if n.startswith("normalizer:")],
                         "sink": "sink:S", "accepted_language": "L_G = predicates in guards",
                         "danger_language": "L_S = sink danger literals"},
            "coverage": {"duty": "duty:psi",
                         "carriers": [n for n in nodes if n.startswith("carrier:")]},
        },
        "nodes": list(nodes.values()),
        "edges": edges,
        "extractor_notes": {"codeql": codeql_note, "engine": O.get("engine"),
                            "dispatch_sites": len(dispatch), "fn_symbols": len(fn_index)},
        "accounting": {
            "edges_total": len(edges),
            "tool_derived": sum(1 for e in edges if e["provenance"].startswith("tool-derived")),
            "model_proposed": sum(1 for e in edges if e["provenance"] == "model-proposed"),
            "hypothesized": sum(1 for e in edges if e["provenance"] == "hypothesized"),
        },
    }
    return graph


def write_graph(graph: dict, pkg: str):
    d = os.path.join(pkg, "work")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, "pcg_graph.json")
    with open(path, "w") as f:
        json.dump(graph, f, indent=1, ensure_ascii=False)
    return path


def manifest_hash(graph: dict) -> str:
    blob = json.dumps({"nodes": graph["nodes"], "edges": graph["edges"]},
                      sort_keys=True).encode()
    return hashlib.sha256(blob).hexdigest()[:16]
