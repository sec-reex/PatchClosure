"""Cut nominated interpreters with tree-sitter (paper §impl)."""
from __future__ import annotations

import re
from pathlib import Path

try:
    from tree_sitter_language_pack import get_parser
except ImportError:  # pragma: no cover
    get_parser = None

EXT_LANG = {
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "tsx",
    ".py": "python", ".go": "go", ".java": "java",
    ".php": "php", ".rb": "ruby",
}

IF_NODES = {
    "javascript": {"if_statement"}, "typescript": {"if_statement"}, "tsx": {"if_statement"},
    "python": {"if_statement"}, "go": {"if_statement"}, "java": {"if_statement"},
    "php": {"if_statement"}, "ruby": {"if", "unless"},
}
CALL_NODES = {
    "javascript": {"call_expression"}, "typescript": {"call_expression"}, "tsx": {"call_expression"},
    "python": {"call"}, "go": {"call_expression"}, "java": {"method_invocation"},
    "php": {"function_call_expression", "member_call_expression"},
    "ruby": {"call", "method_call"},
}
FN_NODES = {
    "function_declaration", "method_declaration", "function_definition",
    "method_definition", "function", "function_item",
}
NORMALIZE = re.compile(
    r"\b(replace|replaceAll|normalize|decode|encode|escape|unescape|sanitize|"
    r"strip|trim|toLowerCase|canonical|resolve|clean|filter)\b",
    re.I,
)


def lang_for(path: str) -> str | None:
    for ext, lang in EXT_LANG.items():
        if str(path).endswith(ext):
            return lang
    return None


def available() -> bool:
    return get_parser is not None


def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


def _text(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "ignore")


def added_code(diff_text: str, target_file: str) -> str:
    out, cur = [], None
    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            cur = line[6:].strip()
            continue
        if cur == target_file and line.startswith("+") and not line.startswith("+++"):
            out.append(line[1:])
    return "\n".join(out)


def added_line_numbers(diff_text: str, target_file: str) -> set[int]:
    added, cur, newno = set(), None, 0
    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            cur = line[6:].strip()
            continue
        if cur != target_file:
            continue
        match = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
        if match:
            newno = int(match.group(1))
            continue
        if line.startswith("+") and not line.startswith("+++"):
            added.add(newno)
            newno += 1
        elif line.startswith("-") and not line.startswith("---"):
            pass
        elif line.startswith("\\"):
            pass
        else:
            newno += 1
    return added


def extract_from_added(path: str, diff_text: str) -> dict:
    code = added_code(diff_text, path)
    return extract(path, code, set()) if code.strip() else {"lang": lang_for(path), "guards": [], "calls": []}


def extract(path: str, source: str, added: set[int]) -> dict:
    lang = lang_for(path)
    if not lang or not available():
        return {"lang": lang, "guards": [], "calls": [], "note": "no grammar"}
    parser = get_parser(lang)
    src = source.encode("utf-8", "ignore")
    tree = parser.parse(src)
    guards, calls = [], []
    for node in _walk(tree.root_node):
        line = node.start_point[0] + 1
        if added and line not in added:
            continue
        code = _text(node, src)
        if node.type in IF_NODES.get(lang, ()):
            cond = node.child_by_field_name("condition") or node.child_by_field_name("test") or node
            guards.append({"kind": "PREDICATE", "line": line, "code": _text(cond, src)[:200],
                           "tokens": _idents(cond, src)})
        elif node.type == "regex":
            guards.append({"kind": "REGEX", "line": line, "code": code[:120], "tokens": []})
        elif node.type in CALL_NODES.get(lang, ()):
            callee = code.split("(")[0].strip()
            if NORMALIZE.search(callee):
                guards.append({"kind": "NORMALIZE", "line": line, "code": code[:160],
                               "tokens": _idents(node, src)})
            calls.append({"callee": callee[-60:], "line": line, "code": code[:160]})
    return {"lang": lang, "guards": _dedup(guards), "calls": calls, "literals": literals_in(source)}


def _idents(node, src: bytes) -> list[str]:
    out = []
    for child in _walk(node):
        if child.type in {
            "identifier", "property_identifier", "member_expression",
            "field_access", "scoped_identifier",
        }:
            text = _text(child, src)
            if text and text not in out:
                out.append(text)
    return out[:8]


def _dedup(guards: list[dict]) -> list[dict]:
    seen, out = set(), []
    for guard in guards:
        key = (guard["kind"], guard.get("line"), guard.get("code"))
        if key not in seen:
            seen.add(key)
            out.append(guard)
    return out


def literals_in(source: str) -> list[str]:
    found = re.findall(r"""(['\"])((?:\\.|(?!\1).){0,32})\1""", source)
    lits = []
    for _, body in found:
        body = bytes(body, "utf-8").decode("unicode_escape", "ignore")
        if body and body not in lits:
            lits.append(body)
    return lits


def list_functions(srcroot: Path, files: list[str] | None = None, cap: int = 80) -> list[str]:
    """Defined function names in changed files (or a shallow walk)."""
    if not available() or not srcroot:
        return []
    names: list[str] = []
    paths: list[Path] = []
    if files:
        for rel in files:
            hit = Path(srcroot) / rel
            if hit.is_file():
                paths.append(hit)
            else:
                paths.extend(p for p in Path(srcroot).rglob(Path(rel).name) if p.is_file())
    if not paths:
        for ext in EXT_LANG:
            paths.extend(list(Path(srcroot).rglob(f"*{ext}"))[:40])
    for path in paths[:60]:
        lang = lang_for(str(path))
        if not lang:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        src = text.encode("utf-8", "ignore")
        try:
            tree = get_parser(lang).parse(src)
        except Exception:
            continue
        for node in _walk(tree.root_node):
            if node.type not in FN_NODES:
                continue
            name = node.child_by_field_name("name")
            if not name:
                continue
            tok = _text(name, src)
            if tok and tok not in names:
                names.append(tok)
            if len(names) >= cap:
                return names
    return names


def locate_function(srcroot: Path, fn: str) -> dict | None:
    """Find the definition of `fn` (last identifier) and return the slice."""
    if not available() or not srcroot or not fn:
        return None
    tok = re.split(r"[.(#:/\\]", str(fn).split("::")[-1])[-1].strip()
    if not tok or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", tok):
        return None
    for ext, lang in EXT_LANG.items():
        for path in Path(srcroot).rglob(f"*{ext}"):
            low = path.as_posix().lower()
            if "node_modules" in low or "/vendor/" in low:
                continue
            if "/tests/" in low or "/__tests__/" in low or ".test." in low:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if tok not in text:
                continue
            hit = _fn_in_file(path, text, lang, tok)
            if hit:
                return hit
            hit = _fn_by_text(path, text, lang, tok)
            if hit:
                return hit
    return None


def _fn_by_text(path: Path, text: str, lang: str, tok: str) -> dict | None:
    """Fallback when the grammar misses a definition (Java static methods, etc.)."""
    matches = list(re.finditer(
        rf"(?:public|private|protected|static|\s)+[\w<>,\[\]]+\s+{tok}\s*\(", text
    ))
    if not matches:
        matches = list(re.finditer(rf"(?:function|def|fn)\s+{tok}\s*\(", text))
    if not matches:
        return None
    best = None
    for match in matches:
        start = text.rfind("\n", 0, match.start()) + 1
        body = text[start:start + 8000]
        cand = {
            "path": path,
            "lang": lang,
            "name": tok,
            "line": text[:match.start()].count("\n") + 1,
            "body": body,
            "params": [],
            "source_bytes": text.encode("utf-8", "ignore"),
            "file_text": text,
        }
        if best is None or len(body) > len(best["body"]):
            best = cand
    return best


def _fn_in_file(path: Path, text: str, lang: str, tok: str) -> dict | None:
    src = text.encode("utf-8", "ignore")
    tree = get_parser(lang).parse(src)
    best = None
    for node in _walk(tree.root_node):
        if node.type in FN_NODES:
            name = node.child_by_field_name("name")
            if name and _text(name, src) == tok:
                body = _text(node, src)
                cand = {
                    "path": path,
                    "lang": lang,
                    "name": tok,
                    "line": node.start_point[0] + 1,
                    "body": body,
                    "params": _params(node, src),
                    "source_bytes": src,
                    "file_text": text,
                }
                if best is None or len(body) > len(best["body"]):
                    best = cand
    if best:
        return best
    for node in _walk(tree.root_node):
        if node.type not in ("assignment_expression", "variable_declarator"):
            continue
        name = node.child_by_field_name("name")
        if name is None or _text(name, src) != tok:
            continue
        if not any(d.type in ("function_expression", "arrow_function", "function") for d in _walk(node)):
            continue
        return {
            "path": path,
            "lang": lang,
            "name": tok,
            "line": node.start_point[0] + 1,
            "body": _text(node, src),
            "params": _params(node, src),
            "source_bytes": src,
            "file_text": text,
        }
    return None


def _params(node, src: bytes) -> list[str]:
    params = node.child_by_field_name("parameters") or node.child_by_field_name("formal_parameters")
    if params is None:
        return []
    names = []
    for child in _walk(params):
        if child.type in ("identifier", "simple_identifier"):
            names.append(_text(child, src))
    return names
