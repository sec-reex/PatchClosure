from __future__ import annotations

from pathlib import Path

SOURCE_SUFFIXES = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".rb", ".php", ".java", ".kt", ".go", ".rs", ".cs",
    ".c", ".cc", ".cpp", ".h", ".hpp", ".coffee",
}


def read_file(root: Path, relpath: str, *, limit: int = 0) -> str:
    if not root or not root.exists() or not relpath:
        return ""
    direct = root / relpath
    if direct.is_file():
        text = direct.read_text(encoding="utf-8", errors="ignore")
        return text[:limit] if limit else text
    name = Path(relpath).name
    hits = [
        p
        for p in root.rglob(name)
        if p.is_file() and (str(p).endswith(relpath) or p.name == name)
    ]
    if not hits:
        return ""
    text = hits[0].read_text(encoding="utf-8", errors="ignore")
    return text[:limit] if limit else text


def source_blob(root: Path, files: list[str], *, per: int = 9000, total: int = 22000) -> str:
    parts: list[str] = []
    used = 0
    for rel in files:
        text = read_file(root, rel, limit=per)
        if not text:
            continue
        chunk = f"\n===== {rel} ({len(text.splitlines())} lines) =====\n{text}\n"
        parts.append(chunk)
        used += len(chunk)
        if used >= total:
            break
    return "".join(parts)[:total]


def find_symbol_file(root: Path, name: str) -> Path | None:
    if not root or not root.exists() or not name:
        return None
    token = re_last_ident(name)
    if not token:
        return None
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in SOURCE_SUFFIXES:
            continue
        if "test" in str(path).lower():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if token in text:
            return path
    return None


def re_last_ident(name: str) -> str:
    import re

    parts = re.split(r"[.(#:/\\]", str(name))
    for part in reversed(parts):
        if part and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", part):
            return part
    return ""
