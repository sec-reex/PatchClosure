"""Patch overlay: map the unified diff onto v1 program points.

Added predicates and normalizers become guard nodes at the sites that
host them.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from patchclosure import diffparse
from patchclosure.slice.treesitter import extract_from_added, lang_for


@dataclass
class GuardNode:
    path: str
    line: int | None
    kind: str  # PREDICATE | NORMALIZE | REGEX
    code: str
    tokens: list[str] = field(default_factory=list)
    lang: str | None = None


def overlay_guards(diff: str) -> list[GuardNode]:
    nodes: list[GuardNode] = []
    for path in diffparse.changed_source_files(diff):
        added = extract_from_added(path, diff)
        lang = added.get("lang") or lang_for(path)
        for guard in added.get("guards") or []:
            nodes.append(
                GuardNode(
                    path=path,
                    line=guard.get("line"),
                    kind=guard.get("kind") or "PREDICATE",
                    code=guard.get("code") or "",
                    tokens=list(guard.get("tokens") or []),
                    lang=lang,
                )
            )
        if not added.get("guards"):
            for hunk in diffparse.guard_hunks(diff):
                if hunk.path != path:
                    continue
                nodes.append(
                    GuardNode(
                        path=path,
                        line=None,
                        kind="PREDICATE",
                        code="\n".join(hunk.added[:16]),
                        lang=lang,
                    )
                )
    return nodes


def primary_language(diff: str) -> str | None:
    counts: dict[str, int] = {}
    for path in diffparse.changed_source_files(diff):
        lang = lang_for(path)
        if lang:
            counts[lang] = counts.get(lang, 0) + 1
    if not counts:
        return None
    return max(counts, key=counts.get)
