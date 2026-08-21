from __future__ import annotations

import re
from dataclasses import dataclass, field


_SKIP_PATH = re.compile(
    r"(/(test|tests|spec|docs|doc)/|\.test\.|\.spec\.|"
    r"\.(md|txt|rst|yml|yaml)$|changelog|news|\.changeset)",
    re.I,
)


@dataclass
class Hunk:
    path: str
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    header: str = ""


def changed_source_files(diff: str) -> list[str]:
    out: list[str] = []
    for match in re.finditer(r"^\+\+\+ b/(.+)$", diff, re.M):
        path = match.group(1).strip()
        if path == "/dev/null" or _SKIP_PATH.search(path):
            continue
        if path not in out:
            out.append(path)
    return out


def added_lines(diff: str) -> list[str]:
    lines = []
    for line in diff.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            lines.append(line[1:])
    return lines


def parse_hunks(diff: str) -> list[Hunk]:
    hunks: list[Hunk] = []
    current: Hunk | None = None
    path = ""
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            path = line[6:].strip()
            continue
        if line.startswith("@@"):
            if current and (current.added or current.removed):
                hunks.append(current)
            current = Hunk(path=path, header=line)
            continue
        if current is None:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            current.added.append(line[1:])
        elif line.startswith("-") and not line.startswith("---"):
            current.removed.append(line[1:])
    if current and (current.added or current.removed):
        hunks.append(current)
    return hunks


_GUARD_HINT = re.compile(
    r"\b(if|unless|reject|raise|throw|return\s+false|forbidden|invalid|"
    r"contains|includes|match|regex|replace|normalize|decode|sanitize|"
    r"startswith|endswith|indexof|check)\b",
    re.I,
)


def guard_hunks(diff: str) -> list[Hunk]:
    """Hunks that look like an added predicate or normalizer, not tests."""
    picked = []
    for hunk in parse_hunks(diff):
        if not hunk.path or hunk.path == "/dev/null" or _SKIP_PATH.search(hunk.path):
            continue
        blob = "\n".join(hunk.added)
        if _GUARD_HINT.search(blob):
            picked.append(hunk)
    return picked or [h for h in parse_hunks(diff) if h.added and not _SKIP_PATH.search(h.path)]
