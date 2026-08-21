from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from patchclosure.config import FORBIDDEN_NAME_PARTS


def _is_forbidden(name: str) -> bool:
    low = name.lower()
    return any(part in low for part in FORBIDDEN_NAME_PARTS)


@dataclass
class Workspace:
    root: Path
    v0: Path | None = None
    v1: Path | None = None
    diff_path: Path | None = None
    exp: Path | None = None
    exp_files: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def diff_text(self) -> str:
        if not self.diff_path or not self.diff_path.is_file():
            return ""
        return self.diff_path.read_text(encoding="utf-8", errors="ignore")

    def seed_text(self) -> str:
        if not self.exp:
            return ""
        parts = []
        for name in self.exp_files:
            if name.startswith("seed_exec"):
                continue
            path = self.exp / name
            if path.is_file():
                parts.append(f"===== {name} =====\n{path.read_text(encoding='utf-8', errors='ignore')[:8000]}")
        return "\n".join(parts)

    def seed_exec(self) -> Path | None:
        if not self.exp:
            return None
        for name in ("seed_exec.py", "seed.py"):
            path = self.exp / name
            if path.is_file():
                return path
        return None


def load_workspace(root: str | Path) -> Workspace:
    root = Path(root).resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"workspace not found: {root}")
    ws = Workspace(root=root)
    for name in ("v0", "v1"):
        path = root / name
        if path.is_dir() and any(path.iterdir()):
            setattr(ws, name, path)
    for name in ("patch_real.diff", "patch.diff"):
        path = root / name
        if path.is_file():
            ws.diff_path = path
            break
    exp = root / "exp"
    if exp.is_dir():
        ws.exp = exp
        for path in sorted(exp.iterdir()):
            if not path.is_file() or path.name.startswith("."):
                continue
            if _is_forbidden(path.name):
                ws.warnings.append(f"skipped forbidden exp file: {path.name}")
                continue
            ws.exp_files.append(path.name)
    for spoil in ("README.md", "INCOMPLETE_FIX_ANALYSIS.md", "STATUS.md", "case.yaml"):
        if (root / spoil).exists():
            ws.warnings.append(f"{spoil} is present; the method will not read it")
    if (root / "scripts" / "verify.sh").exists():
        ws.warnings.append("scripts/verify.sh is present; the method will not read it")
    return ws
