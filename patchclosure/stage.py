from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from patchclosure import config
from patchclosure.config import FORBIDDEN_NAME_PARTS


def read_case_list(path: Path | None = None) -> list[str]:
    path = path or config.EVAL_CASES
    ids = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ids.append(line.split()[0])
    return ids


def _forbidden(name: str) -> bool:
    low = name.lower()
    return any(part in low for part in FORBIDDEN_NAME_PARTS)


def stage_case(
    case_id: str,
    *,
    benchmark: Path | None = None,
    dest_root: Path | None = None,
    fetch: bool = False,
) -> dict:
    benchmark = Path(benchmark or config.BENCHMARK_ROOT)
    dest_root = Path(dest_root or config.WORK)
    src = benchmark / "cases" / case_id
    if not src.is_dir():
        raise FileNotFoundError(f"case not found: {src}")
    dest = dest_root / case_id
    dest.mkdir(parents=True, exist_ok=True)
    copied = []
    for diff_name in ("patch_real.diff", "patch.diff"):
        src_diff = src / diff_name
        if src_diff.is_file():
            shutil.copy2(src_diff, dest / "patch_real.diff")
            copied.append("patch_real.diff")
            break
    exp = dest / "exp"
    exp.mkdir(exist_ok=True)
    poc = src / "poc"
    if poc.is_dir():
        for path in sorted(poc.iterdir()):
            if not path.is_file() or path.name.startswith("."):
                continue
            if _forbidden(path.name):
                continue
            shutil.copy2(path, exp / path.name)
            copied.append(f"exp/{path.name}")
    seed = src / "original_poc.py"
    if seed.is_file() and not (exp / "original_poc.py").exists():
        shutil.copy2(seed, exp / "original_poc.py")
        copied.append("exp/original_poc.py")
    fetched = []
    errors = []
    if fetch:
        script = src / "scripts" / "fetch_source.sh"
        for ver in ("v0", "v1"):
            target = dest / ver
            if not script.is_file():
                errors.append(f"no fetch_source.sh for {ver}")
                continue
            try:
                proc = subprocess.run(
                    ["bash", str(script), "--version", ver, "--dest", str(target)],
                    capture_output=True,
                    text=True,
                    timeout=600,
                    check=False,
                )
                if proc.returncode != 0:
                    errors.append(f"{ver}: {proc.stderr[-200:] or proc.stdout[-200:]}")
                else:
                    fetched.append(ver)
            except (OSError, subprocess.TimeoutExpired) as exc:
                errors.append(f"{ver}: {exc}")
    return {
        "case_id": case_id,
        "dest": str(dest),
        "copied": copied,
        "fetched": fetched,
        "errors": errors,
    }


def stage_many(case_ids: list[str], **kwargs) -> list[dict]:
    return [stage_case(cid, **kwargs) for cid in case_ids]
