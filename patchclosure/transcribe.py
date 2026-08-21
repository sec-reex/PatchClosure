from __future__ import annotations

import json
import re

from patchclosure import config, llm
from patchclosure.prompts import TRANSCRIBE


def transcribe_once(pcg: dict, src: str) -> dict:
    interp = pcg.get("interpreter") or {}
    raw = llm.chat(
        [
            {
                "role": "user",
                "content": TRANSCRIBE.format(
                    danger_target=str(pcg.get("danger_target") or ""),
                    guard=json.dumps(pcg.get("guard") or {}, ensure_ascii=True),
                    interp=json.dumps(interp, ensure_ascii=True),
                    src=src[:22000],
                ),
            }
        ],
        temperature=0.4,
        max_tokens=3000,
    )
    tr = {
        "admits_py": llm.tagged_block(raw, "ADMITS"),
        "phi_py": llm.tagged_block(raw, "PHI"),
        "danger_py": llm.tagged_block(raw, "DANGER"),
    }
    meta_raw = llm.tagged_block(raw, "META")
    try:
        meta = json.loads(re.search(r"\{.*\}", meta_raw, re.S).group(0)) if meta_raw else {}
    except Exception:
        meta = {}
    tr["alphabet_hint"] = meta.get("alphabet_hint") or []
    tr["evidence"] = meta.get("evidence") or []
    return tr


def compile_predicates(tr: dict):
    ns = {
        "re": __import__("re"),
        "urllib": __import__("urllib.parse", fromlist=["parse"]),
        "unquote": __import__("urllib.parse", fromlist=["unquote"]).unquote,
    }
    for key in ("admits_py", "phi_py", "danger_py"):
        code = tr.get(key) or ""
        if not code:
            raise ValueError(f"empty {key}")
        try:
            exec(code, ns)  # noqa: S102 — transcribed predicates, sandboxed to stdlib names
        except Exception as exc:
            raise ValueError(f"compile {key} failed: {exc}") from exc
    if not all(k in ns for k in ("admits", "phi", "danger")):
        raise ValueError("transcription missing admits/phi/danger")
    return ns["admits"], ns["phi"], ns["danger"]


def ensemble(pcg: dict, src: str, n: int | None = None) -> list[dict]:
    n = max(1, n if n is not None else config.N_ENSEMBLE)
    samples = []
    last_err = None
    for _ in range(n):
        try:
            tr = transcribe_once(pcg, src)
            admits, phi, danger = compile_predicates(tr)
            samples.append({"admits": admits, "phi": phi, "danger": danger, "tr": tr})
        except Exception as exc:
            last_err = exc
            continue
    if not samples:
        raise ValueError(f"no compilable transcription sample: {last_err}")
    return samples
