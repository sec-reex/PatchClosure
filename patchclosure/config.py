from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_dotenv() -> None:
    for path in (ROOT / ".env", ROOT.parent / ".env"):
        if not path.is_file():
            continue
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip("'\"")
            if key and key not in os.environ:
                os.environ[key] = val


_load_dotenv()
WORK = Path(os.environ.get("PATCHCLOSURE_WORK", ROOT / "work"))
OUT = Path(os.environ.get("PATCHCLOSURE_OUT", ROOT / "out"))
EVAL_CASES = ROOT / "configs" / "eval_cases.txt"

LLM_BASE_URL = os.environ.get("PATCHCLOSURE_LLM_BASE_URL") or os.environ.get(
    "DEEPSEEK_BASE_URL", "https://api.deepseek.com"
)
LLM_API_KEY = os.environ.get("PATCHCLOSURE_LLM_API_KEY") or os.environ.get(
    "DEEPSEEK_API_KEY", ""
) or os.environ.get("OPENAI_API_KEY", "")
LLM_MODEL = os.environ.get("PATCHCLOSURE_LLM_MODEL") or os.environ.get(
    "DEEPSEEK_MODEL", "deepseek-chat"
)

PLATFORM_URL = os.environ.get("PCB_PLATFORM_URL", "http://127.0.0.1:8787")
BENCHMARK_ROOT = Path(
    os.environ.get(
        "PCB_BENCHMARK_ROOT",
        ROOT.parent / "benchmark_forgithubrelease",
    )
)

N_ENSEMBLE = int(os.environ.get("PATCHCLOSURE_ENSEMBLE", "3"))
# Paper §impl: k=64 bytes (128 if the blocked seed is already longer).
KMAX_BYTES = int(os.environ.get("PATCHCLOSURE_KMAX_BYTES", "64"))
KMAX = int(os.environ.get("PATCHCLOSURE_KMAX", "4"))  # token-product depth for enum
CANDIDATE_CAP = int(os.environ.get("PATCHCLOSURE_CAP", "60"))
ENUM_BUDGET = int(os.environ.get("PATCHCLOSURE_ENUM_BUDGET", "200000"))
PROBE_BUDGET = int(os.environ.get("PATCHCLOSURE_PROBES", "256"))
SEARCH_SECONDS = int(os.environ.get("PATCHCLOSURE_SECONDS", "600"))
TOKEN_BUDGET = int(os.environ.get("PATCHCLOSURE_TOKENS", "200000"))

JOERN_HOME = os.environ.get(
    "JOERN_HOME",
    str(Path.home() / "joern" / "joern-cli"),
)
JAVA_HOME = os.environ.get(
    "JAVA_HOME",
    "/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home",
)

FORBIDDEN_NAME_PARTS = ("residual", "_heldout")
SEED_NAME_HINTS = ("original_poc", "seed_exec", "seed.py", "seed_")
