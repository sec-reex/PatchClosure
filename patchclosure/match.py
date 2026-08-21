from __future__ import annotations

import re


_IP_HINT = re.compile(
    r"\b(ssrf|loopback|private[- ]?ip|netmask|ip2long|internal host|cidr)\b",
    re.I,
)
_OBLIGATION_HINT = re.compile(
    r"\b(sibling|obligation|authz|authorization|csrf|same duty|unguarded)\b",
    re.I,
)


def classify(pcg: dict, seed: dict | None = None) -> dict:
    declared = str(pcg.get("gap_type") or "unclear").lower()
    blob = " ".join(
        [
            declared,
            str(pcg.get("danger_target") or ""),
            str((pcg.get("sink") or {}).get("op") or ""),
            str(pcg.get("obligation") or ""),
            str(seed or ""),
        ]
    )
    family = declared if declared in {"language", "obligation", "unclear"} else "unclear"
    if family == "unclear" and _OBLIGATION_HINT.search(blob):
        family = "obligation"
    if family == "unclear":
        family = "language"
    return {
        "family": family,
        "ip_family": bool(_IP_HINT.search(blob)),
        "declared": declared,
    }
