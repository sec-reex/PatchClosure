from __future__ import annotations

import re
from itertools import product


def _int_token(part: str) -> int:
    p = part.strip()
    if p.lower().startswith("0x"):
        return int(p, 16)
    if len(p) > 1 and p.startswith("0") and p.isdigit() and set(p) <= set("01234567"):
        return int(p, 8)
    return int(p, 10)


def parse_ipv4(text: str) -> list[int] | None:
    raw = (text or "").strip().strip("[]")
    if raw in {":1", "::1", "0:0:0:0:0:0:0:1"}:
        return [127, 0, 0, 1]
    mapped = re.match(r"(?i)::ffff:([\d.]+)$", raw)
    if mapped:
        return parse_ipv4(mapped.group(1))
    hexmap = re.match(r"(?i)::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$", raw)
    if hexmap:
        hi, lo = int(hexmap.group(1), 16), int(hexmap.group(2), 16)
        return [(hi >> 8) & 255, hi & 255, (lo >> 8) & 255, lo & 255]
    parts = raw.split(".")
    try:
        if len(parts) == 1:
            n = _int_token(parts[0])
            if 0 <= n <= 0xFFFFFFFF:
                return [(n >> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255]
            return None
        if not 2 <= len(parts) <= 4:
            return None
        nums = [_int_token(p) for p in parts]
    except ValueError:
        return None
    if any(n < 0 for n in nums):
        return None
    if len(nums) == 4 and all(n <= 255 for n in nums):
        return nums
    if len(nums) == 2 and nums[0] <= 255 and nums[1] <= 0xFFFFFF:
        n = (nums[0] << 24) | nums[1]
        return [(n >> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255]
    if len(nums) == 3 and nums[0] <= 255 and nums[1] <= 255 and nums[2] <= 0xFFFF:
        n = (nums[0] << 24) | (nums[1] << 16) | nums[2]
        return [(n >> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255]
    return None


def octet_encodings(value: int) -> list[str]:
    forms = [str(value)]
    forms.append("0%o" % value if value else "00")
    forms.append("0x%x" % value)
    forms.append("0X%X" % value)
    forms.append("0x%X" % value)
    forms.append("0X%x" % value)
    forms.append("0%03o" % value)
    return list(dict.fromkeys(forms))


def _compress(octets: list[int]) -> list[str]:
    """Omitted-zero spellings of the same 32-bit value (inet_aton)."""
    a, b, c, d = octets
    n = (a << 24) | (b << 16) | (c << 8) | d
    out = [f"{a}.{b}.{c}.{d}", str(n), "0x%x" % n, "0X%X" % n, "0%o" % n]
    if b == 0 and c == 0:
        out.append(f"{a}.{d}")
    if c == 0:
        out.append(f"{a}.{b}.{d}")
    out.append(f"[::ffff:{a}.{b}.{c}.{d}]")
    hi, lo = (a << 8) | b, (c << 8) | d
    out.append(f"[::ffff:{hi:x}:{lo:x}]")
    out.append(f"[::ffff:{hi:04x}:{lo:04x}]")
    return out


def encodings_of(octets: list[int]) -> list[str]:
    out = list(_compress(octets))
    per = [octet_encodings(v) for v in octets]
    for i, forms in enumerate(per):
        for form in forms:
            if form == str(octets[i]):
                continue
            combo = [str(v) for v in octets]
            combo[i] = form
            out.append(".".join(combo))
    for combo in list(product(*per))[:80]:
        out.append(".".join(combo))
    return list(dict.fromkeys(out))


def gen_ip_candidates(
    samples: list[dict] | None = None,
    *,
    targets: tuple[str, ...] | list[str] = (),
    cap: int = 160,
) -> dict:
    """Radix / omitted-zero spellings of IPs that already appear in the seed.

    Filtered by a measured admits() when one exists. This is not a
    residual host list: empty targets produce no fragments.
    """
    admits_preds = [s["admits"] for s in (samples or []) if "admits" in s]
    cands: list[str] = []
    for tgt in targets:
        octets = parse_ipv4(tgt)
        if octets:
            cands.extend(encodings_of(octets))
    cands = list(dict.fromkeys(cands))
    ranked, others = [], []
    for x in cands:
        admitted = False
        for pred in admits_preds:
            try:
                if pred(x):
                    admitted = True
                    break
            except Exception:
                pass
        (ranked if admitted else others).append(x)
    if not admits_preds:
        ranked, others = cands, []
    fragments = [{"x": x, "admitted": True} for x in ranked] + [
        {"x": x, "admitted": False} for x in others
    ]
    return {
        "family": "ssrf_ip",
        "n_candidates": len(cands),
        "n_admitted": len(ranked),
        "fragments": fragments[:cap],
    }
