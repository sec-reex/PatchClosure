from __future__ import annotations

from collections.abc import Callable


PROBE = "/.%\\:@ \t\r\n?#&=;<>\"'"
FORCED = ("/", ".", "\r", "\n", "\\", "%")
DANGER_CHARS = "/.\\\r\n:@"


def alphabet_from_interpreter(phi: Callable[[str], str], hint: list | None = None) -> list[str]:
    """Keep a symbol iff phi treats it specially, plus structural tokens.

    Σ_φ is the symbols the grounded interpreter branches on,
    not a payload wordlist.
    """
    seed: list[str] = []
    for tok in hint or []:
        if isinstance(tok, str) and len(tok) == 1:
            seed.append(tok)
    for ch in PROBE:
        if ch not in seed:
            seed.append(ch)
    alpha: list[str] = []
    for ch in seed:
        try:
            if phi(ch * 3) != ch * 3:
                alpha.append(ch)
        except Exception:
            continue
    for ch in FORCED:
        if ch not in alpha:
            alpha.append(ch)
    if "a" not in alpha:
        alpha.append("a")
    for ch in DANGER_CHARS:
        for tok in ("%%%02x" % ord(ch), "%%%02X" % ord(ch), "%%u%04x" % ord(ch)):
            if tok not in alpha:
                alpha.append(tok)
    if "%00" not in alpha:
        alpha.append("%00")
    return list(dict.fromkeys(alpha))
