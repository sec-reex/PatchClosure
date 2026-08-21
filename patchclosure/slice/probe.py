"""Probe set from the interpreter's own branch structure.

Up to 256 inputs: literal bytes and escape forms the slice tests, at
the lengths it distinguishes. Not a payload wordlist.
"""
from __future__ import annotations

import re

from patchclosure import config
from patchclosure.slice.treesitter import literals_in


ESCAPE_FORMS = ("%s", "%02x", "%02X", "%u%04x", "\\x%02x", "\\u%04x")

# Character class the slice itself tests (trim / C0 / \s). Not a CVE list.
_CLASS_C0 = re.compile(
    r"trim|strip|lstrip|rstrip|isSpace|isspace|isSpecial|isControl|"
    r"charCodeAt|\\\\s|<=\s*32|<\s*33|<\s*0x20|<=\s*0x1f|<=\s*0x20",
    re.I,
)


def probes_from_source(source: str, extra_hint: list[str] | None = None, cap: int | None = None) -> list[str]:
    cap = cap if cap is not None else config.PROBE_BUDGET
    literals = literals_in(source)
    chars: list[str] = []
    tokens: list[str] = list(extra_hint or [])
    for lit in literals:
        tokens.append(lit)
        for ch in lit:
            if ch not in chars:
                chars.append(ch)
    for hex2 in re.findall(r"\\x([0-9A-Fa-f]{2})", source or ""):
        ch = chr(int(hex2, 16))
        if ch not in chars:
            chars.append(ch)
    for hex4 in re.findall(r"\\u([0-9A-Fa-f]{4})", source or ""):
        ch = chr(int(hex4, 16))
        if ch not in chars:
            chars.append(ch)
    for ch in "/.%\\:@\r\n\t?#&=;":
        if ch not in chars:
            chars.append(ch)
    lengths = {1, 2, 3, 4}
    for lit in literals:
        lengths.add(min(len(lit), 16) or 1)
    out: list[str] = []

    def add(value: str):
        if value not in out:
            out.append(value)

    # Encodings the slice actually branches on, before dumping file literals.
    for ch in "/.%\\:@":
        add(ch)
        add("%%%02x" % ord(ch))
        add("%%%02X" % ord(ch))
        add("%%u%04x" % ord(ch))
    for tok in tokens:
        add(tok)
    if _CLASS_C0.search(source or ""):
        seeds = [t for t in tokens if t and 0 < len(t) <= 24][:6]
        for code in range(32):
            add(chr(code))
            for tok in seeds:
                add(chr(code) + tok)
    for ch in chars:
        for n in sorted(lengths):
            add(ch * n)
        code = ord(ch)
        if code < 256:
            add("%%%02x" % code)
            add("%%%02X" % code)
            add("%%u%04x" % code)
    add("%00")
    add("..")
    add("../")
    add("\r")
    add("\n")
    add("\r\n")
    # branch-like combinations of two extracted tokens, bounded
    for a in tokens[:8]:
        for b in tokens[:8]:
            add(a + b)
            if len(out) >= cap:
                return out[:cap]
    return out[:cap]


def measure(phi, probes: list[str]) -> list[tuple[str, str]]:
    pairs = []
    for probe in probes:
        try:
            out = phi(probe)
        except Exception:
            continue
        if out is None:
            continue
        pairs.append((probe, str(out)))
    return pairs


def alphabet_from_pairs(pairs: list[tuple[str, str]], extra: list[str] | None = None) -> list[str]:
    """Σ_φ: symbols the measured transduction actually branches on."""
    reactive: list[str] = []
    for inp, out in pairs:
        if inp != out:
            for ch in inp:
                if ch not in reactive:
                    reactive.append(ch)
            # keep multi-char escape tokens that changed the output
            for tok in re.findall(r"%u[0-9A-Fa-f]{4}|%[0-9A-Fa-f]{2}", inp):
                if tok not in reactive:
                    reactive.append(tok)
    for tok in extra or []:
        if tok not in reactive:
            reactive.append(tok)
    for forced in ("/", ".", "\r", "\n", "\\", "%", "a"):
        if forced not in reactive:
            reactive.append(forced)
    return reactive
