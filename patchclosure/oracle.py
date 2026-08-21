"""One generic checker per effect channel.

The oracle invokes the candidate and looks for this trial's PCBFLAG_*
on the channel. It does not know residual payloads.
"""
from __future__ import annotations

import re
from urllib.parse import unquote

FLAG_RE = re.compile(r"PCBFLAG_[A-Za-z0-9_]+")

CHANNELS = (
    "disk_file",
    "environment",
    "internal_sidecar",
    "database_cell",
    "probe_string",
    "authz_object",
    "browser_cookie",
    "hang_watchdog",
)


def observe_flag(payload) -> str | None:
    if payload is None:
        return None
    if isinstance(payload, dict):
        for key in (
            "flag", "body", "raw", "fetched_body", "location", "headers",
            "cookie", "gated_secret", "check_body", "set_body",
            "client_output", "response", "X",
        ):
            hit = observe_flag(payload.get(key))
            if hit:
                return hit
        text = str(payload)
    else:
        text = str(payload)
    match = FLAG_RE.search(text)
    return match.group(0) if match else None


def check_channel(channel: str, result: dict, *, attacker: str = "evil.pcb") -> tuple[bool, str]:
    """Return (fired, why). Flag observation wins on every channel."""
    channel = (channel or "").lower()
    flag = observe_flag(result)
    if flag and channel not in {"probe_string", "header_inject", "open_redirect"}:
        return True, f"flag on channel: {flag}"
    raw = str(result.get("raw") or result.get("body") or "")
    loc = str(result.get("location") or "")
    fetched = str(result.get("fetched_body") or "")
    if channel in {"disk_file", "read_exfil", "environment"}:
        return False, "no flag in body"
    if channel in {"internal_sidecar", "ssrf_sidecar"}:
        if fetched and FLAG_RE.search(fetched):
            return True, "flag in sidecar body"
        return False, "sidecar body has no flag"
    if channel in {"probe_string", "header_inject", "open_redirect"}:
        head = re.split(r"\r\n\r\n|\n\n", raw, maxsplit=1)[0]
        for line in re.split(r"\r\n|\r|\n", head):
            if line.lower().startswith("x-pcb-injected:"):
                return True, f"injected header {line[:80]!r}"
        for cand in (loc, unquote(loc)):
            if attacker and attacker in cand.lower():
                return True, f"off-origin Location={cand[:80]!r}"
        body = str(
            result.get("body")
            or result.get("fetched_body")
            or result.get("client_output")
            or result.get("response")
            or result.get("X")
            or result.get("flag")
            or ""
        )
        hit = FLAG_RE.search(body)
        if hit:
            return True, f"flag in effect body: {hit.group(0)}"
        if result.get("flag_seen"):
            return True, "flag_seen"
        return False, "probe channel quiet"
    if channel == "hang_watchdog":
        if result.get("hung") or result.get("timeout"):
            return True, "watchdog fired"
        return False, "no hang"
    if channel in {"authz_object", "browser_cookie", "database_cell"}:
        return False, "no flag on channel"
    return False, "no effect"


def channel_for_family(oracle_family: str | None, danger_family: str | None) -> str:
    fam = (oracle_family or danger_family or "").lower()
    if "ssrf" in fam:
        return "internal_sidecar"
    if "redirect" in fam or "crlf" in fam or "header" in fam:
        return "probe_string"
    if "dos" in fam or "hang" in fam or "redos" in fam:
        return "hang_watchdog"
    if "xss" in fam:
        return "browser_cookie"
    if "sql" in fam:
        return "database_cell"
    if "auth" in fam or "sibling" in fam:
        return "authz_object"
    return "disk_file"
