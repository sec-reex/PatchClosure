"""String-danger L_S from the sink operation, not a per-case payload."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

APP_HOST = "localhost"
APP_BASE = "/base"


def path_escapes(y: str) -> bool:
    depth = 0
    for part in re.split(r"[/\\]", y):
        if part == "..":
            depth -= 1
            if depth < 0:
                return True
        elif part not in ("", "."):
            depth += 1
    return False


FAMILIES = [
    ("path-traversal", r"sendFile|readFile|send_file|path\.join|open\(|download|join|decodePath",
     lambda y: path_escapes(str(y)) or ".." in str(y).replace("...", ""),
     "path escapes the served root"),
    ("crlf-injection", r"set_header|setHeader|header|writeHead|check_header",
     lambda y: ("\r" in str(y)) or ("\n" in str(y)),
     "raw CR/LF reaches a header"),
    ("open-redirect", r"redirect|location|urljoin|extractProtocol",
     lambda y: urlsplit(str(y)).netloc not in ("", APP_HOST),
     "resulting URL host is off-origin"),
    ("ssrf", r"fetch|requests|http\.get|axios|got|ip2long|netmask|contains",
     lambda y: _internal_host(str(y)),
     "host resolves internally"),
    ("cmd-injection", r"exec|spawn|system|popen|subprocess",
     lambda y: any(m in str(y) for m in (";", "|", "&", "$(", "`")),
     "shell metacharacter reaches a shell"),
]


def _internal_host(y: str) -> bool:
    host = (urlsplit(y).hostname or y).lower()
    return host.startswith(("127.", "10.", "192.168.", "169.254.", "0.")) or host in {
        "localhost", "0x7f000001",
    }


def danger_for(sink_op: str, interp_fn: str = "", danger_target: str = ""):
    blob = " ".join([sink_op or "", interp_fn or "", danger_target or ""])
    for name, pat, pred, desc in FAMILIES:
        if re.search(pat, blob, re.I) or name.split("-")[0] in danger_target.lower():
            return pred, name, desc
    target = danger_target.lower()
    if "cr" in target or "header" in target:
        return FAMILIES[1][2], "crlf-injection", FAMILIES[1][3]
    if "ip" in target or "loopback" in target or "ssrf" in target:
        return FAMILIES[3][2], "ssrf", FAMILIES[3][3]
    if "redirect" in target or "host" in target:
        return FAMILIES[2][2], "open-redirect", FAMILIES[2][3]
    return (lambda y: ".." in str(y) or "\r" in str(y) or "\n" in str(y)), "generic", danger_target
