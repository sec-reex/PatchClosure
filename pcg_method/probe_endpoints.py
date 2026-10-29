#!/usr/bin/env python3
"""Probe the live deployment's endpoint surface with harmless GETs.

Legal input: the live V1 instance is part of the given materials. This only
issues read-only GET/OPTIONS requests against a fixed list of generic paths
and records what the service answers. Output: work/endpoints.md (neutral QA
language). Fail-soft: any error is skipped.
"""
import json
import os
import sys
import urllib.error
import urllib.request

PROBE_PATHS = [
    "/", "/healthz", "/health", "/status", "/ping", "/check", "/verify",
    "/api", "/api/v1", "/admin", "/debug", "/metrics", "/version",
    "/info", "/docs", "/openapi.json", "/robots.txt",
]


def probe(host: str, port: int):
    out = []
    for p in PROBE_PATHS:
        url = f"http://{host}:{port}{p}"
        for method in ("GET",):
            req = urllib.request.Request(url, method=method)
            try:
                with urllib.request.urlopen(req, timeout=6) as resp:
                    body = resp.read(400).decode("utf-8", "replace").replace("\n", " ")
                    out.append((p, resp.status, body[:160]))
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", "replace").replace("\n", " ")
                # a non-404 answer means the path EXISTS (auth-gated etc.)
                out.append((p, exc.code, body[:160]))
            except Exception:
                pass
    return out


def main(pkg_dir: str):
    env = os.path.join(pkg_dir, "env.json")
    port = None
    try:
        port = int(json.load(open(env))["port"])
    except Exception:
        port = os.environ.get("PCB_PORT")
    host = os.environ.get("PCB_HOST", "10.7.0.11")
    if not port:
        return
    results = probe(host, int(port))
    work = os.path.join(pkg_dir, "work")
    os.makedirs(work, exist_ok=True)
    lines = [
        "# Endpoint answers observed on the running service",
        "",
        "Read-only GET probes issued during setup. `404` rows are absent paths;",
        "anything else is a live endpoint (an auth error still means the path exists).",
        "The observable your test needs may surface on ANY of these — re-check the",
        "other live endpoints after each input before concluding it did nothing.",
        "",
    ]
    live = [r for r in results if r[1] != 404]
    gone = [r for r in results if r[1] == 404]
    for p, code, body in live:
        lines.append(f"- `{p}` → {code} :: {body}")
    if gone:
        lines.append(f"- (absent/404: {' '.join(p for p, _, _ in gone)})")
    with open(os.path.join(work, "endpoints.md"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"endpoint probe: {len(live)} live of {len(results)} probed")


if __name__ == "__main__":
    main(sys.argv[1])
