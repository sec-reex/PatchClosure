"""Obligation-gap discharge: Semgrep call-site + taint, then IssueIdentity."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from copy import deepcopy
from pathlib import Path

from patchclosure import llm
from patchclosure.prompts import CARRIERS
from patchclosure.source import re_last_ident


def propose_carrier_patterns(diff: str, src: str) -> dict:
    if not llm.available():
        return {}
    raw = llm.chat(
        [{"role": "user", "content": CARRIERS.format(diff=diff[:6000], src=src[:16000])}],
        max_tokens=1200,
    )
    return llm.parse_json_object(raw)


def _semgrep(root: Path, pattern: str, lang: str, timeout: int = 120) -> list[dict]:
    if not shutil.which("semgrep") or not pattern:
        return []
    cmd = ["semgrep", "--json", "--quiet", "--disable-version-check", "-e", pattern, "-l", lang, str(root)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if not proc.stdout.strip():
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    return _fmt(data.get("results") or [])


def _fmt(results) -> list[dict]:
    out = []
    for match in results:
        out.append({
            "path": match.get("path", ""),
            "line": (match.get("start") or {}).get("line"),
            "code": ((match.get("extra") or {}).get("lines") or "")[:120],
        })
    return out


def taint(root: Path, source_pattern: str, sink_pattern: str, lang: str, timeout: int = 180) -> list[dict]:
    if not shutil.which("semgrep") or not source_pattern or not sink_pattern:
        return []
    rule = {
        "rules": [{
            "id": "pcg-taint",
            "languages": [lang],
            "message": "taint",
            "severity": "INFO",
            "mode": "taint",
            "pattern-sources": [{"pattern": source_pattern}],
            "pattern-sinks": [{"pattern": sink_pattern}],
        }]
    }
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        json.dump(rule, fh)
        path = fh.name
    try:
        proc = subprocess.run(
            ["semgrep", "--json", "--quiet", "--disable-version-check", "--config", path, str(root)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if not proc.stdout.strip():
            return []
        data = json.loads(proc.stdout)
        return _fmt(data.get("results") or [])
    except Exception:
        return []
    finally:
        try:
            Path(path).unlink()
        except OSError:
            pass


def _grep_callee(root: Path, callee: str) -> list[dict]:
    name = re_last_ident(callee)
    if not name or not root:
        return []
    hits = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in {".py", ".js", ".php", ".rb", ".java", ".go"}:
            continue
        if "test" in str(path).lower():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if name in line:
                hits.append({"path": str(path), "line": i, "code": line.strip()[:120]})
                if len(hits) >= 200:
                    return hits
    return hits


def rank_by_reach(unguarded: list[dict], tainted: list[dict], guarded: list[dict]) -> list[dict]:
    """Attacker-reachable first: taint hits, then same directory as the patched sites."""
    tkeys = {(t["path"], t["line"]) for t in tainted}
    prefixes = set()
    for site in guarded:
        parts = Path(site.get("path") or "").parts
        prefixes.add("/".join(parts[:4]))
    scored = []
    for site in unguarded:
        reach = 2 if (site.get("path"), site.get("line")) in tkeys else 0
        path = site.get("path") or ""
        if any(path.startswith(p) for p in prefixes if p):
            reach += 1
        scored.append(( -reach, site))
    scored.sort(key=lambda kv: kv[0])
    return [site for _s, site in scored]


def enumerate_carriers(root: Path | None, spec: dict) -> dict:
    if not root or not spec:
        return {"guarded": [], "unguarded": [], "n_unguarded": 0, "tainted": []}
    lang = spec.get("language") or "python"
    guarded = _semgrep(root, spec.get("guarded_pattern") or "", lang)
    everyone = _semgrep(root, spec.get("unguarded_pattern") or "", lang)
    if not everyone:
        everyone = _grep_callee(root, spec.get("callee") or "")
    gkeys = {(g["path"], g["line"]) for g in guarded}
    unguarded = [s for s in everyone if (s["path"], s["line"]) not in gkeys]
    tainted = []
    if spec.get("source_pattern") and spec.get("unguarded_pattern"):
        tainted = taint(root, spec["source_pattern"], spec["unguarded_pattern"], lang)
    ranked = rank_by_reach(unguarded, tainted, guarded)
    return {
        "callee": spec.get("callee"),
        "guarded": guarded,
        "unguarded": ranked[:80],
        "tainted": tainted[:40],
        "n_guarded": len(guarded),
        "n_unguarded": len(unguarded),
        "n_tainted": len(tainted),
    }


def discover_siblings(root: Path | None, seed: dict | None, exec_mod=None) -> list[dict]:
    """Sibling carriers in the product tree or the seed's own fields.

    `exec_mod` is ignored here. Product-tree / seed-field siblings only;
    the live probe's API is handled separately in `agent.probe_space`.
    """
    if not seed:
        return []
    out: list[dict] = []
    seen: set[str] = set()
    path = seed.get("path") if isinstance(seed.get("path"), str) else None
    if path and path.startswith(("/api/", "/app/", "/admin/")) and path.count("/") >= 2 and root:
        prefix = path.rsplit("/", 1)[0]
        for route in _http_routes(root):
            if route.startswith(prefix + "/") and route != path and route not in seen:
                seen.add(route)
                out.append({"path": route, "code": f'"{route}"', "line": 0, "kind": "route"})
    op = seed.get("op")
    if isinstance(op, str) and op and root:
        for name in _quoted_cmds(root, op):
            if name != op and name not in seen:
                seen.add(name)
                out.append({"path": name, "code": f'op={name}', "line": 0, "kind": "op"})
    path = seed.get("path")
    host = seed.get("host")
    if isinstance(path, str) and isinstance(host, str) and "\r\n" in path:
        out.append({"path": "host", "code": "host", "line": 0, "kind": "field"})
    if seed.get("component") == "path" and isinstance(seed.get("url"), str) and "\r\n" in seed["url"]:
        out.append({"path": "host", "code": "component=host", "line": 0, "kind": "component"})
    # NAVEX / SemFuzz: same request, move a seed token the guard already
    # mentions (or a CRLF / .. already on the seed) onto another payload field.
    from patchclosure.assemble import PAYLOAD_KEYS

    fields = [(k, seed[k]) for k in PAYLOAD_KEYS if isinstance(seed.get(k), str) and seed[k]]
    markers = _field_markers(seed, fields)
    for src_k, src_v in fields:
        for token in markers:
            if token not in src_v:
                continue
            for dst_k, _dst_v in fields:
                if dst_k == src_k:
                    continue
                key = f"move:{src_k}->{dst_k}:{token[:12]}"
                if key in seen:
                    continue
                seen.add(key)
                out.append({
                    "path": dst_k,
                    "code": f"{src_k}->{dst_k}",
                    "line": 0,
                    "kind": "field-move",
                    "src": src_k,
                    "dst": dst_k,
                    "token": token,
                })
    return out[:24]


def _field_markers(seed: dict, fields: list[tuple[str, str]]) -> list[str]:
    """Tokens already on the seed, or quoted literals that also occur there."""
    marks: list[str] = []
    for _k, val in fields:
        if "\r\n" in val:
            tail = val.split("\r\n", 1)[1]
            marks.append("\r\n" + tail.split(" HTTP/")[0] if tail else "\r\n")
            marks.append("\r\n")
        elif "\n" in val:
            marks.append("\n" + val.split("\n", 1)[1][:40])
        if "../" in val:
            marks.append("../")
        if "..\\" in val:
            marks.append("..\\")
    return list(dict.fromkeys(m for m in marks if m))


def _http_routes(root: Path) -> list[str]:
    import re

    found: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in {".js", ".ts", ".py", ".php", ".rb", ".java", ".go"}:
            continue
        low = path.as_posix().lower()
        if "node_modules" in low or "/test" in low:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for hit in re.findall(r"""['\"](/(?:api|app|v1|admin|parse|validate|convos)[^'\"]{1,80})['\"]""", text):
            if hit not in found:
                found.append(hit)
        if len(found) >= 80:
            break
    return found


def _quoted_cmds(root: Path, known: str) -> list[str]:
    import re

    names: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in {".js", ".php", ".py"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if known not in text:
            continue
        for hit in re.findall(
            r"""(?:case\s+|cmd\s*[=:]\s*|['\"]cmd['\"]\s*=>\s*)['\"]([a-z][a-z0-9_]{2,20})['\"]""",
            text,
        ):
            if hit != known and hit not in names:
                names.append(hit)
    return names[:16]


def issue_identity(seed: dict, carrier: dict) -> dict | None:
    """Replay the seed's credentials at sibling Y. Unbuildable → None (static only)."""
    if not seed or not carrier:
        return None
    path = str(carrier.get("path") or "")
    code = str(carrier.get("code") or "")
    kind = str(carrier.get("kind") or "")
    cand = deepcopy(seed)
    if kind == "field" and path == "host" and isinstance(cand.get("path"), str) and "\r\n" in cand["path"]:
        tail = cand["path"].split("\r\n", 1)[1]
        if " HTTP/" in tail:
            tail = tail.split(" HTTP/")[0]
        base_host = str(cand.get("host") or "")
        clean = cand["path"].split("\r\n", 1)[0]
        # Same seed tail on the sibling field; a leading space is HTTP obs-fold.
        cand["host"] = base_host + "\r\n " + tail
        cand["path"] = clean
        cand["_assemble"] = "issue-identity:host"
        cand["_carrier"] = {"path": "host", "line": carrier.get("line")}
        return cand
    if kind == "field-move":
        src, dst, token = carrier.get("src"), carrier.get("dst"), carrier.get("token")
        if not (src and dst and token and isinstance(cand.get(src), str) and token in cand[src]):
            return None
        moved = deepcopy(cand)
        moved[src] = moved[src].replace(token, "", 1)
        base = moved[dst] if isinstance(moved.get(dst), str) else ""
        if token.startswith("\r\n") and dst == "host" and base and not base.endswith("\r\n"):
            moved[dst] = base + "\r\n " + token[2:]
        else:
            moved[dst] = base + token
        moved["_assemble"] = f"issue-identity:{src}->{dst}"
        moved["_carrier"] = {"path": dst, "line": carrier.get("line")}
        return moved
    if kind == "component" and isinstance(cand.get("url"), str) and "\r\n" in cand["url"]:
        url = cand["url"]
        head, inj = url.split("\r\n", 1)
        m = re.match(r"(https?://)([^/:]+)(?::(\d+))?", head)
        if m:
            port = m.group(3) or "80"
            # Same injected header(s) on the host; tab-port is HTTP authority fold.
            cand["url"] = m.group(1) + m.group(2) + "\r\n" + inj + f"\t:{port}/"
            cand["component"] = "host"
            cand["_assemble"] = "issue-identity:component-host"
            cand["_carrier"] = {"path": "host", "line": carrier.get("line")}
            return cand
    if kind == "endpoint" and "endpoint" in cand and path:
        cand["endpoint"] = path
        cand["_assemble"] = f"issue-identity:endpoint:{path}"
        cand["_carrier"] = {"path": path, "line": carrier.get("line")}
        return cand
    if kind == "op" and "op" in cand and path:
        cand["op"] = path.lstrip("/")
        cand["_assemble"] = f"issue-identity:{cand['op']}"
        cand["_carrier"] = {"path": path, "line": carrier.get("line")}
        return cand
    m = re_search_route(path, code)
    if not m:
        return None
    if "path" in cand:
        cand["path"] = m
    elif "url" in cand:
        cand["url"] = m
    else:
        cand["path"] = m
    cand["_assemble"] = f"issue-identity:{m}"
    cand["_carrier"] = {"path": path, "line": carrier.get("line")}
    return cand


def re_search_route(path: str, code: str) -> str | None:
    import re

    if any(tok in path for tok in (".js", ".py", ".java", ".go", "/Users/", "/home/", "work/PCBV2", "node_modules")):
        return None
    for blob in (code, path):
        hit = re.search(r"(/[A-Za-z0-9_./-]{3,80})", blob)
        if not hit:
            continue
        route = hit.group(1)
        if route.endswith((".js", ".py", ".java", ".go")):
            continue
        if any(tok in route for tok in ("/Users/", "/home/", "work/PCBV2")):
            continue
        return route
    if path.endswith(".php"):
        return "/" + Path(path).name
    return None
