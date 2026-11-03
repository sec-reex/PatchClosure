#!/usr/bin/env python3
"""Deterministic plant-facts extractor: where does the per-run planted value
live, and where can it surface?

The deployment materials in the case directory (entrypoint, setup scripts,
seed files, compose) are GIVEN materials. This traces the planted marker
from its env injection to a concrete target — a file, database table, or
baked env — and then locates the V1 source sites that read it. Everything
is file:line facts, neutral language, no interpretation, zero LLM.

Output: work/plant_facts.md (fail-soft).
"""
from __future__ import annotations

import os
import re
import sys

FLAG_VAR = re.compile(r"\b(PCB_FLAG|RUN_FLAG|MARKER)\b")

FILE_WRITE = re.compile(
    r"(?:>\s*|tee\s+(?:-a\s+)?|install\s+[^&;|]*?\s+|cp\s+\S+\s+|mv\s+\S+\s+)"
    r"(/?[\w./-]{2,120})")
SQL_INSERT = re.compile(r"(?i)INSERT\s+(?:IGNORE\s+)?INTO\s+([\w.]+)")
SQL_TABLE_REF = re.compile(r"(?i)(?:FROM|INTO|UPDATE|JOIN)\s+([\w.]+)")
SEED_HELPER = re.compile(r"(?i)[\w./-]*(?:seed|plant|canary)[\w./-]*\.(php|sql|py|sh|js)")
SQLITE_OPEN = re.compile(r"(?i)([\w./-]+\.(?:db|sqlite3?))")
ENV_SERVE_RX = {
    "php": re.compile(r"getenv\s*\(\s*['\"]PCB_FLAG['\"]|\$_ENV\[.{0,20}PCB_FLAG|\$PCB_FLAG"),
    "python": re.compile(r"environ(?:\.get)?\s*\(\s*['\"](?:PCB_FLAG|RUN_FLAG|MARKER)['\"]"),
    "javascript": re.compile(r"process\.env\.(?:PCB_FLAG|RUN_FLAG|MARKER)"),
    "go": re.compile(r"Getenv\s*\(\s*\"(?:PCB_FLAG|RUN_FLAG|MARKER)\""),
    "java": re.compile(r"getenv\s*\(\s*\"(?:PCB_FLAG|RUN_FLAG|MARKER)\""),
    "ruby": re.compile(r"ENV\[[\"'](?:PCB_FLAG|RUN_FLAG|MARKER)"),
}
HINT_COMMENT = re.compile(r"(?i)(planted|bake|canary|channel|吐出|注入|seed|monitor).{0,120}")


def _read(path):
    try:
        return open(path, errors="replace").read()
    except OSError:
        return None


def _case_script_files(case_dir):
    out = []
    for fn in ("entrypoint.sh", "docker-compose.yml", "Dockerfile",
               "seed.php", "seed.sql", "pcb_seed.php", ".source.env"):
        p = os.path.join(case_dir, fn)
        if os.path.isfile(p):
            out.append((os.path.relpath(p, case_dir), _read(p) or ""))
    sc = os.path.join(case_dir, "scripts")
    if os.path.isdir(sc):
        for fn in sorted(os.listdir(sc)):
            p = os.path.join(sc, fn)
            if os.path.isfile(p):
                out.append((f"scripts/{fn}", _read(p) or ""))
    # any seed-helper at top level
    for fn in sorted(os.listdir(case_dir)):
        if SEED_HELPER.fullmatch(fn) or SEED_HELPER.match(fn):
            p = os.path.join(case_dir, fn)
            if os.path.isfile(p) and all(p != os.path.join(case_dir, f) for f in
                                         ("entrypoint.sh", "docker-compose.yml", "Dockerfile")):
                out.append((fn, _read(p) or ""))
    return out


def _trace_target(case_dir, files):
    """Find the concrete plant target(s) from setup materials."""
    targets = []
    for rel, text in files:
        for i, line in enumerate(text.splitlines(), 1):
            if not FLAG_VAR.search(line):
                continue
            # file-plant: write/serve from a file path on the same line or next
            m = FILE_WRITE.search(line)
            if m and not line.strip().startswith("#"):
                targets.append(("file", m.group(1), rel, i, line.strip()[:160]))
            for sm in SQL_INSERT.finditer(line):
                targets.append(("table", sm.group(1), rel, i, line.strip()[:160]))
            # helper script referenced with flag nearby (same line)
            hm = re.search(r"[\w./-]*(?:seed|plant|canary)[\w./-]*\.(?:php|sql|py|js)", line)
            if hm and not line.strip().startswith("#"):
                targets.append(("helper", hm.group(0), rel, i, line.strip()[:160]))
        # comment hints that describe the channel explicitly (given materials)
        for i, line in enumerate(text.splitlines(), 1):
            if FLAG_VAR.search(line) and HINT_COMMENT.search(line):
                targets.append(("hint", line.strip()[:200], rel, i, ""))
    return targets


def _compose_services(case_dir):
    """Minimal line-wise parse of docker-compose.yml: for each service, the
    comments above it, env vars carrying the marker, volumes, published
    ports. Only services that receive the marker or carry canary/probe/hit
    signals are returned. `<<: *anchor` merges are resolved so services
    defined through x- anchors (vulhub recipe style) report their inherited
    flag env / volumes."""
    text = _read(os.path.join(case_dir, "docker-compose.yml"))
    if not text:
        return []
    anchors = {}   # anchor name -> body lines (for <<: merges)
    cur_anchor = None
    for line in text.splitlines():
        m = re.match(r"^x-[\w-]+:\s*&([\w-]+)\s*(#.*)?$", line)
        if m:
            cur_anchor = m.group(1)
            anchors[cur_anchor] = []
            continue
        if cur_anchor:
            if re.match(r"^\S", line):   # next top-level key ends the anchor
                cur_anchor = None
            else:
                anchors[cur_anchor].append(line)
    services, cur, pending = [], None, []
    stopped = False
    for i, line in enumerate(text.splitlines(), 1):
        if re.match(r"^(volumes|networks|secrets|configs|include|name):\s*(#.*)?$", line):
            stopped = True   # service definitions ended
            cur = None
            pending = []
            continue
        m = re.match(r"^  ([\w-]+):\s*$", line)
        if m and not line.startswith("    ") and not stopped:
            cur = {"service": m.group(1), "line": i, "comments": list(pending),
                   "flag_env": [], "volumes": [], "ports": [], "real": False,
                   "anchor": None}
            services.append(cur)
            pending = []
            continue
        if line.strip().startswith("#"):
            pending.append(line.strip())
            continue
        if not re.match(r"^\s", line):
            cur = None
            pending = []
            continue
        if cur is None:
            continue
        # a real service body defines image/build/profiles — anchor bodies
        # (x-*) reindented at service level carry keys like `entrypoint:`
        # that are NOT services; requiring this keeps the parse honest
        if re.match(r"^\s+(image|build|profiles|deploy):", line):
            cur["real"] = True
        ma = re.match(r"^\s*<<:\s*\*(\w+)", line)
        if ma:
            cur["anchor"] = ma.group(1)
        if FLAG_VAR.search(line):
            cur["flag_env"].append(line.strip()[:120])
        vm = re.search(r"-\s*([\w.-]+:/[\w./-]+)", line)
        if vm:
            cur["volumes"].append(vm.group(1))
        # a published port spec ends in colon+digits before a quote/bracket/EOL
        # (volume mounts end in a /path, so they never match)
        if re.search(r":\d{2,5}[\"'],?\]?\s*$", line):
            cur["ports"].append(line.strip()[:80])
    for s in services:
        for ln in anchors.get(s.get("anchor") or "", []):
            if FLAG_VAR.search(ln) and not s["flag_env"]:
                s["flag_env"].append(ln.strip()[:120])
            vm = re.search(r"-\s*([\w.-]+:/[\w./-]+)", ln)
            if vm:
                s["volumes"].append(vm.group(1))
            if re.search(r":\d{2,5}[\"'],?\]?\s*$", ln):
                s["ports"].append(ln.strip()[:80])
    out = []
    for s in services:
        if not s["real"]:
            continue
        sig = s["service"] + " " + " ".join(s["comments"])
        if s["flag_env"] or re.search(r"(?i)canary|probe|catch|sidecar|hit", sig):
            out.append(s)
    return out


def _trace_compose(case_dir):
    facts = []
    for s in _compose_services(case_dir):
        sig = s["service"] + " " + " ".join(s["comments"])
        tgt = ""
        for v in s["volumes"]:
            m = re.search(r"(/[\w./-]*(?:hits|log|canary|flag)[\w./-]*)", v, re.I)
            if m:
                tgt = m.group(1)
        canaryish = bool(re.search(r"(?i)canary|probe|catch|sidecar|hit", sig))
        # a published app port + flag env = the app variant itself (v0/v1/v2),
        # not a sidecar; a sidecar records the marker into a mounted hit log
        # (or is declared canary-ish without any published port)
        if canaryish and (tgt or not s["ports"]):
            role = "canary-sidecar" if re.search(r"(?i)canary", sig) else "sidecar"
            desc = "; ".join(s["comments"])[:200] or (s["flag_env"][0] if s["flag_env"] else "")
            facts.append(("sidecar", s["service"], s["line"], role, tgt, desc))
        elif s["flag_env"]:
            desc = "; ".join(s["comments"])[:120] or (s["flag_env"][0] if s["flag_env"] else "")
            facts.append(("app-flag-env", s["service"], s["line"],
                          "app" if s["ports"] else "service", "", desc))
    return facts


def _trace_helper(case_dir, targets):
    """Context-aware scan of seed/plant helpers. Helpers are plant machinery
    by construction; the flag rides a local ($flag), so track enclosing
    constructs (DB::table / new Model / file writes) to name the storage
    target and column/key."""
    facts = []
    helper_names = {t[1] for t in targets if t[0] == "helper"}
    helper_names |= {fn for fn, _ in _case_script_files(case_dir)
                     if re.match(r"(?i)(?:\w+_)?seed\.(?:php|sql|py|js)$", fn)
                     or "seed" in os.path.basename(fn).lower()
                     or "plant" in os.path.basename(fn).lower()}
    for h in sorted(helper_names):
        text = _read(os.path.join(case_dir, h))
        if text is None:
            text = _read(os.path.join(case_dir, "scripts", h))
        if text is None:
            continue
        lines = text.splitlines()
        ctx = ""  # last DB::table / new Model / function-write context
        for i, line in enumerate(lines, 1):
            m = re.search(r"DB::table\(\s*['\"]([\w.]+)['\"]", line)
            if m:
                ctx = f"table:{m.group(1)}"
            m = re.search(r"(?:new\s+|::create\(|::firstOrNew\(|::updateOrCreate\()([A-Z]\w+)", line)
            if m:
                ctx = f"model:{m.group(1)}"
            m = re.search(r"(?:file_put_contents|WriteFile|writeFile|os\.WriteFile|fs\.write(?:File)?Sync?)\s*\(\s*['\"]?([\w./-]+)", line)
            if m:
                ctx = f"file:{m.group(1)}"
            if FLAG_VAR.search(line) or re.search(r"\$\w*flag\w*", line, re.I):
                cm = re.search(r"['\"](\w+)['\"]\s*=>", line)
                col = cm.group(1) if cm else ""
                if ctx.startswith("table:"):
                    facts.append(("table", ctx[6:], col, h, i, line.strip()[:160]))
                elif ctx.startswith("model:"):
                    facts.append(("model", ctx[6:], col, h, i, line.strip()[:160]))
                elif ctx.startswith("file:"):
                    facts.append(("file", ctx[5:], col, h, i, line.strip()[:160]))
            m = re.search(r"(?i)INSERT\s+(?:IGNORE\s+)?INTO\s+([\w.]+)", line)
            if m:
                facts.append(("table", m.group(1), "", h, i, line.strip()[:160]))
    seen, out = set(), []
    for f in facts:
        k = (f[0], f[1], f[2])
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out[:12]


_PROD_EXT = {".php", ".php3", ".inc", ".js", ".mjs", ".ts", ".py", ".go",
             ".java", ".rb", ".erb", ".blade.php", ".vue", ".jsx", ".tsx"}


def _source_readers(v1_dir, needle, regex=False):
    """Find V1 production-code sites referencing the plant target. Doc/config
    files are skipped; needle may be a regex when regex=True."""
    hits = []
    rx = re.compile(needle) if regex else None
    for dirpath, dirnames, filenames in os.walk(v1_dir):
        dirnames[:] = [d for d in dirnames if d not in (
            "node_modules", "vendor", ".git", "__pycache__", "test", "tests",
            "spec", "fixtures", "testdata", "storage", "public", "docs")]
        for fn in filenames:
            if os.path.splitext(fn)[1] not in _PROD_EXT:
                continue
            p = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(p) > 1_500_000:
                    continue
                text = _read(p)
            except OSError:
                continue
            if not text:
                continue
            matched = rx.search(text) if rx else (needle in text)
            if not matched:
                continue
            rel = os.path.relpath(p, v1_dir)
            for i, line in enumerate(text.splitlines(), 1):
                if (rx.search(line) if rx else needle in line):
                    hits.append((rel, i, line.strip()[:160]))
                    if len(hits) >= 10:
                        return hits
    return hits


def build_plant_facts(case_dir: str, pkg_dir: str) -> str | None:
    files = _case_script_files(case_dir)
    if not files:
        return None
    targets = _trace_target(case_dir, files)
    if not targets:
        return None
    v1_dir = os.path.join(pkg_dir, "v1_source")
    if os.path.islink(v1_dir):
        v1_dir = os.path.realpath(v1_dir)

    L = ["# Where the per-run planted value lives", ""]
    L.append("Traced from the deployment's own setup materials (given inputs,")
    L.append("file:line). The value is injected per run through the marker env;")
    L.append("these facts say WHERE it is stored and WHICH code reads it. Use")
    L.append("them to aim the check at pages/sites that actually carry it.")
    L.append("")

    L.append("## Trace in setup materials")
    L.append("")
    for kind, val, rel, ln, line in targets[:20]:
        if kind == "hint":
            L.append(f"- note `{rel}:{ln}`: {val}")
        else:
            L.append(f"- `{kind}` target `{val}`  ({rel}:{ln})  `{line}`")
    L.append("")

    # helper seed files → storage facts
    facts = _trace_helper(case_dir, targets)
    # compose sidecar services (canary hit loggers etc.)
    sidecars = _trace_compose(case_dir)
    sc = [f for f in sidecars if f[0] == "sidecar"]
    apps = [f for f in sidecars if f[0] == "app-flag-env"]
    if sc:
        L.append("## Sidecar services carrying the marker (from docker-compose)")
        L.append("")
        for _k, svc, ln, role, tgt, desc in sc[:8]:
            tt = f"; hit log `{tgt}`" if tgt else ""
            L.append(f"- service `{svc}` ({role}){tt}  (docker-compose.yml:{ln})")
            if desc:
                L.append(f"  - {desc}")
        L.append("The sidecar is reachable only from inside the compose network")
        L.append("by its service name as an HTTP host (e.g. `http://" +
                 sc[0][1] + "/...`) — check what makes the app fetch")
        L.append("an attacker-chosen URL, and which responses reflect it.")
        L.append("")
    if apps:
        L.append("## Compose services receiving the marker (app variants)")
        L.append("")
        for _k, svc, ln, role, tgt, desc in apps[:8]:
            L.append(f"- service `{svc}` ({role})  (docker-compose.yml:{ln})")
            if desc:
                L.append(f"  - {desc}")
        L.append("")
    if facts:
        L.append("## Seeded storage (from the setup helper)")
        L.append("")
        for kind, tgt, col, h, i, line in facts[:12]:
            loc = f" column/key `{col}`" if col else ""
            L.append(f"- {kind} `{tgt}`{loc}  ({h}:{i})  `{line}`")
        L.append("")

    # source readers
    L.append("## Source sites that reference the target")
    L.append("")
    needles = []
    for kind, val, _rel, _ln, _line in targets:
        if kind in ("file", "table", "helper"):
            base = os.path.basename(val)
            if base and (base, False) not in needles:
                needles.append((base, False))
    for kind, tgt, _col, _h, _i, _line in facts:
        forms = []
        if kind == "model":
            forms.append((f"\\b{tgt}(::|\\b)", True))          # Mailbox:: / new Mailbox
        elif kind == "table":
            forms.append((f"['\\\"]{tgt}['\\\"]", True))        # table('users') / FROM "users"
        elif kind == "file":
            forms.append((re.escape(os.path.basename(tgt)), False))
        for pat, is_rx in forms:
            if (pat, is_rx) not in [(a, b) for a, b in needles]:
                needles.append((pat, is_rx))
    for _k, svc, _ln, _role, _tgt, _desc in sidecars:
        for pat in (f"http://{svc}/", f"['\\\"]{svc}['\\\"]"):
            if (pat, True) not in [(a, b) for a, b in needles]:
                needles.append((pat, True))
    if os.path.isdir(v1_dir):
        for lang, rx in ENV_SERVE_RX.items():
            for dirpath, dirnames, filenames in os.walk(v1_dir):
                dirnames[:] = [d for d in dirnames if d not in (
                    "node_modules", "vendor", ".git", "__pycache__")]
                for fn in filenames:
                    if rx.search(fn):
                        continue
                    p = os.path.join(dirpath, fn)
                    try:
                        text = _read(p)
                    except OSError:
                        continue
                    if text and rx.search(text):
                        rel = os.path.relpath(p, v1_dir)
                        for i, line in enumerate(text.splitlines(), 1):
                            if rx.search(line):
                                L.append(f"- env reader `{rel}:{i}`  `{line.strip()[:150]}`")
                                break
        for nd, is_rx in needles[:8]:
            hits = _source_readers(v1_dir, nd, regex=is_rx)
            if hits:
                L.append("")
                label = nd if not is_rx else f"`{nd}` (pattern)"
                L.append(f"### readers of {label}")
                L.append("")
                for rel, i, line in hits[:8]:
                    L.append(f"- `{rel}:{i}`  `{line}`")
    L.append("")
    return "\n".join(L)


def main(case_dir: str, pkg_dir: str):
    out = build_plant_facts(case_dir, pkg_dir)
    if not out:
        print("pcg plant facts: no trace found")
        return
    work = os.path.join(pkg_dir, "work")
    os.makedirs(work, exist_ok=True)
    with open(os.path.join(work, "plant_facts.md"), "w") as f:
        f.write(out)
    print(f"pcg plant facts: written ({len(out)} bytes)")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
