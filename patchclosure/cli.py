from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

from patchclosure import config, pipeline, platform, stage
from patchclosure.preimage import exec_bounded_preimage
from patchclosure.workspace import load_workspace


def _write_json(path: Path | None, obj: dict) -> None:
    text = json.dumps(obj, indent=2, default=str, ensure_ascii=True)
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
    print(text)


def _attach_compose(case: str, run_id: str) -> None:
    """Let staged seed_exec.py `docker compose exec` hit the controller project."""
    os.environ["COMPOSE_PROJECT_NAME"] = platform.compose_project(run_id)
    roots = [
        Path(os.environ["PCB_BENCHMARK_ROOT"]) if os.environ.get("PCB_BENCHMARK_ROOT") else None,
        config.BENCHMARK_ROOT,
        config.ROOT.parent / "benchmark_platform",
    ]
    compose = None
    for root in roots:
        if root is None:
            continue
        cand = root / "cases" / case / "docker-compose.yml"
        if cand.is_file():
            compose = cand
            break
    ws_exp = config.WORK / case / "exp"
    if compose is not None and ws_exp.is_dir():
        dest = ws_exp / "docker-compose.yml"
        if not dest.exists():
            try:
                dest.symlink_to(compose)
            except OSError:
                shutil.copy2(compose, dest)


def cmd_stage(args) -> int:
    if args.cases:
        ids = [c.strip() for c in args.cases.split(",") if c.strip()]
    else:
        ids = stage.read_case_list(Path(args.cases_file) if args.cases_file else None)
    reports = stage.stage_many(
        ids,
        benchmark=Path(args.benchmark) if args.benchmark else None,
        dest_root=Path(args.dest) if args.dest else None,
        fetch=args.fetch,
    )
    _write_json(None, {"staged": reports, "fetch": args.fetch})
    failed = [r for r in reports if r.get("errors")]
    return 1 if failed and args.fetch else 0


def cmd_analyze(args) -> int:
    report = pipeline.analyze(args.workspace)
    out = Path(args.out) if args.out else None
    _write_json(out, report)
    return 0


def cmd_fire(args) -> int:
    ws = load_workspace(args.workspace)
    if args.report:
        report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    else:
        report = pipeline.analyze(ws)
    report = pipeline.fire(ws, report, v1_base=args.v1_base, v1_port=args.v1_port)
    out = Path(args.out) if args.out else None
    _write_json(out, report)
    return 0 if (report.get("validate") or {}).get("residual") else 2


def cmd_live(args) -> int:
    """Paper VALIDATE against a controller V1 run (current /api/v1/runs API)."""
    case = args.case
    ws = load_workspace(Path(args.workspace) if args.workspace else config.WORK / case)
    created = platform.create_run(case, version="v1")
    run_id = created["run_id"]
    report: dict = {"case": case, "run_id": run_id, "warnings": []}
    try:
        run = platform.wait_run(run_id, timeout=args.wait)
        base = platform.run_v1_base(run)
        plant = run.get("flag") or ""
        if plant:
            os.environ["RUN_FLAG"] = plant
            os.environ["PCB_FLAG"] = plant
        if run.get("source_dir") and not ws.v1:
            from pathlib import Path as P
            src = P(run["source_dir"])
            if src.is_dir():
                ws.v1 = src
        report["v1_base"] = base
        report["run_state"] = run.get("state")
        if not base:
            # Some cases (compose-exec clients) publish no host port.
            base = "http://127.0.0.1:0"
        _attach_compose(case, run_id)
        analyzed = pipeline.analyze(ws)
        report.update(analyzed)
        port_map = platform.docker_published_map(run_id)
        report = pipeline.fire(ws, report, v1_base=base, port_map=port_map)
        residual = (report.get("validate") or {}).get("residual") or {}
        if residual.get("flag") and run_id:
            try:
                report["flag_submit"] = platform._req(
                    "POST",
                    f"/api/v1/runs/{run_id}/submissions",
                    {"type": "flag", "value": residual["flag"]},
                )
            except platform.PlatformError as exc:
                report["flag_submit"] = {"error": str(exc)}
    finally:
        try:
            platform.stop_run(run_id)
            report["stopped"] = True
        except Exception as exc:  # noqa: BLE001
            report["stop_error"] = str(exc)[:200]
    out = Path(args.out) if args.out else config.OUT / f"{case}.json"
    _write_json(out, report)
    return 0 if (report.get("validate") or {}).get("residual") else 2


def cmd_session(args) -> int:
    created = platform.create_session(args.case)
    sid = created["session_id"]
    print(json.dumps({"session_id": sid, "state": created.get("state")}, indent=2))
    sess = platform.wait_ready(sid, timeout=args.wait)
    workspace = sess.get("workspace")
    if not workspace:
        print("session ready but no workspace path", file=sys.stderr)
        return 1
    # Confirm the seed is blocked on v1 before searching.
    v1_run = (sess.get("v1") or {}).get("run_id")
    seed_check = None
    if v1_run:
        try:
            seed_check = platform.submit_verify(v1_run, "seed")
        except platform.PlatformError as exc:
            seed_check = {"error": str(exc)}
    report = pipeline.analyze(workspace)
    report["session_id"] = sid
    report["seed_verify"] = seed_check
    report = pipeline.fire(workspace, report, v1_base=platform.v1_base(sess))
    residual = (report.get("validate") or {}).get("residual") or {}
    flag = residual.get("flag")
    if flag:
        try:
            report["flag_submit"] = platform.submit_flag(sid, flag)
        except platform.PlatformError as exc:
            report["flag_submit"] = {"error": str(exc)}
    if args.stop:
        try:
            platform.stop_session(sid)
            report["stopped"] = True
        except platform.PlatformError as exc:
            report["stop_error"] = str(exc)
    out = Path(args.out) if args.out else config.OUT / f"{args.case}.json"
    _write_json(out, report)
    return 0 if residual else 2


def cmd_selftest(_args) -> int:
    def admits(x: str) -> bool:
        return "\r\n" not in x

    def phi(x: str) -> str:
        return x

    def danger(y: str) -> bool:
        return "\r" in y or "\n" in y

    result = exec_bounded_preimage(admits, phi, danger, alphabet=["a", "\r", "\n"], kmax=2)
    ok = result.get("shortest") in {"\r", "\n"}
    print(json.dumps({"webrick_like": result, "ok": ok}, indent=2, default=str))
    from patchclosure.ip_enum import gen_ip_candidates

    ip = gen_ip_candidates([], targets=("127.0.0.1",), cap=20)
    has_hex = any(f["x"] == "0X7F000001" or f["x"].startswith("0X7F") for f in ip["fragments"])
    print(json.dumps({"ip_enum_ok": has_hex, "n": ip["n_candidates"]}, indent=2))
    from patchclosure.assemble import assemble_variants

    variants = assemble_variants(
        {"path": "/%2e/WEB-INF/pcb-secret.txt"},
        "/%u002e/WEB-INF/pcb-secret.txt",
    )
    replaced = any("%u002e" in str(v.get("path")) for v in variants)
    print(json.dumps({"assemble_ok": replaced, "n": len(variants)}, indent=2))
    return 0 if ok and has_hex and replaced else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="patchclosure",
        description="Residual exploit discovery for incomplete web-security patches.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("stage", help="Copy diff + seed into work/; optionally fetch v0/v1.")
    p.add_argument("--cases", help="Comma-separated case ids (default: configs/eval_cases.txt)")
    p.add_argument("--cases-file")
    p.add_argument("--benchmark")
    p.add_argument("--dest")
    p.add_argument("--fetch", action="store_true")
    p.set_defaults(func=cmd_stage)

    p = sub.add_parser("analyze", help="BUILD → MATCH → DISPATCH on a staged workspace.")
    p.add_argument("workspace")
    p.add_argument("--out")
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("fire", help="VALIDATE ranked candidates on a live V1.")
    p.add_argument("workspace")
    p.add_argument("--report", help="JSON from analyze; default is to analyze first")
    p.add_argument("--v1-base", required=True)
    p.add_argument("--v1-port", type=int)
    p.add_argument("--out")
    p.set_defaults(func=cmd_fire)

    p = sub.add_parser("live", help="ANALYZE + VALIDATE on a live controller V1 run.")
    p.add_argument("--case", required=True)
    p.add_argument("--workspace", help="Staged work dir; default work/<case>")
    p.add_argument("--wait", type=int, default=1800)
    p.add_argument("--out")
    p.set_defaults(func=cmd_live)

    p = sub.add_parser("session", help="Run the full pipeline against a controller session.")
    p.add_argument("--case", required=True)
    p.add_argument("--wait", type=int, default=1800)
    p.add_argument("--out")
    p.add_argument("--stop", action="store_true", help="Stop the session after VALIDATE.")
    p.set_defaults(func=cmd_session)

    p = sub.add_parser("selftest", help="Interpreter / preimage checks (no LLM, no Docker).")
    p.set_defaults(func=cmd_selftest)

    args = parser.parse_args(argv)
    return args.func(args)
