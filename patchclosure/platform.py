from __future__ import annotations

import json
import re
import subprocess
import time
import urllib.error
import urllib.request

from patchclosure import config


class PlatformError(RuntimeError):
    pass


def _req(method: str, path: str, body: dict | None = None, timeout: int = 300) -> dict:
    url = config.PLATFORM_URL.rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:400]
        raise PlatformError(f"{method} {path} -> {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise PlatformError(f"{method} {path} failed: {exc}") from exc


def create_session(case_id: str) -> dict:
    return _req("POST", "/api/v1/sessions", {"case_id": case_id}, timeout=60)


def create_run(case_id: str, *, version: str = "v1", trial_id: str = "t1") -> dict:
    return _req(
        "POST",
        "/api/v1/runs",
        {
            "case_id": case_id,
            "target_version": version,
            "exposure_profile": "agent_v1_patch",
            "trial_id": trial_id,
        },
        timeout=60,
    )


def get_run(run_id: str) -> dict:
    return _req("GET", f"/api/v1/runs/{run_id}")


def wait_run(run_id: str, *, timeout: int = 1800, poll: int = 5) -> dict:
    deadline = time.time() + timeout
    last = {}
    while time.time() < deadline:
        last = get_run(run_id)
        state = last.get("state")
        if state in {"ready", "scoring"}:
            return last
        if state in {"error", "stopped", "expired"}:
            raise PlatformError(f"run failed: {json.dumps(last)[:400]}")
        time.sleep(poll)
    raise PlatformError(f"run {run_id} not ready after {timeout}s")


def stop_run(run_id: str) -> dict:
    return _req("POST", f"/api/v1/runs/{run_id}/stop", {}, timeout=180)


def run_v1_base(run: dict) -> str | None:
    for ep in run.get("endpoints") or []:
        if isinstance(ep, dict) and ep.get("url"):
            return str(ep["url"])
        if isinstance(ep, dict) and ep.get("port"):
            host = ep.get("host") or "127.0.0.1"
            return f"http://{host}:{ep['port']}"
    run_id = run.get("run_id") or ""
    version = run.get("target_version") or "v1"
    if run_id:
        return docker_published_url(run_id, version)
    return None


def compose_project(run_id: str) -> str:
    return f"pcb_{run_id[:12]}"


def docker_published_map(run_id: str) -> dict[int, int]:
    """container_port -> host_port for the compose project."""
    proj = compose_project(run_id)
    proc = subprocess.run(
        ["docker", "ps", "--filter", f"label=com.docker.compose.project={proj}",
         "--format", "{{.Ports}}"],
        capture_output=True, text=True, timeout=20,
    )
    found: dict[int, int] = {}
    if proc.returncode == 0:
        for line in proc.stdout.splitlines():
            for host, cport in re.findall(r"(?:127\.0\.0\.1|0\.0\.0\.0):(\d+)->(\d+)", line):
                found[int(cport)] = int(host)
    return found


def docker_published_url(run_id: str, version: str = "v1") -> str | None:
    proj = compose_project(run_id)
    proc = subprocess.run(
        ["docker", "ps", "--filter", f"label=com.docker.compose.project={proj}",
         "--format", "{{.Ports}}"],
        capture_output=True, text=True, timeout=20,
    )
    if proc.returncode == 0:
        for line in proc.stdout.splitlines():
            match = re.search(r"127\.0\.0\.1:(\d+)->", line) or re.search(r"0\.0\.0\.0:(\d+)->", line)
            if match:
                return f"http://127.0.0.1:{match.group(1)}"
    for port in (8080, 80, 3000, 8000, 8888, 5000, 4173, 5173):
        proc = subprocess.run(
            ["docker", "compose", "-p", proj, "port", version, str(port)],
            capture_output=True, text=True, timeout=20,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            hostport = proc.stdout.strip().split()[-1]
            if ":" in hostport:
                host, hp = hostport.rsplit(":", 1)
                host = "127.0.0.1" if host in {"0.0.0.0", "::"} else host
                return f"http://{host}:{hp}"
    return None


def get_session(session_id: str) -> dict:
    return _req("GET", f"/api/v1/sessions/{session_id}")


def wait_ready(session_id: str, *, timeout: int = 1800, poll: int = 5) -> dict:
    deadline = time.time() + timeout
    last = {}
    while time.time() < deadline:
        last = get_session(session_id)
        state = last.get("state")
        v0 = (last.get("v0") or {}).get("state")
        v1 = (last.get("v1") or {}).get("state")
        if state == "ready" or (v0 == "ready" and v1 == "ready"):
            return last
        if state in {"error", "expired", "stopped"} or v0 == "error" or v1 == "error":
            raise PlatformError(f"session failed: {json.dumps(last)[:400]}")
        time.sleep(poll)
    raise PlatformError(f"session {session_id} not ready after {timeout}s")


def submit_flag(session_id: str, flag: str) -> dict:
    return _req("POST", f"/api/v1/sessions/{session_id}/flag", {"value": flag})


def submit_verify(run_id: str, mode: str = "seed") -> dict:
    return _req(
        "POST",
        f"/api/v1/runs/{run_id}/submissions",
        {"type": "verify", "mode": mode},
    )


def stop_session(session_id: str) -> dict:
    return _req("POST", f"/api/v1/sessions/{session_id}/stop", {})


def v1_base(session: dict) -> str | None:
    v1 = session.get("v1") or {}
    for key in ("base_url", "url", "endpoint"):
        if v1.get(key):
            return str(v1[key])
    endpoints = v1.get("endpoints") or []
    if isinstance(endpoints, list) and endpoints:
        first = endpoints[0]
        if isinstance(first, dict):
            if first.get("url"):
                return str(first["url"])
            if first.get("port"):
                host = first.get("host") or "127.0.0.1"
                return f"http://{host}:{first['port']}"
        if isinstance(first, (int, str)):
            return f"http://127.0.0.1:{first}"
    return None
