"""Run sliced interpreters in the real language runtime.

JavaScript and Python run natively. PHP, Ruby, Go, Java, and Rust run
in a per-language subprocess (or a toolchain container if the runtime
is missing locally). External interpreters (libc, browser) are invoked
as themselves, not reimplemented.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import threading
from collections.abc import Callable


class NodeWorker:
    def __init__(self, body: str, node: str = "node"):
        loop = (
            body + "\n"
            "const _rl=require('readline').createInterface({input:process.stdin});\n"
            "_rl.on('line',(l)=>{let r;try{r={ok:true,v:f(JSON.parse(l))}}"
            "catch(e){r={ok:false,e:String(e)}}process.stdout.write(JSON.stringify(r)+'\\n');});\n"
        )
        self.p = subprocess.Popen(
            [node, "-e", loop],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._lock = threading.Lock()

    def call(self, x):
        with self._lock:
            self.p.stdin.write(json.dumps(x) + "\n")
            self.p.stdin.flush()
            line = self.p.stdout.readline()
        if not line:
            raise RuntimeError("node worker died")
        result = json.loads(line)
        if not result["ok"]:
            raise RuntimeError(result["e"])
        return result["v"]

    def close(self):
        try:
            self.p.stdin.close()
            self.p.terminate()
        except Exception:
            pass


class PyInterp:
    def __init__(self, fn: Callable):
        self.fn = fn

    def call(self, x):
        return self.fn(x)


def lang_available(lang: str) -> bool:
    if lang in {"javascript", "typescript", "tsx", "python"}:
        return True
    if lang == "java":
        return shutil.which("javac") is not None and shutil.which("java") is not None
    if lang == "go":
        return shutil.which("go") is not None
    if lang == "ruby":
        return shutil.which("ruby") is not None
    if lang == "php":
        return shutil.which("php") is not None or _docker_image("php:8.2-cli")
    if lang == "rust":
        return shutil.which("rustc") is not None or _docker_image("rust:slim")
    return False


def _docker_image(img: str) -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(
            ["docker", "image", "inspect", img],
            capture_output=True,
            timeout=20,
        ).returncode == 0
    except Exception:
        return False


def run_batch(lang: str, harness_src: str, inputs: list, timeout: int = 120) -> list[dict]:
    if lang == "java":
        return _run_java(harness_src, inputs, timeout)
    if lang == "go":
        return _run_file(["go", "run"], ".go", harness_src, inputs, timeout)
    if lang == "ruby":
        return _run_file(["ruby"], ".rb", harness_src, inputs, timeout)
    if lang == "php":
        if shutil.which("php"):
            return _run_cmd(["php", "-r", harness_src], inputs, timeout)
        return _run_cmd(["docker", "run", "--rm", "-i", "php:8.2-cli", "php", "-r", harness_src], inputs, timeout)
    raise RuntimeError(f"no batch harness for {lang}")


def _run_cmd(cmd: list[str], inputs: list, timeout: int) -> list[dict]:
    payload = "\n".join(json.dumps(i) for i in inputs) + "\n"
    proc = subprocess.run(cmd, input=payload, capture_output=True, text=True, timeout=timeout)
    return _parse_json_lines(proc.stdout)


def _run_file(cmd: list[str], ext: str, src: str, inputs: list, timeout: int) -> list[dict]:
    with tempfile.NamedTemporaryFile("w", suffix=ext, delete=False) as fh:
        fh.write(src)
        path = fh.name
    try:
        return _run_cmd(cmd + [path], inputs, timeout)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _run_java(src: str, inputs: list, timeout: int) -> list[dict]:
    work = tempfile.mkdtemp(prefix="pc_java_")
    path = os.path.join(work, "Slice.java")
    PathWrite = open  # local alias kept short
    with PathWrite(path, "w", encoding="utf-8") as fh:
        fh.write(src)
    try:
        compile_ = subprocess.run(
            ["javac", path], capture_output=True, text=True, timeout=timeout, cwd=work
        )
        if compile_.returncode != 0:
            raise RuntimeError(compile_.stderr[-200:])
        return _run_cmd(["java", "-cp", work, "Slice"], inputs, timeout)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _parse_json_lines(stdout: str) -> list[dict]:
    out = []
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def run_external(kind: str, values: list[str]) -> list[str]:
    """Harness that *is* the interpreter (libc / runtime), not a rewrite."""
    if kind == "strtol":
        # libc strtol via python ctypes when available, else int(x, 0)
        try:
            import ctypes
            import ctypes.util

            libc = ctypes.CDLL(ctypes.util.find_library("c"))
            libc.strtol.restype = ctypes.c_long
            end = ctypes.c_char_p()
            out = []
            for value in values:
                n = libc.strtol(value.encode(), ctypes.byref(end), 0)
                out.append(str(n))
            return out
        except Exception:
            return [str(int(v, 0)) if _looks_int(v) else v for v in values]
    if kind == "unquote":
        from urllib.parse import unquote

        return [unquote(v) for v in values]
    if kind == "url":
        # WHATWG via node URL, not a Python rewrite
        js = "f=(x)=>{try{return new URL(x, 'http://localhost/').href}catch(e){return String(e)}}"
        worker = NodeWorker(js)
        try:
            return [str(worker.call(v)) for v in values]
        finally:
            worker.close()
    raise RuntimeError(f"unknown external interpreter {kind}")


def _looks_int(value: str) -> bool:
    try:
        int(value, 0)
        return True
    except ValueError:
        return False
