import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from patchclosure.graph import codeql


def test_codeql_is_installed():
    assert codeql.available()
    assert codeql.language_for("javascript") == "javascript"


@pytest.mark.parametrize("lang", ["javascript", "python", "java", "go", "ruby"])
def test_codeql_templates_compile(lang):
    work = Path(tempfile.mkdtemp(prefix="pc_qlc_"))
    pack = codeql.QLPACKS / codeql.PACK_KEY[lang]
    for name in ("qlpack.yml", "codeql-pack.lock.yml"):
        src = pack / name
        if src.is_file():
            shutil.copy2(src, work / name)
    (work / "CoReach.ql").write_text(
        codeql._render_query(lang, "(?i).*(src).*", "(?i).*(guard).*", "(?i).*(sink).*"),
        encoding="utf-8",
    )
    proc = subprocess.run(
        ["codeql", "query", "compile", str(work / "CoReach.ql")],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, proc.stderr[-800:] or proc.stdout[-800:]


def test_codeql_js_coreach(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.js").write_text(
        "function extractProtocol(address) {\n"
        "  return decodePath(checkSegment(address));\n"
        "}\n"
        "function checkSegment(p) { return p; }\n"
        "function decodePath(p) { return p; }\n"
    )
    result = codeql.co_reach(
        src, "javascript",
        ["extractProtocol"],
        ["checkSegment"],
        ["decodePath"],
        timeout=300,
    )
    assert not result.get("error"), result
    assert result["sink_calls"] >= 1
    assert result["guard_calls"] >= 1
    assert result["flows_src_to_sink"] >= 1
    assert result["co_reachable"] is True
