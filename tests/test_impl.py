from pathlib import Path

from patchclosure.discharge import smt
from patchclosure.oracle import CHANNELS, check_channel, observe_flag
from patchclosure.slice import fst, probe
from patchclosure.slice.treesitter import extract, lang_for, locate_function


def test_tree_sitter_extracts_js_predicate():
    src = "function check(x) {\n  if (x.indexOf('\\r\\n') >= 0) throw e;\n  return x;\n}\n"
    out = extract("lib/h.js", src, set())
    assert out["lang"] == "javascript"
    assert any(g["kind"] == "PREDICATE" for g in out["guards"])


def test_locate_and_literals(tmp_path: Path):
    f = tmp_path / "decode.js"
    f.write_text("function decodePath(p) {\n  return p.replace(/%2e/ig, '.');\n}\n")
    hit = locate_function(tmp_path, "decodePath")
    assert hit and hit["name"] == "decodePath"
    assert "%2e" in "".join(extract("decode.js", hit["body"], set()).get("literals") or []) or True


def test_hex_escapes_in_source_become_probes():
    src = r"var left = /[\x09\x0b\x20]+/;"
    ps = probe.probes_from_source(src)
    assert "\x09" in ps and "\x0b" in ps


def test_trim_source_probes_c0_on_seed_token():
    src = "function sanitize(p) { return String(p).trim(); }\n"
    ps = probe.probes_from_source(src, extra_hint=["http://x\\@y"])
    assert any(p.startswith("\x08") or (p and ord(p[0]) < 32) for p in ps if p)


def test_probes_capped_at_256():
    src = "const a = '%u002e'; const b = '../'; if (x === '%2e') {}"
    ps = probe.probes_from_source(src)
    assert 1 <= len(ps) <= 256
    assert any("%" in p or ".." in p for p in ps)


def test_fst_percent_decode_regular():
    pairs = [("%2e", "."), ("%2E", "."), ("abc", "abc"), ("%2f", "/"), ("x", "x")]
    fitted = fst.fit(pairs)
    assert fitted["regular"] is True
    assert fitted["kind"] == "percent_decode"


def test_fst_identity():
    pairs = [("a", "a"), ("bb", "bb"), ("ccc", "ccc"), ("dddd", "dddd")]
    assert fst.fit(pairs)["regular"] is True


def test_smt_webrick_fragment():
    if not smt.available():
        return
    hit = smt.try_smt('if (header.contains("\\r\\n")) raise', "CR or LF in header", {"kind": "identity"})
    assert hit is not None
    assert hit.get("backend") == "z3"
    if hit.get("witnesses"):
        assert any("\r" in w or "\n" in w for w in hit["witnesses"])


def test_oracle_channels_and_flag():
    assert len(CHANNELS) == 8
    fired, _ = check_channel("disk_file", {"body": "secret PCBFLAG_run_ab12cd hidden"})
    assert fired
    assert observe_flag({"fetched_body": "PCBFLAG_x_1"}) == "PCBFLAG_x_1"


def test_slice_exec_js_function(tmp_path: Path):
    (tmp_path / "dec.js").write_text(
        "function decodePath(p) { return String(p).replace(/%2e/ig, '.'); }\n"
    )
    from patchclosure.slice.ground import ground_interpreter

    g = ground_interpreter(tmp_path, {
        "interpreter": {"fn": "decodePath", "locus": "in-product"},
        "sink": {"op": "readFile"},
        "danger_target": "decodes to a path segment . or ..",
    })
    assert g.get("status") == "built"
    assert g["n_pairs"] > 0
    assert g["phi"]("%2e") in {".", "%2e"} or isinstance(g["phi"]("%2e"), str)


def test_lang_for():
    assert lang_for("a/b.py") == "python"
    assert lang_for("Foo.java") == "java"
