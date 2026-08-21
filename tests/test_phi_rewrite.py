from patchclosure.assemble import assemble_variants
from patchclosure.carriers import discover_siblings, issue_identity
from patchclosure.ip_enum import gen_ip_candidates
from patchclosure.preimage import ips_in_seed, seed_rewrites


def test_phi_inverse_rewrites_decoded_form_in_seed():
    pairs = [("%2e", "."), (".", ".")]
    frags = seed_rewrites({"path": "/./WEB-INF/x"}, pairs)
    xs = [f.get("x") for f in frags]
    assert any(x and "%2e" in str(x) for x in xs)


def test_phi_eraser_prefixes_empty_output():
    pairs = [("\x08", ""), ("\\", "\\")]
    frags = seed_rewrites({"to": "http://evil\\@ok"}, pairs)
    xs = [f.get("x") for f in frags]
    assert any(str(x).startswith("\x08") for x in xs)
    assert any(isinstance(f.get("candidate"), dict) and str(f["candidate"].get("to", "")).startswith("\x08") for f in frags)


def test_field_move_replays_token_on_sibling_field():
    seed = {"host": "127.0.0.1", "path": "/x\r\nGET flag HTTP/1.1", "query": "a=1"}
    sibs = discover_siblings(None, seed)
    moves = [s for s in sibs if s.get("kind") == "field-move"]
    assert moves
    cand = issue_identity(seed, moves[0])
    assert cand and cand.get("_assemble", "").startswith("issue-identity:")


def test_scheme_from_seed_shape_not_scheme_table():
    from patchclosure.agent import scheme_variants

    sch = scheme_variants({"url": "phar://work/x"})
    assert any("phar:///" in str(f.get("x")) for f in sch)
    assert any(str(f.get("x")).startswith("PHAR://") for f in sch)


def test_token_shift_only_uses_literals_from_this_guard():
    from patchclosure.agent import guard_token_shift

    only = guard_token_shift(
        {"path": "__proto__.pcbUnlock"},
        [{"code": "if (k === '__proto__') return;"}],
    )
    xs = [str(f.get("x")) for f in only]
    assert not any("constructor.prototype" in x for x in xs)
    assert not any("a.__proto__" in x for x in xs)
    two = guard_token_shift(
        {"path": "__proto__.pcbUnlock"},
        [{"code": "if (k === '__proto__' || k === 'constructor') return;"}],
    )
    assert any("constructor" in str(f.get("x")) and "constructor.prototype" not in str(f.get("x")) for f in two)


def test_agent_source_has_no_bypass_alias_table():
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "patchclosure" / "agent.py").read_text()
    for banned in (
        "constructor.prototype",
        "a.__proto__",
        "PHAR://",
        "phar:///",
        'mode"] = "residual"',
    ):
        assert banned not in src


def test_map_nest_and_sibling_maps():
    from patchclosure.agent import map_nest, sibling_maps

    seed = {"mode": "a", "query": {"#x": "1"}}
    assert any("x" in (f["candidate"].get("query") or {}) for f in map_nest(seed))
    moved = sibling_maps(seed, 'candidate.get("destination_query")')
    assert any(f["candidate"].get("destination_query") == {"#x": "1"} for f in moved)


def test_probe_space_reads_switch_literals():
    from patchclosure.agent import probe_space

    text = 'def run_probe(c):\n    if probe == "copy":\n        pass\n    elif probe == "move":\n        pass\n'
    frags = probe_space({"probe": "move"}, text)
    assert any(f.get("x") == "copy" for f in frags)


def test_agent_propose_noop_without_seed():
    from patchclosure.agent import propose

    assert propose(seed=None, diff="", guards=[], pairs=[]) == []


def test_phi_equivalent_rewrites_seed_token():
    pairs = [("%2e", "."), ("%u002e", "."), ("%2E", "."), ("abc", "abc")]
    frags = seed_rewrites({"path": "/%2e/WEB-INF/pcb-secret.txt"}, pairs)
    xs = [f.get("x") for f in frags]
    assert any(x and "%u002e" in str(x) and "WEB-INF" in str(x) for x in xs)


def test_no_pairs_emits_nothing():
    assert seed_rewrites({"path": "/%2e/WEB-INF/pcb-secret.txt"}, []) == []
    assert seed_rewrites({"filter": '[{"$where": "true"}]'}, [("%2e", ".")]) == []


def test_no_bypass_catalog_without_measurement():
    empty = seed_rewrites(
        {
            "path": "//internal-sidecar/flag",
            "spec": "__proto__.pcbUnlock",
            "filter": '[{"$where": "true"}]',
        },
        None,
    )
    assert empty == []
    assert ips_in_seed({"host": "0177.0.0.1"}) == ["0177.0.0.1"]
    assert ips_in_seed({"avatar": "http://[::1]:9111/"}) == ["[::1]"]
    from patchclosure.ip_enum import encodings_of, parse_ipv4

    assert parse_ipv4("[::1]") == [127, 0, 0, 1]
    assert any(x == "[::ffff:7f00:1]" for x in encodings_of([127, 0, 0, 1]))


def test_ip_enum_only_from_seed_target():
    none = gen_ip_candidates([], targets=(), cap=80)
    assert none["fragments"] == []
    gen = gen_ip_candidates([], targets=("0177.0.0.1",), cap=80)
    xs = [f["x"] for f in gen["fragments"]]
    assert any("0x7f" in x.lower() for x in xs)
    assert "0177.0.0.1" in xs or "127.0.0.1" in xs


def test_seed_exec_switch_is_not_a_sibling_catalog():
    class _Mod:
        BASE = {"rewrite": {}, "proxypass": {}}
        __file__ = "/tmp/does-not-need-to-exist.py"

    seed = {"op": "upload", "route": "rewrite", "technique": "param-union"}
    sibs = discover_siblings(None, seed, exec_mod=_Mod)
    assert not any(s.get("kind") in {"seed-key", "route-name", "op"} for s in sibs)


def test_obligation_mislabel_still_keeps_phi_rewrites():
    """BUILD often says obligation; measured φ still has to discharge."""
    from patchclosure.pipeline import _uniq

    phi = [{"x": "/%u002e/WEB-INF/pcb-secret.txt", "backend": "phi-equivalent"}]
    merged = _uniq(phi + [])
    assert merged[0]["x"].startswith("/%u002e")


def test_joern_identifiers_drop_prose():
    from patchclosure.graph.joern import identifiers

    assert "decodePath" in identifiers(["decodePath", "URI path parsing (canonicalization)"])
    assert "URI" not in identifiers(["URI path parsing (canonicalization)"])
    assert "path" not in identifiers(["path", "param"])


def test_graph_localizes_existing_symbol():
    from patchclosure.build import apply_graph

    pcg = {"interpreter": {"fn": "URI", "locus": "in-product"}, "notes": []}
    out = apply_graph(
        pcg,
        {"ranked_guards": [{"guard": "identity", "co_reachable": True}]},
        None,
        "",
    )
    assert out["interpreter"]["fn"] == "identity"


def test_graph_replaces_absent_nomination_with_decoder():
    from patchclosure.build import apply_graph

    pcg = {"interpreter": {"fn": "URI", "locus": "in-product"}, "notes": []}
    out = apply_graph(
        pcg,
        {
            "ranked_guards": [
                {"guard": "param", "present": True, "co_reachable": False},
                {"guard": "decodePath", "present": True, "co_reachable": False},
            ]
        },
        None,
        "",
    )
    assert out["interpreter"]["fn"] == "decodePath"


def test_graph_does_not_jump_to_first_present_name():
    from patchclosure.build import apply_graph

    pcg = {"interpreter": {"fn": "decodePath", "locus": "in-product"}, "notes": []}
    out = apply_graph(
        pcg,
        {
            "ranked_guards": [
                {"guard": "param", "present": True, "co_reachable": False},
                {"guard": "decodePath", "present": True, "co_reachable": False},
            ]
        },
        None,
        "",
    )
    assert out["interpreter"]["fn"] == "decodePath"


def test_field_sibling_moves_crlf_to_host():
    seed = {"host": "127.0.0.1", "path": "/x\r\nGET flag HTTP/1.1"}
    sibs = discover_siblings(None, seed)
    assert any(s.get("kind") == "field" for s in sibs)
    cand = issue_identity(seed, sibs[0])
    assert cand and "\r\n" in cand["host"] and "\r\n" not in cand["path"]


def test_assemble_splices_guard_literal():
    vars_ = assemble_variants(
        {"value": "pcbseed\r\nX-Pcb-Injected: __PCB_FLAG__"},
        "\r",
        tokens=["\r\n"],
    )
    assert any("\r\n" not in str(v.get("value")) and "\r" in str(v.get("value")) for v in vars_)


def test_assemble_places_full_rewritten_field():
    vars_ = assemble_variants(
        {"path": "/%2e/WEB-INF/pcb-secret.txt"},
        "/%u002e/WEB-INF/pcb-secret.txt",
    )
    assert any("%u002e" in str(v.get("path")) and "WEB-INF" in str(v.get("path")) for v in vars_)
