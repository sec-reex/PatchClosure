from patchclosure.assemble import assemble_variants
from patchclosure.ip_enum import gen_ip_candidates
from patchclosure.preimage import exec_bounded_preimage


def test_webrick_lone_cr():
    def admits(x):
        return "\r\n" not in x

    def phi(x):
        return x

    def danger(y):
        return "\r" in y or "\n" in y

    result = exec_bounded_preimage(admits, phi, danger, alphabet=["a", "\r", "\n"], kmax=2)
    assert result["shortest"] in {"\r", "\n"}
    assert all("\r\n" not in w for w in result["witnesses"])


def test_ip_uppercase_hex():
    out = gen_ip_candidates([], targets=("127.0.0.1",), cap=40)
    xs = {f["x"] for f in out["fragments"]}
    assert "0X7F000001" in xs or any(x.startswith("0X7F") for x in xs)
    assert "0177.0.0.1" in xs or "0x7f.0.0.1" in xs


def test_assemble_places_full_rewritten_field():
    variants = assemble_variants(
        {"path": "/%2e/WEB-INF/pcb-secret.txt"},
        "/%u002e/WEB-INF/pcb-secret.txt",
    )
    paths = [v["path"] for v in variants if "path" in v]
    assert any("%u002e" in p and "WEB-INF" in p for p in paths)
