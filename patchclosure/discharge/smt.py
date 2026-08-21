"""SMT string-fragment preimage (paper §impl).

Prefix, contains, length, and regular constraints go to Z3. Anything
outside that fragment is decided by executing the guard and φ.
"""
from __future__ import annotations

import re

try:
    import z3
except ImportError:  # pragma: no cover
    z3 = None


def available() -> bool:
    return z3 is not None


def z3_preimage(build_guard, build_danger_of_phi, kmin=1, kmax=64, max_solutions=10) -> list[str]:
    if z3 is None:
        raise RuntimeError("z3-solver is not installed")
    x = z3.String("x")
    solver = z3.Solver()
    solver.add(build_guard(x))
    solver.add(build_danger_of_phi(x))
    solver.add(z3.Length(x) >= kmin, z3.Length(x) <= kmax)
    sols = []
    while len(sols) < max_solutions and solver.check() == z3.sat:
        model = solver.model()
        val = model[x].as_string() if model[x] is not None else ""
        sols.append(val)
        solver.add(x != z3.StringVal(val))
    return sols


def try_smt(guard_code: str, danger_target: str, fst: dict | None, kmax: int = 64) -> dict | None:
    """Build Z3 constraints when guard and danger sit in the decidable fragment."""
    if z3 is None:
        return None
    kind = (fst or {}).get("kind") or ((fst or {}).get("fst_model") or {}).get("kind")
    if kind not in {None, "identity", "percent_decode"}:
        return None
    guard_fn = _guard_constraint(guard_code)
    danger_fn = _danger_constraint(danger_target, kind == "percent_decode")
    if not guard_fn or not danger_fn:
        return None
    try:
        sols = z3_preimage(guard_fn, danger_fn, kmin=1, kmax=min(kmax, 16), max_solutions=8)
    except Exception as exc:
        return {"backend": "z3", "error": str(exc)[:200]}
    return {"backend": "z3", "witnesses": sols, "kind": kind or "identity"}


def _guard_constraint(code: str):
    """admits(x) as Z3: True unless a simple reject pattern is visible."""
    if z3 is None:
        return None
    # if /contains/includes "LIT" → reject strings containing LIT
    lit = re.search(r"""(?:contains|includes|indexOf|find)\s*\(\s*['\"]([^'\"]+)['\"]""", code)
    if lit:
        token = lit.group(1)

        def build(x, t=token):
            return z3.Not(z3.Contains(x, z3.StringVal(t)))

        return build
    rx = re.search(r"""=~\s*/((?:\\.|[^/])+)/""", code)
    if not rx:
        rx = re.search(r"""new RegExp\(\s*['\"]([^'\"]+)['\"]""", code)
    if rx:
        try:
            regex = z3.Re(rx.group(1))
        except Exception:
            return None

        def build(x, r=regex):
            return z3.Not(z3.InRe(x, r))

        return build
    # no recognizable constraint → cannot put L_G in the solver
    return None


def _danger_constraint(target: str, decoded: bool):
    if z3 is None:
        return None
    low = (target or "").lower()

    def after(x):
        return x  # identity; percent_decode is not in Z3's cheap fragment

    if "cr" in low or "lf" in low or "header" in low:
        def build(x):
            y = after(x)
            return z3.Or(z3.Contains(y, z3.StringVal("\r")), z3.Contains(y, z3.StringVal("\n")))

        return build
    if "dot" in low or ".." in low or "path" in low or "segment" in low:
        def build(x):
            return z3.Contains(after(x), z3.StringVal(".."))

        return build
    return None
