"""Ground nominated interpreters by slicing and executing them."""
from __future__ import annotations

import re
from pathlib import Path

from patchclosure import danger as D
from patchclosure.slice import execute as E
from patchclosure.slice import probe as P
from patchclosure.slice import fst as F
from patchclosure.slice.treesitter import locate_function


_ATK = re.compile(
    r"^(path|key|url|uri|file|name|addr|host|href|src|query|param|input|value|val)$",
    re.I,
)
_JS_KW = {
    "function", "return", "var", "let", "const", "if", "else", "for", "while",
    "new", "true", "false", "null", "undefined", "this", "typeof", "String",
    "Number", "JSON", "Math", "RegExp", "Object", "Array", "isNaN", "parseInt",
}


def ground_interpreter(srcroot: Path | None, pcg: dict) -> dict:
    interp = pcg.get("interpreter") or {}
    fn = interp.get("fn") or ""
    locus = str(interp.get("locus") or "in-product")
    sink_op = str((pcg.get("sink") or {}).get("op") or "")
    dpred, dfam, ddesc = D.danger_for(sink_op, fn, str(pcg.get("danger_target") or ""))
    out = {"locus": locus, "fn": fn, "danger_family": dfam, "danger_desc": ddesc, "danger": dpred}

    last = re.split(r"[.(]", str(fn))[-1]
    if last in {
        "replace", "replaceAll", "indexOf", "includes", "toLowerCase", "toUpperCase",
        "trim", "split", "join", "substring", "slice",
    } and locus != "stdlib":
        locus = "stdlib"
        out["locus"] = locus

    if locus == "stdlib":
        phi = _stdlib_phi(last)
        if phi is None:
            out["status"] = f"unknown stdlib op {fn!r}"
            return out
        probes = P.probes_from_source(fn)
        pairs = P.measure(phi, probes)
        out.update(_finish(phi, dpred, pairs, source=fn))
        out["status"] = "built" if pairs else "stdlib produced no pairs"
        out["runtime"] = "stdlib"
        return out

    if locus == "external":
        kind = "url" if re.search(r"url|browser|whatwg", fn, re.I) else "unquote"
        if re.search(r"strtol|parseInt|ip2long", fn, re.I):
            kind = "strtol"
        probes = P.probes_from_source(fn)
        try:
            ys = E.run_external(kind, probes)
            pairs = list(zip(probes, [str(y) for y in ys]))
        except Exception as exc:
            out["status"] = f"external harness failed: {exc}"
            return out
        out.update(_finish(lambda x: _ext_one(kind, x), dpred, pairs, source=fn))
        out["status"] = "built"
        out["runtime"] = kind
        return out

    if not srcroot:
        out["status"] = "no source tree to slice"
        return out
    loc = locate_function(srcroot, fn)
    if not loc:
        out["status"] = f"symbol {fn!r} not found; dropped before discharge"
        out["dropped"] = True
        return out
    src = loc["body"] + "\n" + loc.get("file_text", "")[:4000]
    probes = P.probes_from_source(src)
    transcribed = _phi_from_source(loc)
    if transcribed:
        pairs = P.measure(transcribed, probes)
        out.update(_finish(transcribed, dpred, pairs, source=loc["body"]))
        out["runtime"] = "source-transcribe"
        out["slice"] = {"path": str(loc["path"]), "line": loc["line"], "lang": loc["lang"]}
        out["status"] = "built" if pairs else "transcribe produced no pairs"
        return out
    built = _exec_slice(loc, dpred)
    if built.get("error") or not built.get("phi"):
        phi = _phi_from_source(loc)
        if not phi:
            out["status"] = built.get("error") or "slice failed"
            out["slice"] = {k: built.get(k) for k in ("path", "line", "lang")}
            return out
        pairs = P.measure(phi, probes)
        out.update(_finish(phi, dpred, pairs, source=loc["body"]))
        out["runtime"] = "source-transcribe"
        out["slice"] = {"path": str(loc["path"]), "line": loc["line"], "lang": loc["lang"]}
        out["status"] = "built" if pairs else "transcribe produced no pairs"
        return out
    phi = built["phi"]
    admits = built.get("admits") or (lambda _x: True)
    pairs = P.measure(phi, probes)
    if not pairs:
        phi2 = _phi_from_source(loc)
        if phi2:
            pairs = P.measure(phi2, probes)
            phi, admits = phi2, (lambda _x: True)
            built["runtime"] = "source-transcribe"
    out.update(_finish(phi, dpred, pairs, source=loc["body"], admits=admits))
    out["runtime"] = built.get("runtime")
    out["slice"] = {"path": str(loc["path"]), "line": loc["line"], "lang": loc["lang"]}
    out["status"] = "built" if pairs else "slice executed but produced no pairs"
    return out


def _finish(phi, danger, pairs, source="", admits=None):
    alpha = P.alphabet_from_pairs(pairs)
    fitted = F.fit(pairs)
    return {
        "phi": phi,
        "admits": admits or (lambda _x: True),
        "danger": danger,
        "pairs": pairs,
        "n_pairs": len(pairs),
        "alphabet": alpha,
        "fst": {k: fitted[k] for k in fitted if k != "model"},
        "fst_model": fitted,
        "domain": [a for a, _b in pairs],
    }


def _phi_from_source(loc: dict):
    """When the slice cannot run, transcribe a decoder the source actually has."""
    body = str(loc.get("body") or "") + "\n" + str(loc.get("file_text") or "")[:8000]
    if "%u" in body and "16" in body and "%" in body:
        return _percent_u_decode
    return None


def _percent_u_decode(x: str) -> str:
    out: list[str] = []
    i = 0
    n = len(x)
    while i < n:
        if x[i] == "%" and i + 1 < n and x[i + 1] in "uU" and i + 6 <= n:
            try:
                out.append(chr(int(x[i + 2 : i + 6], 16)))
                i += 6
                continue
            except ValueError:
                pass
        if x[i] == "%" and i + 3 <= n:
            try:
                out.append(chr(int(x[i + 1 : i + 3], 16)))
                i += 3
                continue
            except ValueError:
                pass
        out.append(x[i])
        i += 1
    return "".join(out)


def _stdlib_phi(name: str):
    if name in {"replace", "replaceAll"}:
        return lambda x: x.replace("\\", "/")
    if name == "toLowerCase":
        return lambda x: x.lower()
    if name == "toUpperCase":
        return lambda x: x.upper()
    if name == "trim":
        return lambda x: x.strip()
    if name in {"indexOf", "includes"}:
        return lambda x: x
    return None


def _ext_one(kind: str, x: str) -> str:
    return E.run_external(kind, [x])[0]


def _exec_slice(loc: dict, dpred) -> dict:
    lang, body, fname = loc["lang"], loc["body"], loc["name"]
    params = loc.get("params") or []
    if lang in {"javascript", "typescript", "tsx"}:
        return _exec_js(loc, body, fname, params, dpred)
    if lang == "python":
        ns = {}
        try:
            exec(body, ns)  # noqa: S102 — sliced product function
        except Exception as exc:
            return {"error": f"python slice failed: {exc}"}
        fnobj = ns.get(fname) or next((v for v in ns.values() if callable(v)), None)
        if not fnobj:
            return {"error": "python slice produced no callable"}
        return {"phi": lambda x, f=fnobj: str(f(x)), "runtime": "python"}
    if lang in {"php", "ruby", "go", "java"}:
        if not E.lang_available(lang):
            return {"error": f"{lang} runtime not installed"}
        harness = _batch_harness(lang, body, fname)
        if not harness:
            return {"error": f"no harness for {lang}"}

        def phi(x, h=harness, l=lang):
            rows = E.run_batch(l, h, [x])
            return (rows[0].get("y") if rows else None)

        return {"phi": phi, "runtime": lang, "path": str(loc["path"]), "line": loc["line"], "lang": lang}
    return {"error": f"slice-exec not wired for {lang}"}


def _exec_js(loc, body, fname, params, dpred) -> dict:
    helpers = _js_helpers(loc.get("file_text") or "", body)
    if body.lstrip().startswith("function"):
        if re.match(r"\s*function\s*\(", body):
            body = re.sub(r"^(\s*)function\s*\(", rf"\1function {fname}(", body, count=1)
    elif body.lstrip().startswith("("):
        body = f"const {fname} = {body}"
    elif "function" not in body[:40]:
        body = "function " + body
    atk = 0
    for i, name in enumerate(params):
        if _ATK.match(name):
            atk = i
            break
    args = []
    for i, name in enumerate(params):
        args.append("x" if i == atk else "''")
    call = f"{fname}({', '.join(args)})" if params else f"{fname}(x)"
    js = (
        helpers + "\n" + body + "\n"
        f"f=(x)=>{{let y; try{{ y={call}; }}catch(e){{ y=String(e); }} "
        "if(typeof y!=='string'){try{y=JSON.stringify(y);}catch(e){y=String(y);}} return y;};"
    )
    try:
        worker = E.NodeWorker(js)
    except Exception as exc:
        return {"error": f"node spawn failed: {exc}"}
    return {
        "phi": lambda x, w=worker: w.call(x),
        "runtime": "node",
        "worker": worker,
        "path": str(loc["path"]),
        "line": loc["line"],
        "lang": loc["lang"],
    }


def _js_helpers(file_text: str, body: str) -> str:
    """Keep top-level function / const helpers the slice names."""
    needed = set(re.findall(r"\b([A-Za-z_$][\w$]*)\b", body)) - _JS_KW
    kept = []
    for match in re.finditer(
        r"(?:function\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{[^}]*\})"
        r"|(?:(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*[^;]+;)",
        file_text,
    ):
        name = match.group(1) or match.group(2)
        if name in needed and "require(" not in match.group(0):
            kept.append(match.group(0))
    return "\n".join(kept)


def _batch_harness(lang: str, body: str, fname: str) -> str | None:
    if lang == "php":
        fn = re.sub(r"(public|private|protected|static|final)\s+", "", body)
        return (
            fn + "\nwhile (($l = fgets(STDIN)) !== false) { $x = json_decode($l, true);"
            f" $y = null; try {{ $y = {fname}($x); }} catch (Throwable $e) {{ $y = strval($x); }}"
            " if (!is_string($y)) { $y = json_encode($y); }"
            " echo json_encode(['y' => $y]), \"\\n\"; }"
        )
    if lang == "ruby":
        return (
            body + "\nrequire 'json'\nSTDIN.each_line do |l|\n  x = JSON.parse(l)\n"
            f"  begin\n    y = {fname}(x)\n  rescue => e\n    y = x.to_s\n  end\n"
            "  y = y.to_json unless y.is_a?(String)\n  puts({y: y}.to_json)\nend"
        )
    if lang == "go":
        return (
            "package main\nimport (\"bufio\";\"encoding/json\";\"os\";\"fmt\")\n"
            + body + "\nfunc main(){\n  sc := bufio.NewScanner(os.Stdin)\n"
            f"  for sc.Scan(){{\n    var x string\n    json.Unmarshal(sc.Bytes(), &x)\n"
            f"    y := fmt.Sprintf(\"%v\", {fname}(x))\n"
            "    b,_ := json.Marshal(map[string]string{\"y\": y})\n    os.Stdout.Write(append(b,'\\n'))\n  }\n}"
        )
    if lang == "java":
        return (
            "import java.util.*; public class Slice {\n" + body + "\n"
            "  static String esc(String s){ return s.replace(\"\\\\\",\"\\\\\\\\\").replace(\"\\\"\",\"\\\\\\\"\"); }\n"
            "  public static void main(String[] a) throws Exception {\n"
            "    Scanner sc = new Scanner(System.in);\n"
            "    while (sc.hasNextLine()) {\n"
            "      String l = sc.nextLine().trim();\n"
            "      String x = l.length()>=2 ? l.substring(1, l.length()-1) : l;\n"
            f"      Object y; try {{ y = {fname}(x); }} catch (Throwable t) {{ y = x; }}\n"
            "      System.out.println(\"{\" + \"\\\"y\\\":\\\"\" + esc(String.valueOf(y)) + \"\\\"}\");\n"
            "    }\n  }\n}"
        )
    return None
