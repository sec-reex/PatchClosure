BUILD = """You are analyzing whether a security patch is INCOMPLETE, using the
language-gap model: the guard accepts language L_G; the sink is dangerous on
language L_S; the interpreter phi maps attacker input to what the sink consumes.
A residual x satisfies: x passes the guard AND phi(x) is dangerous at the sink.

You are given the patch diff and the source of the changed file(s). Do NOT
output payloads. Output STRICT JSON only:
{{
  "guard": {{"where":"file:line","code":"the check/normalize the PATCH added","reads":"which attacker input"}},
  "sink": {{"where":"file:line","op":"the dangerous op","in_diff":true}},
  "interpreter": {{"fn":"transform between guard and sink","where":"file:line","locus":"in-product|stdlib|external"}},
  "gap_type":"language|obligation|unclear",
  "danger_target":"concrete description of what makes phi(x) dangerous at THIS sink",
  "obligation":"short name if gap_type is obligation else null",
  "carriers":["sibling sites that should bear the same duty, if obligation"],
  "notes":"uncertainties"
}}

=== PATCH DIFF ===
{diff}
=== FULL SOURCE OF CHANGED FILE(S) ===
{src}
=== SEED (blocked original exploit; not an answer) ===
{seed}
"""

BUILD_REFINE = """Your previous nomination could not be grounded against the
source tree. The interpreter.fn must be a REAL function that exists
(a definition we can slice and run). Do NOT invent payloads.

Grounding error: {error}
Functions that actually exist in the changed / nearby source:
{symbols}

Reply with the SAME JSON schema. Prefer interpreter.fn from the
symbol list. If the transform is a standard-library or runtime
parser (decode, URL, inet_aton), set locus to stdlib or external
and name that parser.

=== PREVIOUS JSON ===
{prev}

=== PATCH DIFF ===
{diff}
=== SOURCE (changed files) ===
{src}
"""

TRANSCRIBE = """Transcribe THREE Python predicates FROM THE REAL SOURCE below.
Faithful transcriptions of what the code does (cite source lines). Do NOT
special-case any payload. Pure stdlib only (re, urllib.parse). Output the
functions in the TAGGED BLOCKS (raw Python, not JSON).

<ADMITS>
def admits(x):
    # True iff x SURVIVES the patch guard (guard does NOT block x)
    return True
</ADMITS>
<PHI>
def phi(x):
    # interpreter transform the sink applies to x (decode/parse/normalize)
    return x
</PHI>
<DANGER>
def danger(y):
    # True iff y (=phi(x)) is dangerous at the sink per danger_target
    return False
</DANGER>
<META>
{{"alphabet_hint": ["%","/",".","\\\\r","\\\\n",":","@"], "evidence": ["file:line ..."]}}
</META>

danger_target for this case: {danger_target}
guard added by patch: {guard}
interpreter: {interp}

=== REAL SOURCE (guard file + interpreter file) ===
{src}
"""

CARRIERS = """The patch installs a security obligation at some sites and may have
missed siblings. From the diff and source, name the callee the patch wrapped
and a Semgrep-style pattern for guarded vs unguarded calls. Do NOT emit
payloads. STRICT JSON:
{{
  "callee":"function or method name",
  "language":"python|javascript|php|java|ruby|go",
  "guarded_pattern":"semgrep pattern that matches the PATCHED call",
  "unguarded_pattern":"semgrep pattern that matches any call of the callee",
  "source_pattern":"how attacker input enters, e.g. request.args.get(...)"
}}

=== PATCH DIFF ===
{diff}
=== CHANGED SOURCE ===
{src}
"""
