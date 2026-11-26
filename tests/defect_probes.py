"""Probes for the defects fixed in the package (see TESTING.md, "Defects fixed").

Each probe is a small Python program run in a SUBPROCESS, so that it can be run under
`python3 -O` (which strips `assert` statements). A probe prints exactly one line:

    RAISED <ExceptionType> <message>     the guard fired
    RETURNED <value>                     the call came back with a value

The packaged code must print, with and without -O, the prefix that EXPECT gives for the probe
(RAISED, for a probe not listed there).

`IMPORTS_NEW` binds the module under test to the name M.
"""
import os
import subprocess
import sys

IMPORTS_NEW = {
    "aig": "from certlab.encoders import aig as M",
    "xag": "from certlab.encoders import xag as M",
    "mig": "from certlab.encoders import mig as M",
    "multi_aig": "from certlab.encoders import multi_aig as M",
    "multi_mig": "from certlab.encoders import multi_mig as M",
    "npn": "from certlab import npn as M",
    "forced_multi": "from certlab.certify import forced_multi as M",
    "witness": "from certlab import witness as M",
}

# Fake kissat behaviours: none of them is a verdict (10 = SAT, 20 = UNSAT).
FAKE_KISSAT = {
    "exit0": "exit 0",
    "exit1": "exit 1",
    "sigkill": "kill -9 $$",
    "no_status_line": "echo 'c only a comment'; exit 3",
}

_TRY = """
try:
    r = {call}
    print("RETURNED", repr(r)[:200])
except Exception as e:
    print("RAISED", type(e).__name__, str(e)[:200])
"""

PROBES = {}

# D1: kissat failure must not read as UNSAT (xag, mig). The harness puts a fake kissat on PATH.
for _b in ("xag", "mig"):
    PROBES[f"solver_failure_{_b}"] = (_b, "{imp}\n" + _TRY.format(call="M.solve_k(2, 0b1000, 1)"))

# D1: a SAT model that does not compute tt must not be returned as a witness. The probe writes its
# own fake kissat (exit 10 + a model selecting NOR for an AND target) into $FAKEBIN.
_BAD_MODEL_KISSAT = """
import os, stat
{imp}
enc = M.{cls}(2, 1, 0b1000).build()
sel = [o for o in enc.options[1] if {pred}][0][{idx}]
lits = [sel] + [-o[{idx}] for o in enc.options[1] if o[{idx}] != sel] + [-enc.out_pol]
p = os.path.join(os.environ["FAKEBIN"], "kissat")
open(p, "w").write("#!/bin/sh\\necho 's SATISFIABLE'\\necho 'v " + " ".join(map(str, lits)) + " 0'\\nexit 10\\n")
os.chmod(p, 0o755)
""" + _TRY.format(call="M.solve_k(2, 0b1000, 1, return_circuit=True)")
PROBES["bad_model_xag"] = ("xag", _BAD_MODEL_KISSAT.replace("{cls}", "XAGEncoder")
                           .replace("{pred}", "o[0] == 'and' and o[2] == 1 and o[4] == 1").replace("{idx}", "5"))
PROBES["bad_model_mig"] = ("mig", _BAD_MODEL_KISSAT.replace("{cls}", "MIGEncoder")
                           # MAJ(0, ~x1, ~x2) = NOR(x1, x2): constant node 0 with pa=0
                           .replace("{pred}", "o[:6] == (0, 0, 1, 1, 2, 1)").replace("{idx}", "6"))

# D1: the AIG verdict guard (pysat path). A fake `pysat.solvers.Glucose4` returns a model that
# selects AND(~x1, ~x2) for an AND target.
PROBES["bad_model_aig"] = ("aig", """
import sys, types
{imp}
enc = M.AIGEncoder(2, 1, 0b1000).build()
sel = [o[4] for o in enc.options[1] if o[1] == 1 and o[3] == 1][0]
model = [sel] + [-o[4] for o in enc.options[1] if o[4] != sel] + [-enc.out_pol]
class Glucose4:
    def __init__(self, bootstrap_with=None): pass
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def solve(self): return True
    def get_model(self): return model
mod = types.ModuleType("pysat.solvers"); mod.Glucose4 = Glucose4
pkg = types.ModuleType("pysat"); pkg.solvers = mod
sys.modules["pysat"] = pkg; sys.modules["pysat.solvers"] = mod
""" + _TRY.format(call="M.solve_k(2, 0b1000, 1, return_circuit=True)"))

# D1: decode must reject a model that selects two options for one gate.
for _b, _cls, _idx in (("aig", "AIGEncoder", 4), ("xag", "XAGEncoder", 5), ("mig", "MIGEncoder", 6)):
    PROBES[f"decode_two_options_{_b}"] = (_b, "{imp}\n"
        f"enc = M.{_cls}(2, 1, 0b1000).build()\n"
        f"two = [o[{_idx}] for o in enc.options[1]][:2]\n"
        + _TRY.format(call="enc.decode(two)"))

# Phase 2, multi-output encoders: the same three guards (solver failure, SAT model that does not
# compute the tables, decode of an ambiguous model), plus a fence that does not sum to k.
for _b in ("multi_aig", "multi_mig"):
    PROBES[f"solver_failure_{_b}"] = (_b, "{imp}\n" + _TRY.format(call="M.solve_k(2, [0b1000], 1)"))

# The fake model selects NOR(x1, x2) for gate 1 and routes output 0 to gate 1 (node 3), for an
# AND target: decodable, but wrong on rows 00 and 11 (NOR and AND agree on 01 and 10).
_BAD_MODEL_MULTI = """
import os
{imp}
enc = M.{cls}(2, 1, [0b1000]).build()
sel = [o for o in enc.options[1] if {pred}][0][{idx}]
lits = [sel] + [-o[{idx}] for o in enc.options[1] if o[{idx}] != sel]
lits += [enc.osel[(0, 3)]] + [-v for (o, nd), v in enc.osel.items() if (o, nd) != (0, 3)]
lits += [-enc.opol[0]]
p = os.path.join(os.environ["FAKEBIN"], "kissat")
open(p, "w").write("#!/bin/sh\\necho 's SATISFIABLE'\\necho 'v " + " ".join(map(str, lits)) + " 0'\\nexit 10\\n")
os.chmod(p, 0o755)
""" + _TRY.format(call="M.solve_k(2, [0b1000], 1{extra})")
PROBES["bad_model_multi_aig"] = ("multi_aig", _BAD_MODEL_MULTI.replace("{cls}", "MultiAIGEncoder")
                                 .replace("{pred}", "o[1] == 1 and o[3] == 1").replace("{idx}", "4")
                                 .replace("{extra}", ""))
PROBES["bad_model_multi_mig"] = ("multi_mig", _BAD_MODEL_MULTI.replace("{cls}", "MultiMIGEncoder")
                                 .replace("{pred}", "o[:6] == (0, 0, 1, 1, 2, 1)").replace("{idx}", "6")
                                 .replace("{extra}", ", return_circuit=True"))

for _b, _cls, _idx in (("multi_aig", "MultiAIGEncoder", 4), ("multi_mig", "MultiMIGEncoder", 6)):
    PROBES[f"decode_two_options_{_b}"] = (_b, "{imp}\n"
        f"enc = M.{_cls}(2, 1, [0b1000]).build()\n"
        f"two = [o[{_idx}] for o in enc.options[1]][:2] + [enc.osel[(0, 3)]]\n"
        + _TRY.format(call="enc.decode(two)"))
    PROBES[f"decode_two_output_nodes_{_b}"] = (_b, "{imp}\n"
        f"enc = M.{_cls}(2, 1, [0b1000]).build()\n"
        f"one = [o[{_idx}] for o in enc.options[1]][:1] + [enc.osel[(0, 3)], enc.osel[(0, 1)]]\n"
        + _TRY.format(call="enc.decode(one)"))

# Phase 2, solver verdict (review of 0.2.0): exactly one status line ("s ..."), and it must agree
# with the exit code. A comment that mentions a verdict is not a status line. The fake kissat
# prints a CORRECT model for an AND target (gate 1 = AND(x1, x2), output 0 = gate 1), so a probe
# that is accepted returns SAT with a witness.
_VERDICT_MULTI = """
import os
{imp}
enc = M.{cls}(2, 1, [0b1000]).build()
sel = [o for o in enc.options[1] if {pred}][0][{idx}]
lits = [sel] + [-o[{idx}] for o in enc.options[1] if o[{idx}] != sel]
lits += [enc.osel[(0, 3)]] + [-v for (o, nd), v in enc.osel.items() if (o, nd) != (0, 3)]
lits += [-enc.opol[0]]
model = "v " + " ".join(map(str, lits)) + " 0"
lines = [l.replace("MODEL", model) for l in {lines}]
p = os.path.join(os.environ["FAKEBIN"], "kissat")
open(p, "w").write(chr(10).join(["#!/bin/sh"] + lines) + chr(10))
os.chmod(p, 0o755)
""" + _TRY.format(call="M.solve_k(2, [0b1000], 1{extra})")
_VERDICT_CASES = {
    # name: lines of the fake kissat ("MODEL" is replaced by the v line of the correct model)
    "verdict_comment_is_not_a_status_line": [
        "echo 'c previous run: s UNSATISFIABLE'", "echo 's SATISFIABLE'", "echo 'MODEL'", "exit 10"],
    "verdict_status_line_missing": ["echo 'MODEL'", "exit 10"],
    "verdict_two_status_lines": [
        "echo 's SATISFIABLE'", "echo 's UNSATISFIABLE'", "echo 'MODEL'", "exit 10"],
    "verdict_disagrees_with_exit_code": ["echo 's UNSATISFIABLE'", "exit 10"],
    # the dangerous direction: a SAT status line with the UNSAT exit code must not read as either
    "verdict_sat_line_with_unsat_exit_code": ["echo 's SATISFIABLE'", "echo 'MODEL'", "exit 20"],
}
for _case, _lines in _VERDICT_CASES.items():
    for _b, _cls, _pred, _idx, _extra in (
            ("multi_aig", "MultiAIGEncoder", "o[:4] == (1, 0, 2, 0)", "4", ""),
            ("multi_mig", "MultiMIGEncoder", "o[:6] == (0, 0, 1, 0, 2, 0)", "6", ", return_circuit=True")):
        PROBES[f"{_case}_{_b}"] = (_b, _VERDICT_MULTI.replace("{cls}", _cls).replace("{pred}", _pred)
                                   .replace("{idx}", _idx).replace("{extra}", _extra)
                                   .replace("{lines}", repr(_lines)))

PROBES["fence_must_sum_to_k_multi_mig"] = ("multi_mig", "{imp}\n" + _TRY.format(
    call="M.MultiMIGEncoder(3, 3, M.sum_tts(3), fence=(1, 1))"))

# D1: NPN validation must reject a census whose representative is not canonical.
PROBES["npn_validate_corrupt_csv"] = ("npn", """
import csv, os, tempfile
{imp}
rows = list(csv.DictReader(open(M.CENSUS_CSV)))
for r in rows:
    if r["npn_rep_dec"] == "1":
        r["npn_rep_dec"] = "2"; r["npn_rep_hex"] = "0x0002"   # same class, not the minimum
p = os.path.join(tempfile.mkdtemp(), "bad.csv")
with open(p, "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
M.CENSUS_CSV = p
""" + _TRY.format(call="M.validate()"))

# D1: witness legs must raise on a solver failure instead of continuing.
PROBES["witness_leg_solver_failure"] = ("witness", """
{imp}
M.TT, M.N, M.OPT = 0x03DE, 4, 6
""" + _TRY.format(call="M.leg_optlb()"))

# D5: build_amo_shared without n must not silently pick a module default.
PROBES["amo_shared_requires_n"] = ("forced_multi", "{imp}\n" + _TRY.format(
    call="(lambda r: (r[0], M.build_amo_shared(0x03de, 6, n=4)[0]))(M.build_amo_shared(0x03de, 6))"))


# What each probe must print (prefix). A probe not listed here must print "RAISED"; the listed ones
# pin the exception type and the guard's message, so an accidental error elsewhere in the call
# (a TypeError, say) does not pass for the guard.
EXPECT = {
    "bad_model_xag": "RAISED RuntimeError SAT model does not simulate",
    "bad_model_mig": "RAISED RuntimeError SAT model does not simulate",
    "bad_model_aig": "RAISED RuntimeError REJECTED: the circuit does not match the truth table",
    "decode_two_options_aig": "RAISED ValueError gate 1: selection is not unique",
    "decode_two_options_xag": "RAISED ValueError gate 1: 2 active options",
    "decode_two_options_mig": "RAISED ValueError gate 1: 2 active options",
    "bad_model_multi_aig": "RAISED RuntimeError SAT model does not reproduce the truth tables",
    "bad_model_multi_mig": "RAISED RuntimeError SAT model does not reproduce the truth tables",
    "decode_two_options_multi_aig": "RAISED ValueError gate 1: 2 active options",
    "decode_two_options_multi_mig": "RAISED ValueError gate 1: 2 active options",
    "decode_two_output_nodes_multi_aig": "RAISED ValueError output 0: 2 selected nodes",
    "decode_two_output_nodes_multi_mig": "RAISED ValueError output 0: 2 selected nodes",
    "fence_must_sum_to_k_multi_mig": "RAISED ValueError fence (1, 1) does not sum to 3",
    "npn_validate_corrupt_csv": "RAISED ValueError rep 0x0002 (dec=2) is not a fixed point",
    "witness_leg_solver_failure": "RAISED RuntimeError k=1 expected UNSAT(20), got 1",
    "amo_shared_requires_n": "RAISED TypeError build_amo_shared: n is required",
}
for _b in ("multi_aig", "multi_mig"):
    EXPECT[f"verdict_comment_is_not_a_status_line_{_b}"] = "RETURNED (True, ("
    for _case in ("verdict_status_line_missing", "verdict_two_status_lines",
                  "verdict_disagrees_with_exit_code", "verdict_sat_line_with_unsat_exit_code"):
        EXPECT[f"{_case}_{_b}"] = "RAISED RuntimeError kissat gave no verdict"

# The solver-failure probes (fake kissat with no verdict) pin the guard's message too.
SOLVER_FAILURE_EXPECT = {
    "solver_failure_xag": "RAISED RuntimeError kissat rc=",
    "solver_failure_mig": "RAISED RuntimeError kissat rc=",
    "solver_failure_multi_aig": "RAISED RuntimeError kissat gave no verdict",
    "solver_failure_multi_mig": "RAISED RuntimeError kissat gave no verdict",
}


def run_probe(name, imports, optimize, env, cwd=None, timeout=600):
    key, code = PROBES[name]
    code = code.replace("{imp}", imports[key])
    cmd = [sys.executable] + (["-O"] if optimize else []) + ["-c", code]
    p = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=cwd, timeout=timeout)
    lines = [l for l in p.stdout.splitlines() if l.startswith(("RAISED", "RETURNED"))]
    if not lines:
        return "CRASHED rc=%d %s" % (p.returncode, (p.stderr or p.stdout)[-300:].replace("\n", " | "))
    return lines[-1]


def fake_kissat_dir(base, mode):
    d = os.path.join(base, f"fakebin-{mode}")
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, "kissat")
    with open(p, "w") as fh:
        fh.write("#!/bin/sh\n" + FAKE_KISSAT[mode] + "\n")
    os.chmod(p, 0o755)
    return d
