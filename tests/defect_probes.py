"""Probes for the defects fixed in the package (see TESTING.md, "Defects fixed").

Each probe is a small Python program run in a SUBPROCESS, so that it can be run under
`python3 -O` (which strips `assert` statements). A probe prints exactly one line:

    RAISED <ExceptionType> <message>     the guard fired
    RETURNED <value>                     the call came back with a value

The packaged code must print RAISED for every probe, with and without -O.

`IMPORTS_NEW` binds the module under test to the name M.
"""
import os
import subprocess
import sys

IMPORTS_NEW = {
    "aig": "from certlab.encoders import aig as M",
    "xag": "from certlab.encoders import xag as M",
    "mig": "from certlab.encoders import mig as M",
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
