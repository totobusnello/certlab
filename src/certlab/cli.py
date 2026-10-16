"""Command-line interface: `certlab <subcommand> ...`.

Every subcommand has a stable, documented exit code, in the mould of scripts/check_drat.sh:

  synth       smallest k found by ascending SAT search, witness checked by the independent
              simulator.  0 found, 1 none up to --kmax, 3 kissat missing, 4 solver failure.
              The lower bound of an ascending search is solver-asserted, NOT certified: use
              `certlab witness` (or the certify modules) for DRAT-certified UNSAT legs.
  cnf         write the CNF of one (basis, n, tt, k) cell and print its sha256.  0 ok.
  check-drat  drat-trim verdict.  0 VERIFIED, 1 NOT VERIFIED (the proof is wrong), 2 usage or
              missing file/tool, 3 drat-trim time limit (neither verified nor refuted),
              4 checker failed (killed, out of memory, no status line; neither verified nor refuted).
  simulate    check a circuit (JSON) against a truth table with the independent simulator.
              0 match, 1 mismatch, 2 bad input.
  npn         canonical NPN representative (n = 4) and the census opt_AIG of its class.  0 ok.
  witness     regenerate a forced-reconvergence witness chain (see certlab.witness).

Truth tables are given in hex; bit t = f(row t), input x_j = bit j-1 of t.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

from certlab import simulate as _sim

DRAT_RC = {"VERIFIED": 0, "NOT_VERIFIED": 1, "TIMEOUT": 3}


def _encoder(basis, n, k, tt, formula):
    if basis == "aig":
        from certlab.encoders.aig import AIGEncoder
        return AIGEncoder(n, k, tt, formula=formula).build()
    if basis == "xag":
        from certlab.encoders.xag import XAGEncoder
        return XAGEncoder(n, k, tt, formula=formula).build()
    if basis == "mig":
        from certlab.encoders.mig import MIGEncoder
        return MIGEncoder(n, k, tt, formula=formula).build()
    raise ValueError(basis)


def _dimacs(enc):
    lines = [f"p cnf {enc.nvars} {len(enc.clauses)}\n"]
    lines += [" ".join(map(str, cl)) + " 0\n" for cl in enc.clauses]
    return "".join(lines)


def _trivial(n, tt):
    m = (1 << (1 << n)) - 1
    cands = {0, m}
    for j in range(1, n + 1):
        v = _sim.input_tt(n, j)
        cands |= {v, v ^ m}
    return tt in cands


def cmd_synth(a):
    tt = int(a.tt, 16)
    if tt >> (1 << a.n):
        print(f"truth table {a.tt} has more than 2^{a.n} bits", file=sys.stderr)
        return 2
    if _trivial(a.n, tt):
        print(json.dumps({"basis": a.basis, "n": a.n, "tt": a.tt, "k": 0, "note": "constant or literal"}))
        return 0
    if shutil.which("kissat") is None:
        print("certlab synth: kissat is not on PATH -- nothing was run, so there is no verdict", file=sys.stderr)
        return 3
    for k in range(1, a.kmax + 1):
        enc = _encoder(a.basis, a.n, k, tt, a.formula)
        if any(len(cl) == 0 for cl in enc.clauses):
            continue
        with tempfile.NamedTemporaryFile("w", suffix=".cnf", delete=False) as fh:
            fh.write(_dimacs(enc))
            path = fh.name
        try:
            r = subprocess.run(["kissat", "-q", path], capture_output=True, text=True, timeout=a.timeout)
        finally:
            os.unlink(path)
        if r.returncode == 20:
            continue
        if r.returncode != 10:
            print(f"certlab synth: kissat rc={r.returncode} at k={k} (neither SAT nor UNSAT)", file=sys.stderr)
            return 4
        model = [int(x) for line in r.stdout.splitlines() if line.startswith("v ")
                 for x in line[2:].split() if x != "0"]
        gates, out_pol = enc.decode(model)
        if not _sim.check(a.basis, a.n, tt, gates, out_pol):
            print(f"certlab synth: the SAT model at k={k} does not compute tt (encoder defect)", file=sys.stderr)
            return 4
        print(json.dumps({"basis": a.basis, "n": a.n, "tt": a.tt, "k": k, "formula": a.formula,
                          "gates": [list(g) for g in gates], "out_pol": bool(out_pol),
                          "lower_bound": "solver-asserted (k-1 UNSAT by kissat), not DRAT-certified"}))
        return 0
    print(f"certlab synth: no circuit with k <= {a.kmax}", file=sys.stderr)
    return 1


def cmd_cnf(a):
    tt = int(a.tt, 16)
    enc = _encoder(a.basis, a.n, a.k, tt, a.formula)
    data = _dimacs(enc).encode()
    with open(a.output, "wb") as fh:
        fh.write(data)
    h = hashlib.sha256(data).hexdigest()
    print(f"{h}  {a.output}  (sha16 {h[:16]}, {enc.nvars} vars, {len(enc.clauses)} clauses)")
    return 0


def cmd_check_drat(a):
    for f in (a.cnf, a.drat):
        if not os.path.isfile(f):
            print(f"check-drat: file not found: {f}", file=sys.stderr)
            return 2
    if shutil.which("drat-trim") is None:
        print("check-drat: drat-trim is not on PATH", file=sys.stderr)
        return 2
    from certlab.certify.zc_certify import drat_verify_detailed
    d = drat_verify_detailed(a.cnf, a.drat)
    rc = DRAT_RC.get(d["verdict"], 4)
    print(f"{d['verdict']}  {os.path.basename(a.drat)}  (status={d['status']!r}, drat-trim rc={d['rc']})")
    return rc


def cmd_simulate(a):
    try:
        with open(a.circuit) as fh:
            c = json.load(fh)
        tt = int(a.tt, 16)
        gates = [tuple(g) for g in c["gates"]]
        ok = _sim.check(a.basis, a.n, tt, gates, bool(c["out_pol"]))
    except (OSError, ValueError, KeyError, TypeError, IndexError) as e:
        print(f"simulate: bad input: {e}", file=sys.stderr)
        return 2
    print("MATCH" if ok else "MISMATCH")
    return 0 if ok else 1


def cmd_npn(a):
    from certlab import npn
    census, _ = npn.load_census()
    opt, rep = npn.opt_lookup(census, int(a.tt, 16))
    print(json.dumps({"tt": a.tt, "npn_rep": f"{rep:#06x}", "opt_aig": opt}))
    return 0


def cmd_witness(a):
    from certlab import witness
    sys.argv = ["certlab witness"] + a.rest
    try:
        witness.main()
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="certlab", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p, k=False):
        p.add_argument("--basis", choices=("aig", "xag", "mig"), required=True)
        p.add_argument("--n", type=int, required=True)
        p.add_argument("--tt", required=True, help="truth table in hex")
        p.add_argument("--formula", action="store_true", help="fan-out-1 formula (tree) mode")
        if k:
            p.add_argument("--k", type=int, required=True)

    p = sub.add_parser("synth"); common(p)
    p.add_argument("--kmax", type=int, default=12)
    p.add_argument("--timeout", type=float, default=None)
    p.set_defaults(fn=cmd_synth)
    p = sub.add_parser("cnf"); common(p, k=True)
    p.add_argument("-o", "--output", required=True)
    p.set_defaults(fn=cmd_cnf)
    p = sub.add_parser("check-drat")
    p.add_argument("cnf"); p.add_argument("drat")
    p.set_defaults(fn=cmd_check_drat)
    p = sub.add_parser("simulate")
    p.add_argument("--basis", choices=("aig", "xag", "mig"), required=True)
    p.add_argument("--n", type=int, required=True)
    p.add_argument("--tt", required=True)
    p.add_argument("--circuit", required=True, help="JSON with 'gates' and 'out_pol' (as printed by synth)")
    p.set_defaults(fn=cmd_simulate)
    p = sub.add_parser("npn")
    p.add_argument("tt")
    p.set_defaults(fn=cmd_npn)
    p = sub.add_parser("witness")
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p.set_defaults(fn=cmd_witness)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
