"""Regenerate and machine-recheck the headline result FROM SCRATCH: the seventh, non-lift
forced-reconvergence class at n=5, witness f = 0x03de & (~x0 | x4) = 0x03de0154 (and the other
witnesses in WITNESSES).

Naming: the family is called the `forced-reconvergence family` / `F_n`.

Machine-independent (no hardcoded paths, no python-version assumption).
Prerequisites on PATH: python3, kissat, drat-trim.

    python3 -m certlab.witness           # quick: opt-LB + witnesses + non-canalizing (~seconds)
    python3 -m certlab.witness --full     # also the forced-multi no-SB certificate (247 MB, ~minutes)
    python3 -m certlab.witness 0x09c50800 --tree-chain

Generated CNF/DRAT files go to $CERTLAB_OUT (default ./certlab_generated).

What each leg establishes for f (n=5):
  opt = 8      : circuit UNSAT at k=1..7 (DRAT, drat-trim VERIFIED) + a k=8 SAT model that
                 verify_circuit confirms computes f. => opt(f) = 8.
  tree <= 9    : a fan-out-1 formula of 9 gates computes f (SAT model, verify_circuit).  [self-certifying]
  forced-multi : "some optimum has <=1 reconvergent gate" is UNSAT at k=8 with ZERO symmetry
                 breaking (the vetted encoder) -> every 8-gate optimum has >=2 reconvergences.
                 With tree>=opt+1 forced by this, tree = 9, so gap = tree - opt = 1.
  non-canalizing : no variable has a constant cofactor => f is not an AND/OR-lift.
Portability note: a CNF's SHA is deterministic from the encoder (machine-independent, pinned here);
a DRAT's bytes depend on the solver build, so the portable check is "drat-trim VERIFIED", not a DRAT SHA.
"""
import os, sys, argparse

HERE = os.path.dirname(os.path.abspath(__file__))
from certlab.encoders.aig import AIGEncoder, verify_circuit             # noqa: E402
from certlab.certify.forced_multi import build_amo_shared                  # noqa: E402
from certlab.certify.zc_certify import write_cnf, kissat, drat_verify, sha16 # noqa: E402

# Witnesses this module can regenerate. `forced_cnf_sha16` pins the forced-multi CNF hash, which is
# encoder-deterministic and therefore machine-independent (DRAT bytes are not -- they depend on the
# solver build, so the portable acceptance test is "drat-trim VERIFIED").
#
# WHY ONE TABLE SERVES EVERY WITNESS. An earlier public copy of this script had a more general CLI
# and its documentation listed five commands -- the three directed-sweep witnesses, the n=4 base, and
# the census witness -- while the working copy, tightened to pin SHAs per witness, had dropped to two
# entries and stopped accepting the other three. The two copies drifted apart in BOTH capability and
# rigour, and the drifted one was the copy that strangers execute. One table that serves every
# documented command is the fix.
#
# Every n=5 witness here carries a no-SB `forced_cnf_sha16`. Two of them once did not, and a comment
# explained why: they had been certified through the `gate_order_b` ordering, so no no-SB CNF
# existed to pin. That was honest then and became false the moment the no-SB certificates landed --
# the manifest pinned the two new hashes and named this script as their regenerator while the table
# still said the hashes did not exist and the code forced `match = True` without comparing. Three
# independent reviews found it in the same hour.
#
# So: `forced_cnf_sha16: None` is not a state any n=5 witness is allowed to be in. If a witness ever
# legitimately lacks a pin, the `None` branch below still handles it and says so out loud -- but
# check data/manifest.csv first, because a manifest row that names this script and a `None` here
# cannot both be right.
WITNESSES = {
    0x03DE0154: {"n": 5, "opt": 8, "forced_cnf_sha16": "ed3b8350f72f8078",
                 "desc": "0x03de & (~x0 | x4) — 7th class, found by directed sweep"},
    0xABFE03DE: {"n": 5, "opt": 8, "forced_cnf_sha16": "39d9bd8db8daeb8b",
                 "desc": "0x03de | (x0 & x4) — 8th class, directed sweep (forced-multi certified with NO symmetry breaking, 2026-08-12)"},
    0x57DF03DE: {"n": 5, "opt": 8, "forced_cnf_sha16": "378fa46181ed496b",
                 "desc": "0x03de | (~x0 & x4) — 9th class, directed sweep (forced-multi certified with NO symmetry breaking, 2026-08-12)"},
    0x03DE:     {"n": 4, "opt": 6, "forced_cnf_sha16": None,
                 "desc": "the n=4 base of the Lift Theorem — flagship class 0x03de"},
    0x09C50800: {"n": 5, "opt": 8, "forced_cnf_sha16": "8949334bf9baa8ca",
                 "desc": "10th class — found by random census, not by construction"},
}
DEFAULT_TT = 0x03DE0154
# A regenerator must never write into the directory it is supposed to reproduce: it destroys the
# reference it is being checked against. Output goes to its own directory, outside the data.
OUT = os.environ.get("CERTLAB_OUT", os.path.join(os.getcwd(), "certlab_generated"))
os.makedirs(OUT, exist_ok=True)

# Set by main() from argv; module-level so the leg_* helpers keep their shape. `N` joins them
# because the n=4 base is one of the witnesses.
TT = DEFAULT_TT
N = WITNESSES[DEFAULT_TT]["n"]
OPT = WITNESSES[DEFAULT_TT]["opt"]
EXPECT_FORCED_CNF_SHA16 = WITNESSES[DEFAULT_TT]["forced_cnf_sha16"]


def is_canalizing(tt, n=None):
    """`n=None` and not `n=N`: a parameter default is evaluated ONCE, when the function is
    defined, so `n=N` froze the 5 of that moment and ignored the `N` that main sets per witness.
    Observed on the first run of the n=4 base: `0x03de` was judged as a 5-variable function,
    where x4 has a constant cofactor, and the script reported `canalizing=True` against the
    census value -- a RED leg from late binding, not from mathematics."""
    n = N if n is None else n
    for i in range(n):
        for val in (0, 1):
            bits = [(tt >> a) & 1 for a in range(1 << n) if ((a >> i) & 1) == val]
            if all(b == 0 for b in bits) or all(b == 1 for b in bits):
                return True
    return False


def leg_optlb():
    print(f"\n[opt-LB] circuit UNSAT for k=1..{OPT-1} (=> opt >= {OPT})")
    allok = True
    for k in range(1, OPT):
        enc = AIGEncoder(N, k, TT).build()
        if any(len(cl) == 0 for cl in enc.clauses):
            print(f"  k={k}: UNSAT (syntactic)"); continue
        cnf = os.path.join(OUT, f"n5_{TT:#010x}_opt_k{k}.cnf"); write_cnf(enc.nvars, enc.clauses, cnf)
        drat = os.path.join(OUT, f"n5_{TT:#010x}_opt_k{k}.drat")
        rc, _ = kissat(cnf, drat)
        if rc != 20:
            raise RuntimeError(f"k={k} expected UNSAT(20), got {rc}")
        ok = drat_verify(cnf, drat); allok = allok and ok
        print(f"  k={k}: UNSAT  cnf={sha16(cnf)}  drat-trim={'VERIFIED' if ok else 'FAIL'}")
    return allok


def leg_optwitness():
    enc = AIGEncoder(N, OPT, TT).build()
    cnf = os.path.join(OUT, f"n5_{TT:#010x}_opt_k{OPT}.cnf"); write_cnf(enc.nvars, enc.clauses, cnf)
    rc, model = kissat(cnf)
    if rc != 10:
        raise RuntimeError(f"k={OPT} expected SAT(10), got {rc}")
    gates, op = enc.decode(model); ok = verify_circuit(N, TT, gates, op)
    print(f"\n[opt witness] k={OPT} SAT, verify_circuit={ok}  => opt = {OPT}")
    return ok


def leg_tree():
    enc = AIGEncoder(N, OPT + 1, TT, formula=True).build()
    cnf = os.path.join(OUT, f"n5_{TT:#010x}_tree_k{OPT+1}.cnf"); write_cnf(enc.nvars, enc.clauses, cnf)
    rc, model = kissat(cnf)
    if rc != 10:
        raise RuntimeError(f"formula k={OPT+1} expected SAT(10), got {rc}")
    gates, op = enc.decode(model); ok = verify_circuit(N, TT, gates, op)

    # FAN-OUT COUNTED PER GATE, not trusted to the encoder's `formula=True`. The documentation
    # stated "per-gate fan-out is counted" and the manifest repeated it, but this leg used to call
    # only `verify_circuit`, which compares the truth table and says nothing about structure. A
    # regression in `formula` mode would have passed as a "self-certifying tree" with nothing
    # checking the property that gives the leg its name. Now the check exists: in a formula, every
    # internal node is consumed at most once, counting the output as a consumer.
    consumers = {}
    for gi, (a, _pa, b, _pb) in enumerate(gates, start=1):
        for operand in (a, b):
            if operand > N:                       # > N = internal node (inputs may have free fan-out)
                consumers[operand] = consumers.get(operand, 0) + 1
    # The OUTPUT is node `N + len(gates)` -- the last gate, by construction of the encoder (see
    # `simulate()`, which reads `vals[n + len(gates)]`). The second value of `decode()` is the
    # output POLARITY, a bool, not a node: a first version did `abs(op)` and compared it with N,
    # which in Python computes `abs(True) = 1` -- because `bool` is a subclass of `int` -- and so
    # never counted anything, while the comment claimed "counting the output as a consumer". In
    # practice the verdict does not change (the last gate cannot be anyone's operand, so it has 0
    # internal consumers), but a comment that describes what the code does NOT do is the same
    # failure as a leg that claims more than it executes.
    out_node = N + len(gates)
    consumers[out_node] = consumers.get(out_node, 0) + 1
    max_fanout = max(consumers.values()) if consumers else 0
    shared = {k: v for k, v in consumers.items() if v > 1}
    fanout_ok = not shared
    print(f"\n[tree] fan-out-1 formula k={OPT+1} SAT, verify_circuit={ok}, "
          f"max internal fan-out={max_fanout} (counted per gate, {len(consumers)} internal nodes)")
    if shared:
        print(f"  !!! nodes with fan-out>1: {shared} — NOT a fan-out-1 formula; the leg FAILS")
    print(f"  => tree <= {OPT+1} (self-certifying: truth table + fan-out-1 structure)")
    return ok and fanout_ok


def leg_tree_chain():
    """The LOWER-BOUND chain of tree: formula UNSAT at k=1..opt, one leg per k, with DRAT.

    This leg exists because data/manifest.csv pins a CNF hash for it, and a manifest row must name
    a command a reader can actually run, not a private script or a description.

    Compares the SHA of each k against the per-witness reference CSV in data/witness/ when it is
    present; when it is not, it still prints the SHAs for manual comparison, and says which case
    applies -- instead of keeping quiet.
    """
    import csv as _csv
    # The reference CSV is looked up in data/witness/ and, optionally, at $TREE_CHAIN_CSV.
    ref = {}
    # PER WITNESS. A first version looked only for `tree_chain_n5.csv`, which is the FLAGSHIP's CSV
    # -- for the other three the `tt_hex` filter matched nothing, `ref` stayed empty and the
    # per-leg comparison passed without comparing. Specific name first, legacy name second,
    # because the flagship is the only one that uses the unsuffixed name.
    cands = [os.path.join(HERE, "..", "..", "data", "witness", f"tree_chain_n5_{TT:#010x}.csv"),
             os.path.join(HERE, "..", "..", "data", "witness", "tree_chain_n5.csv")]
    if os.environ.get("TREE_CHAIN_CSV"):
        cands.append(os.environ["TREE_CHAIN_CSV"])
    ref_from = None
    for cand in cands:
        if not os.path.exists(cand):
            continue
        for r in _csv.DictReader(open(cand)):
            if r.get("mode") == "formula" and r.get("tt_hex", "").lower() == f"{TT:#010x}":
                ref[int(r["k"])] = r["cnf_sha16"]
        # `break` only when the file REALLY carried legs of this witness. A first version stopped at
        # the first file that EXISTED, so the flagship's CSV absorbed the lookup of the other three:
        # `ref` empty, and a message announcing a comparison that did not happen. Silence that looks
        # like a check is the worst outcome.
        if ref:
            ref_from = os.path.basename(cand)
            break
        ref = {}
    print(f"\n[tree chain] formula-mode UNSAT k=1..{OPT}  "
          f"({'comparing against ' + ref_from if ref_from else 'no reference CSV for this witness: SHAs printed for manual comparison'})")
    allok = True
    for k in range(1, OPT + 1):
        enc = AIGEncoder(N, k, TT, formula=True).build()
        if any(len(cl) == 0 for cl in enc.clauses):
            print(f"  k={k}: UNSAT (syntactic)")
            continue
        cnf = os.path.join(OUT, f"n{N}_{TT:#010x}_tree_k{k}.cnf")
        write_cnf(enc.nvars, enc.clauses, cnf)
        got = sha16(cnf)
        drat = os.path.join(OUT, f"n{N}_{TT:#010x}_tree_k{k}.drat")
        rc, _ = kissat(cnf, drat)
        if rc != 20:
            raise RuntimeError(f"formula k={k} expected UNSAT(20), got {rc}")
        dok = drat_verify(cnf, drat)
        if k in ref:
            m = (got == ref[k])
            allok = allok and dok and m
            print(f"  k={k}: UNSAT  cnf={got} ({'MATCH' if m else 'MISMATCH vs ' + ref[k]})  "
                  f"drat-trim={'VERIFIED' if dok else 'FAIL'}")
        else:
            allok = allok and dok
            print(f"  k={k}: UNSAT  cnf={got}  drat-trim={'VERIFIED' if dok else 'FAIL'}")
    return allok


def leg_canalizing():
    c = is_canalizing(TT)
    print(f"\n[non-canalizing] canalizing={c}  => {'NOT a lift (independent class)' if not c else 'IS a lift'}")
    return not c


def leg_forced():
    print(f"\n[forced-multi] amo-shared UNSAT at k={OPT}, ZERO symmetry break (247 MB DRAT, ~minutes)")
    # `n=N` EXPLICIT: build_amo_shared requires it, so the n=4 base cannot be certified as a
    # five-variable instance with its files labelled n4.
    nv, cl = build_amo_shared(TT, OPT, gate_order_b=False, n=N)
    cnf = os.path.join(OUT, f"n{N}_{TT:#010x}_amo1shared_nosb.cnf"); write_cnf(nv, cl, cnf)
    csha = sha16(cnf)
    if EXPECT_FORCED_CNF_SHA16 is None:
        # No pin: the verdict is still checked, byte-identity cannot be. Saying so out loud is the
        # point -- an "OK" that silently skips the comparison is worse than a missing comparison.
        match = True
        print(f"  cnf sha16={csha}  (no no-SB pin for this witness — see WITNESSES; the verdict is still verified)")
    else:
        match = (csha == EXPECT_FORCED_CNF_SHA16)
        print(f"  cnf sha16={csha}  (expected {EXPECT_FORCED_CNF_SHA16}: {'MATCH' if match else 'MISMATCH!'})")
    drat = os.path.join(OUT, f"n{N}_{TT:#010x}_amo1shared_nosb.drat")
    rc, _ = kissat(cnf, drat)
    if rc != 20:
        raise RuntimeError(f"forced-multi expected UNSAT(20), got {rc}")
    ok = drat_verify(cnf, drat)
    print(f"  UNSAT  drat-trim={'VERIFIED' if ok else 'FAIL'}  => every optimum has >=2 reconvergences")
    return ok and match


def main():
    global TT, N, OPT, EXPECT_FORCED_CNF_SHA16
    ap = argparse.ArgumentParser(description="Regenerate and machine-recheck a forced-reconvergence witness chain.")
    ap.add_argument("tt", nargs="?", default=f"{DEFAULT_TT:#010x}",
                    help="truth table in hex (default: the 7th-class witness 0x03de0154)")
    ap.add_argument("--full", action="store_true", help="also regenerate the forced-multi no-SB certificate")
    ap.add_argument("--tree-chain", action="store_true",
                    help="also regenerate the tree lower-bound chain (formula UNSAT k=1..opt, per-leg SHAs)")
    args = ap.parse_args()
    tt = int(args.tt, 16)
    if tt not in WITNESSES:
        known = ", ".join(f"{k:#010x}" for k in WITNESSES)
        sys.exit(f"unknown witness {tt:#010x} — this script pins CNF SHAs, so it only serves: {known}")
    TT, N, OPT = tt, WITNESSES[tt]["n"], WITNESSES[tt]["opt"]
    EXPECT_FORCED_CNF_SHA16 = WITNESSES[tt]["forced_cnf_sha16"]
    print(f"=== reproduce witness {TT:#010x} — {WITNESSES[tt]['desc']}  (n={N}, opt={OPT}) ===")
    res = {
        "opt-LB (k=1..7 UNSAT)": leg_optlb(),
        f"opt witness (k={OPT} SAT)": leg_optwitness(),
        f"tree<= {OPT+1} (formula witness)": leg_tree(),
        "non-canalizing": leg_canalizing(),
    }
    if args.tree_chain:
        res[f"tree chain (formula UNSAT k=1..{OPT})"] = leg_tree_chain()
    if args.full:
        res["forced-multi (no-SB UNSAT)"] = leg_forced()
    print("\n=== SUMMARY ===")
    for k, v in res.items():
        print(f"  [{'PASS' if v else 'FAIL'}] {k}")
    sys.exit(0 if all(res.values()) else 1)


if __name__ == "__main__":
    main()
