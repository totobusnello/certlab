"""Forced-multi test for n = 5 -- does the n = 4 phenomenon of forced multiple reconvergence
generalize? Given a gap=1 n=5 function, certify by SAT+DRAT whether EVERY size-optimal AIG has
>=2 gates of fan-out>=2.

Reuses the at-most-one-shared encoding of certlab.certify.zc_certify (fixed there at N=4),
generalized to arbitrary n. Chain per function:
  (1) opt(f) = OPT : circuit UNSAT k=1..OPT-1 (DRAT) + witness k=OPT (verify_circuit).
  (2) tree(f) = OPT+1 (gap=1): formula UNSAT k=OPT (DRAT) + witness k=OPT+1.
  (3) forced-multi : "exists an opt-gate AIG with <=1 fan-out>=2 gate" is UNSAT (DRAT).
UNSAT in (3) ==> single reconvergence is impossible at n=5 ==> the phenomenon generalizes.

Usage: python3 -m certlab.certify.forced_multi <tt_int> <opt> [n]
"""
import sys
import os
from itertools import combinations

from certlab.encoders.aig import AIGEncoder, verify_circuit  # noqa: E402
from certlab.certify.zc_certify import write_cnf, kissat, drat_verify, sha16, CERTS  # noqa: E402

N = 5


def build_amo_shared(tt, opt, gate_order_b=False, n=None, relax=()):
    """Base circuit encoder (k=opt) + at-most-one-shared. Sound direction: fan-out>=2 => z.

    `n` is REQUIRED (a TypeError is raised without it). It used to default to the module-level
    `N = 5`, which was a silent trap between modules: a caller that set its own `N` per witness
    (to serve an n=4 base) did not change THIS module's `N`, so a 4-variable witness would have
    been encoded as a FIVE-variable instance, labelled n4, and the leg could PASS on the wrong
    object. Overriding the global from `main` worked for direct execution and not for import --
    the worst combination, because it looked fixed.

    gate_order_b (default False): EXPERIMENTAL, opt-in, NOT proved WLOG. Adds a gate-ordering
    symmetry break on the NON-OUTPUT gates 1..k-1, keyed by the larger operand first
    (b, a, pa, pb), via adjacent-pair clauses; the output gate is exempt. Empirically it gave
    0 wrong verdicts on the 51 SAT baselines used in the research audit, which is evidence, not
    a proof. No certificate produced by this package uses it: every certification path runs
    without symmetry breaking. A verdict obtained with gate_order_b=True is not a certificate.

    An earlier gate-ordering symmetry break by the smaller operand was unsound (counterexample
    tt = 0x80008000) and has been removed."""
    if n is None:
        raise TypeError("build_amo_shared: n is required (pass n= explicitly; there is no module default)")
    nn = n
    # `relax` forwards to the encoder the switching-off of WLOG constraints, to AUDIT the
    # argument for them (see AIGEncoder.__init__). If the UNSAT survives with 'dup'/'aeqb'/'const'
    # relaxed, those three constraints were not carrying the result and need no argument -- the
    # prose link shrinks from five items to two.
    enc = AIGEncoder(nn, opt, tt, relax=relax).build()
    nvars = enc.nvars
    clauses = list(enc.clauses)
    k = opt
    if gate_order_b:
        # Order NON-OUTPUT gates by the LARGER operand b FIRST (key = (b,a,pa,pb)), not by a.
        # Rationale: a gate that becomes available only after some node j is placed uses j as
        # its larger operand b, so b tracks topological depth => ordering by non-decreasing b is
        # compatible with the topological constraint (ordering by a is not). It admits the
        # circuit that refuted the removed ordering (tt = 0x80008000: g1 = x2&x3, g2 = x1&g1).
        # Whether it is truly WLOG is NOT established -- a verdict from it is not a certificate.
        # Output gate k exempt.
        for i in range(1, k - 1):
            for (a, pa, b, pb, s) in enc.options[i]:
                ki = (b, a, pa, pb)
                for (a2, pa2, b2, pb2, s2) in enc.options[i + 1]:
                    if (b2, a2, pa2, pb2) < ki:   # key(i) > key(i+1): forbid
                        clauses.append([-s, -s2])

    def newvar():
        nonlocal nvars
        nvars += 1
        return nvars

    u = {}
    for i in range(1, k):
        node = nn + i
        users = []
        for j in range(i + 1, k + 1):
            refs = [o[4] for o in enc.options[j] if o[0] == node or o[2] == node]
            if not refs:
                continue
            uij = newvar()
            u[(i, j)] = uij
            for s in refs:
                clauses.append([-s, uij])
            users.append(j)
        zi = newvar()
        u[("z", i)] = zi
        for j1, j2 in combinations(users, 2):
            clauses.append([zi, -u[(i, j1)], -u[(i, j2)]])
    zs = [u[("z", i)] for i in range(1, k)]
    for a, b in combinations(zs, 2):
        clauses.append([-a, -b])
    return nvars, clauses


def cnf_of(enc, path):
    write_cnf(enc.nvars, enc.clauses, path)



def enc_decode_tree(encw, mw):
    """Decodes the model of the `tree` witness. It exists as a named function so that the
    symmetry with the `opt` leg (which calls enc.decode(model)) is visible when reading."""
    return encw.decode(mw)

def main():
    tt = int(sys.argv[1], 0)
    opt = int(sys.argv[2])
    if len(sys.argv) > 3:
        globals()["N"] = int(sys.argv[3])
    tag = f"{tt:#010x}"
    print(f"[{tag}] n={N}, opt hint={opt}")

    # (1) opt lower bound: UNSAT k=1..opt-1 (DRAT)
    ok_lb = True
    for kk in range(1, opt):
        enc = AIGEncoder(N, kk, tt).build()
        cnf = os.path.join(CERTS, f"n5_{tt:#010x}_opt_k{kk}.cnf")
        if any(len(cl) == 0 for cl in enc.clauses):
            print(f"  opt-LB k={kk}: UNSAT (syntactic)"); continue
        cnf_of(enc, cnf)
        drat = os.path.join(CERTS, f"n5_{tt:#010x}_opt_k{kk}.drat")
        rc, _ = kissat(cnf, drat)
        if rc == 10:
            print(f"  !!! opt-LB k={kk} SAT — opt<{opt}. ABORT.")
            # 2 = contradiction of the premise, not 1 (= the chain does not close). The solver
            # REFUTED the opt given on the command line; returning 1 here would put a refutation
            # in the same drawer as a leg that failed to verify.
            return 2
        ver = drat_verify(cnf, drat); ok_lb = ok_lb and ver
        print(f"  opt-LB k={kk}: UNSAT drat-trim={'VERIFIED' if ver else 'FAIL'}")

    # (1b) opt witness k=opt
    enc = AIGEncoder(N, opt, tt).build()
    cnf = os.path.join(CERTS, f"n5_{tt:#010x}_opt_k{opt}.cnf"); cnf_of(enc, cnf)
    rc, model = kissat(cnf)
    if rc != 10:
        print(f"  !!! k={opt} not SAT — opt>{opt}. ABORT.")
        return 2  # likewise: no circuit with k=opt exists, so opt>opt. A contradiction, not a chain failure.
    gates, op = enc.decode(model)
    vc = verify_circuit(N, tt, gates, op)
    print(f"  opt-UB k={opt}: SAT verify_circuit={vc}")
    if not vc:
        # The simulation check exists precisely so that a False here cannot slide by as printed
        # text (verify_circuit results used to be reported, never acted upon).
        print(f"  !!! witness does not compute tt — k={opt} leg NOT established. ABORT.")
        return 1

    # (2) tree: formula UNSAT k=opt (=> tree>=opt+1) + witness k=opt+1
    enc = AIGEncoder(N, opt, tt, formula=True).build()
    cnf = os.path.join(CERTS, f"n5_{tt:#010x}_tree_k{opt}.cnf"); cnf_of(enc, cnf)
    drat = os.path.join(CERTS, f"n5_{tt:#010x}_tree_k{opt}.drat")
    rc, _ = kissat(cnf, drat)
    tree_ok = False
    if rc == 20:
        ver = drat_verify(cnf, drat)
        encw = AIGEncoder(N, opt + 1, tt, formula=True).build()
        cnfw = os.path.join(CERTS, f"n5_{tt:#010x}_tree_k{opt+1}.cnf"); cnf_of(encw, cnfw)
        rcw, mw = kissat(cnfw)
        # The `tree` leg used to accept ONLY the SAT exit code (`rcw == 10`), without decoding the
        # model, without re-simulating the table and without counting fan-out -- asymmetric with
        # the `opt` witness just above, which does all three. `tree` is a PUBLISHED number, and
        # the re-simulation exists precisely to catch encoder bugs: trusting the formula encoding
        # is trusting the very thing under verification.
        vcw = False; shared = []
        if rcw == 10:
            gw, ow = enc_decode_tree(encw, mw)
            vcw = verify_circuit(N, tt, gw, ow)
            # gate i (1-based) has id N+i; inputs are 1..N.
            # The loop below increments on BOTH operands, so it counts EDGES, not distinct
            # consumers. That is harmless, but not because of an optimality argument: the encoder
            # enumerates the pair with combinations(nodes, 2), so a < b BY CONSTRUCTION and no
            # encodable circuit reads the same wire on both ends. Both readings always give the
            # same number here.
            fanout = {}
            for (a, _pa, b, _pb) in gw:
                for operand in (a, b):
                    if operand > N:
                        fanout[operand] = fanout.get(operand, 0) + 1
            shared = sorted(g for g, c in fanout.items() if c > 1)
        tree_ok = ver and rcw == 10 and vcw and not shared
        print(f"  tree: formula UNSAT k={opt} (drat-trim={'VERIFIED' if ver else 'FAIL'}) + "
              f"formula SAT k={opt+1} ({rcw==10}, verify_circuit={vcw}, "
              f"fanout>1 gates={len(shared)} (must be 0)) => tree={opt+1}, gap=1: {tree_ok}")
    else:
        print(f"  tree: formula k={opt} rc={rc} (SAT => tree<=opt => gap<=0, not gap=1)")

    # (3) forced-multi: at-most-one-shared UNSAT at k=opt
    nvars, clauses = build_amo_shared(tt, opt, n=N)
    cnf = os.path.join(CERTS, f"n5_{tt:#010x}_amo1shared.cnf")
    write_cnf(nvars, clauses, cnf)
    drat = os.path.join(CERTS, f"n5_{tt:#010x}_amo1shared.drat")
    rc, _ = kissat(cnf, drat)
    if rc == 10:
        print(f"  forced-multi: at-most-1-shared SAT => a single-reconvergence optimum EXISTS "
              f"(NOT forced-multi; conforming like most n=4 gap=1).")
        print(f"\n  VERDICT [{tag}]: gap=1 but NOT Z-like (single reconvergence possible).")
        return 0
    if rc != 20:
        print(f"  forced-multi: kissat rc={rc} (neither SAT nor UNSAT — timeout/error). INCONCLUSIVE.")
        return 1
    ver = drat_verify(cnf, drat)
    print(f"  forced-multi: at-most-1-shared UNSAT (drat-trim={'VERIFIED' if ver else 'FAIL'}) "
          f"cnf_sha={sha16(cnf)} drat_sha={sha16(drat)}")

    # The three legs are CHECKED, not merely interpolated into the verdict. Before this guard the
    # headline VERDICT printed and main() returned 0 even with ok_lb, tree_ok or ver False, so a
    # caller doing `forced_multi ... && echo certified` saw success on a broken chain. The same
    # lesson had already been learned for verify_circuit above and had not been swept to its
    # three siblings; an adversarial review found the survivors.
    legs = {"opt-LB DRAT": ok_lb, "tree gap=1": tree_ok, "forced-multi DRAT": ver}
    broken = [k for k, v in legs.items() if not v]
    if broken:
        print(f"\n  !!! VERDICT WITHHELD [{tag}]: at-most-1-shared is UNSAT, but the certification "
              f"chain does not close — failed leg(s): {', '.join(broken)}. "
              f"forced-multi is NOT established for this function.")
        return 1

    print(f"\n  *** VERDICT [{tag}]: FORCED MULTIPLE RECONVERGENCE at n={N} — Z-like. "
          f"The n = 4 phenomenon GENERALIZES (opt LB DRAT={ok_lb}, tree gap=1={tree_ok}, "
          f"forced-multi DRAT={ver}). ***")
    return 0


if __name__ == "__main__":
    sys.exit(main())
