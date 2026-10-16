"""Per-function DRAT certification of the n = 4 forced-reconvergence ("zero-conforming") family.

For each "zero-conforming" function f (gap = 1, n = 4), certifies via SAT+DRAT that EVERY
size-optimal AIG has >=2 gates with fan-out>=2 (forced DOUBLE reconvergence) -- without relying
on the completeness of an enumerator. Per-function chain:

  (1) opt(f) >= OPT   : circuit UNSAT for k=1..OPT-1 (DRAT, drat-trim s VERIFIED).
  (2) opt(f) <= OPT   : witness (circuit SAT at k=OPT, verify_circuit).
  (3) >=2 shared      : "there exists an AIG of OPT gates with <=1 gate of fan-out>=2" is
                        UNSAT (DRAT). At-most-one-shared encoding:
                          u[i,j]  : gate j (j>i) selects an option that references gate i
                                    (clause  -s_o OR u[i,j]  for every option o of j that uses n+i)
                          z[i]    : gate i has fan-out>=2
                                    (clause  z[i] OR -u[i,j] OR -u[i,j']  for all j<j' users of i)
                          amo(z)  : -z[i] OR -z[i']   (at most one shared)
                        UNSAT => no optimum has <=1 shared => all have >=2.

Soundness: the base encoder's dedup/all-used are WLOG at k=OPT (an optimal circuit has no
duplicate or useless gate -- that would shrink the size). The direction "fan-out>=2 => z" is the
only one needed for the UNSAT to be sound (a spurious z only tightens the amo; the solver zeroes
it out).
The witness (2) is verified by simulation; DRAT certifies the CNF.
Remaining confidence gaps: encoder -> CNF (checked against an independent enumeration) and
drat-trim itself.

This module also holds the shared helpers of the certification chain: `write_cnf`, `kissat`,
`drat_verify` / `drat_verify_detailed` (the Python reading of drat-trim's verdict, which must
agree with scripts/check_drat.sh; tests/test_drat_verdict.py runs both on the same outputs) and
`sha16`.

Output location: certificates are written under $CERTLAB_CERTS (default ./certlab_certs).
"""
import sys
import os
import shutil
import io
import time
import subprocess
import hashlib
import json
from itertools import combinations

# drat-trim has an INTERNAL ceiling of 40000 s (`#define TIMEOUT 40000`, flag `-t`) and prints
# `s TIMEOUT` when it hits it (rc=0). Without `-t`, every "s TIMEOUT" was that ceiling, not a
# property of the proof. The ceiling is explicit: env DRAT_TIMEOUT_S (default 7 days).
DRAT_T = int(os.environ.get("DRAT_TIMEOUT_S", str(7 * 24 * 3600)))

HERE = os.path.dirname(os.path.abspath(__file__))
from certlab.encoders.aig import AIGEncoder, verify_circuit, trivial_opt  # noqa: E402

N = 4
CERTS = os.environ.get("CERTLAB_CERTS", os.path.join(os.getcwd(), "certlab_certs"))
os.makedirs(CERTS, exist_ok=True)

# (tt, opt) of the 6 zero-conforming functions (opt from the n = 4 census)
ZC = [(0x0358, 7), (0x0359, 7), (0x03de, 6), (0x06b5, 8), (0x07bc, 7), (0x178e, 8)]


def sha16(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()[:16]


def write_cnf(nvars, clauses, path):
    with open(path, "w") as f:
        f.write(f"p cnf {nvars} {len(clauses)}\n")
        for cl in clauses:
            f.write(" ".join(map(str, cl)) + " 0\n")


class SolverMissing(RuntimeError):
    """The required binary is not installed. It is an EXCEPTION, not a return value, on purpose.

    `kissat()` returns an rc and `drat_verify()` returns a bool, and both types already carry a
    substantive meaning: rc=20 is UNSAT, `False` is "drat-trim said NOT VERIFIED". Degrading a
    missing tool into one of those values publishes an absence of infrastructure as a
    mathematical verdict -- that is how a carriage-return bug in a status grep once nearly led to
    the conclusion that 16 certificate legs were broken, when what was broken was the grep.
    Callers treat this as exit 3 (refused to act), never 1 (the chain does not close) nor 2
    (contradiction)."""


def _install_excepthook():
    """Turns an UNCAUGHT SolverMissing into a clean message + exit 3, for ANY consumer.

    It exists because many scripts import this module and only a few have their own try/except.
    It chains to the previous hook: any other exception still prints a normal traceback.
    """
    previous = sys.excepthook

    def _hook(exc_type, exc_value, tb):
        if issubclass(exc_type, SolverMissing):
            print(f"  REFUSED: {exc_value}", flush=True)
            raise SystemExit(3)
        previous(exc_type, exc_value, tb)

    sys.excepthook = _hook


_install_excepthook()


def _require(bin_):
    if shutil.which(bin_) is None:
        raise SolverMissing(f"{bin_} is not installed -- nothing was run, so there is no verdict")


def kissat(cnf, drat=None):
    _require("kissat")
    args = ["kissat", "-q", cnf] + ([drat] if drat else [])
    p = subprocess.run(args, capture_output=True, text=True)
    model = []
    if p.returncode == 10:
        for line in p.stdout.splitlines():
            if line.startswith("v "):
                model += [int(x) for x in line[2:].split() if x != "0"]
    return p.returncode, model


def drat_verify_detailed(cnf, drat):
    """Verifies and returns the DISCRIMINATED outcome, not a bool. See scripts/check_drat.sh.

    The `s ` prefix is load-bearing and must stay: `"VERIFIED" in stdout` -- an ad-hoc check used
    elsewhere before a review reproduced the failure -- is also true of `s NOT VERIFIED`, so it
    passes a FAILED proof.

    WHY A BOOL IS NOT ENOUGH. Four incompatible outcomes used to collapse into one `False`, and
    the caller recorded the word NOT_VERIFIED, which asserts something about the PROOF:

      s VERIFIED    + rc == 0  -> the proof is correct
      s NOT VERIFIED           -> the proof is WRONG  (the only case that is NOT_VERIFIED)
      s VERIFIED    + rc != 0  -> verified and then died; does not count as evidence
      no `s ` line / signal    -> the checker was KILLED midway; it neither verified NOR refuted

    In one recorded run, four opt=9 classes came out NOT_VERIFIED through the last case: the
    re-certification ran in a process pool and the container's memory ceiling (about 60 GB,
    while `free` showed the host's 124 GB) was hit with ~6 GB of RSS per drat-trim; the cgroup
    logged OOM kills. Re-verified one at a time, on bytes whose sha was IDENTICAL to the
    recorded one, they gave `s VERIFIED` rc=0. The defect was the run's, never the chain's --
    and the bool had thrown the distinction away.
    """
    _require("drat-trim")
    t0 = time.time()
    v = subprocess.run(["drat-trim", cnf, drat, "-t", str(DRAT_T)], capture_output=True, text=True)
    lines = (v.stdout or "").replace("\r", "\n").split("\n")
    status = next((l.strip() for l in reversed(lines) if l.strip().startswith("s ")), "")
    ok = status == "s VERIFIED" and v.returncode == 0
    rc = v.returncode
    if ok:
        verdict = "VERIFIED"
    elif status == "s NOT VERIFIED":
        verdict = "NOT_VERIFIED"
    elif status == "s TIMEOUT" or "time limit exceeded" in (v.stdout or "").lower():
        verdict = "TIMEOUT"
    elif rc < 0:                      # subprocess returns -N when the process dies by signal N
        verdict = f"CHECKER_KILLED_signal{-rc}"
    elif rc >= 128:                   # shell convention
        verdict = f"CHECKER_KILLED_signal{rc - 128}"
    else:
        verdict = "CHECKER_KILLED"
    t = time.time() - t0
    try:
        size = os.path.getsize(drat) if os.path.exists(drat) else -1
        with io.open(drat + ".verify.log", "w", encoding="utf-8", newline="") as fh:
            fh.write(f"verdict={verdict}\n")
            fh.write(f"status_drat_trim={status or '(no `s ` line)'}\n")
            fh.write(f"returncode={rc}\n")
            fh.write(f"t_verify_s={t:.1f}\n")
            fh.write(f"drat_bytes={size}\n")
            fh.write(f"stderr_tail={(v.stderr or '')[-400:]!r}\n")
    except Exception as e:                                   # noqa: BLE001
        # instrumentation must NOT bring down a verification that passed
        print(f"  warning: drat_verify sidecar failed ({e}); verdict preserved", file=sys.stderr)
    return {"ok": ok, "verdict": verdict, "status": status or "(no `s ` line)",
            "rc": rc, "t_s": round(t, 1)}


def drat_verify(cnf, drat):
    """True iff drat-trim actually verified the proof. Thin wrapper over drat_verify_detailed.

    Kept because several call sites depend on the bool. Whoever RECORDS a verdict should use the
    detailed version -- the bool does not distinguish "the proof is wrong" from "my run died".
    """
    return drat_verify_detailed(cnf, drat)["ok"]


def build_amo_shared(tt, opt):
    """Builds the CNF of the base encoder (circuit, k=opt) + at-most-one-shared constraint.
    Returns (nvars, clauses, enc). Fixed at n = N = 4; for other n use
    certlab.certify.forced_multi.build_amo_shared, where n is a required argument."""
    enc = AIGEncoder(N, opt, tt).build()
    nvars = enc.nvars
    clauses = list(enc.clauses)
    k = opt

    def newvar():
        nonlocal nvars
        nvars += 1
        return nvars

    # users of each gate i (i<k): list of (j, sel_vars of the option referencing i)
    # u[i][j] var
    u = {}
    for i in range(1, k):          # gate i, node = N+i
        node = N + i
        user_gates = []
        for j in range(i + 1, k + 1):
            ref_sels = [o[4] for o in enc.options[j] if o[0] == node or o[2] == node]
            if not ref_sels:
                continue
            uij = newvar()
            u[(i, j)] = uij
            for s in ref_sels:
                clauses.append([-s, uij])   # referencing option selected => u
            user_gates.append(j)
        # z[i]: fan-out>=2 => z[i]
        zi = newvar()
        u[("z", i)] = zi
        for j1, j2 in combinations(user_gates, 2):
            clauses.append([zi, -u[(i, j1)], -u[(i, j2)]])
    # amo(z): at most one shared
    zs = [u[("z", i)] for i in range(1, k)]
    for a, b in combinations(zs, 2):
        clauses.append([-a, -b])
    return nvars, clauses, enc


def certify_one(tt, opt):
    tag = f"{tt:#06x}"
    print(f"\n{'='*66}\n[{tag}] opt={opt} -- zero-conforming certification (DRAT)\n{'='*66}")
    res = {"tt_hex": tag, "opt": opt}

    # (1) opt >= OPT : UNSAT for k=1..OPT-1
    lb = []
    ok_lb = True
    for kk in range(1, opt):
        enc = AIGEncoder(N, kk, tt).build()
        cnf = os.path.join(CERTS, f"zc_{tt:#06x}_opt_k{kk}.cnf")
        if any(len(cl) == 0 for cl in enc.clauses):
            print(f"  opt-LB k={kk}: UNSAT (syntactic, empty clause)")
            lb.append({"k": kk, "result": "UNSAT_SYN"})
            continue
        write_cnf(enc.nvars, enc.clauses, cnf)
        drat = os.path.join(CERTS, f"zc_{tt:#06x}_opt_k{kk}.drat")
        rc, _ = kissat(cnf, drat)
        if rc == 10:
            print(f"  !!! opt-LB k={kk} SAT — opt<{opt}. ABORTING {tag}.")
            res["error"] = f"opt LB failed at k={kk}"
            return res
        ver = drat_verify(cnf, drat)
        ok_lb = ok_lb and ver
        print(f"  opt-LB k={kk}: UNSAT drat={os.path.getsize(drat)}B "
              f"cnf_sha={sha16(cnf)} drat-trim={'VERIFIED' if ver else 'FAILED'}")
        lb.append({"k": kk, "result": "UNSAT", "cnf_sha": sha16(cnf),
                   "drat_sha": sha16(drat), "drat_trim_verified": ver})
    res["opt_lower_bound_drat"] = lb
    res["opt_lb_all_verified"] = ok_lb

    # (2) opt <= OPT : witness SAT at k=OPT
    enc = AIGEncoder(N, opt, tt).build()
    cnf_w = os.path.join(CERTS, f"zc_{tt:#06x}_opt_k{opt}.cnf")
    write_cnf(enc.nvars, enc.clauses, cnf_w)
    rc, model = kissat(cnf_w)
    if rc != 10:
        print(f"  !!! opt k={opt} not SAT (rc={rc}) — opt>{opt}? ABORTING.")
        res["error"] = "no witness at k=opt"
        return res
    gates, op = enc.decode(model)
    ok_sim = verify_circuit(N, tt, gates, op)
    print(f"  opt-UB k={opt}: SAT witness verify_circuit={ok_sim}")
    res["opt_witness"] = {"gates": gates, "op": op, "verify_circuit": ok_sim}

    # (3) >=2 shared : at-most-one-shared UNSAT at k=OPT
    nvars, clauses, _ = build_amo_shared(tt, opt)
    cnf = os.path.join(CERTS, f"zc_{tt:#06x}_amo1shared.cnf")
    write_cnf(nvars, clauses, cnf)
    drat = os.path.join(CERTS, f"zc_{tt:#06x}_amo1shared.drat")
    rc, _ = kissat(cnf, drat)
    if rc == 10:
        print(f"  !!! at-most-1-shared SAT -- a conforming optimum exists! NOT zero-conforming. ABORTING.")
        res["error"] = "at-most-1-shared SAT (not zero-conforming)"
        res["forced_ge2_shared"] = False
        return res
    ver = drat_verify(cnf, drat)
    print(f"  >=2-shared: at-most-1-shared UNSAT drat={os.path.getsize(drat)}B "
          f"cnf_sha={sha16(cnf)} drat-trim={'VERIFIED' if ver else 'FAILED'}")
    res["amo1shared_unsat_drat"] = {"result": "UNSAT", "cnf_sha": sha16(cnf),
                                    "drat_sha": sha16(drat), "drat_trim_verified": ver}
    res["forced_ge2_shared"] = ver
    res["certified"] = ok_lb and ok_sim and ver
    print(f"  [{tag}] zero-conforming, DRAT-certified: {res['certified']}")
    return res


def main():
    only = os.environ.get("ZC_ONLY")  # e.g. "0x03de"
    targets = ZC if not only else [(tt, o) for tt, o in ZC if f"{tt:#06x}" == only]
    out = []
    for tt, opt in targets:
        out.append(certify_one(tt, opt))
    allok = all(r.get("certified") for r in out)
    path = os.path.join(CERTS, "zc_forced_witness.json")
    json.dump({"n": len(out), "all_certified": allok, "results": out}, open(path, "w"), indent=2)
    print(f"\n[SAVE] {path}\nALL {len(out)} ZC functions DRAT-certified (forced double reconvergence)? {allok}")
    return 0 if allok else 1


if __name__ == "__main__":
    sys.exit(main())
