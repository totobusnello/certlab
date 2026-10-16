"""Certify forced-multi WITHOUT any symmetry break -- solve the VETTED no-SB at-most-one-shared
instance directly. If it returns UNSAT with a drat-trim-VERIFIED proof, the forced-multi
certificate has ZERO symmetry-break gap (no WLOG argument needed at all). Races the available
solver configs; keeps the DRAT of whichever proves UNSAT.

This is level 1 of scripts/certify.sh ("certify forced-multi: DRAT, no symmetry breaking"), for
n = 5 witnesses.

Usage: python3 -m certlab.certify.cert_nosb <tt_hex> <opt> [timeout_s]
Exit codes: 0 certified, 1 UNSAT but drat-trim did not verify, 2 SAT (contradiction to
investigate), 3 refused (nothing run), 4 no verdict.
"""
import glob, os, shutil, subprocess, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
from certlab.certify.forced_multi import build_amo_shared  # noqa
from certlab.certify.zc_certify import write_cnf, drat_verify, sha16, CERTS  # noqa


def refuse_if_of_record(drat):
    """This script writes `n5_<tt>_amo1shared_nosb.drat` -- EXACTLY the name space in which a
    results CSV records VERIFIED proofs, with the sha16 of each. Running it on an already
    certified witness truncates that proof to its first byte and, if the run ends in a timeout,
    leaves a partial file in place of a certificate -- the sha stops matching and the artefact
    does not come back without re-running hours of solver. A file NAMED in a CSV of the
    certificates directory is an artefact of record and is not overwritten."""
    base = os.path.basename(drat)
    for csv_path in glob.glob(os.path.join(CERTS, "*.csv")):
        with open(csv_path, errors="ignore") as fh:
            if base in fh.read():
                print(f"  ABORT: {base} is cited by {os.path.basename(csv_path)} — it is a proof of record, "
                      f"and this run would truncate it. Delete the CSV row first if it really must be redone.",
                      flush=True)
                return True
    return False


def main():
    tt = int(sys.argv[1], 16); opt = int(sys.argv[2])
    T = float(sys.argv[3]) if len(sys.argv) > 3 else 14400.0
    if refuse_if_of_record(os.path.join(CERTS, f"n5_{tt:#010x}_amo1shared_nosb.drat")):
        return 3
    nv, cl = build_amo_shared(tt, opt, gate_order_b=False, n=5)   # VETTED encoder, NO symmetry break
    cnf = os.path.join(CERTS, f"n5_{tt:#010x}_amo1shared_nosb.cnf")
    write_cnf(nv, cl, cnf)
    print(f"[cert-nosb] {tt:#010x} opt={opt}: {nv} vars, {len(cl)} clauses (NO SB), timeout={T}s", flush=True)
    drat = os.path.join(CERTS, f"n5_{tt:#010x}_amo1shared_nosb.drat")
    # race: kissat (writes DRAT) vs cadical (writes DRAT)
    dk = drat; dc = drat + ".cadical"
    # The race DEGRADES instead of crashing when a solver is not installed, because of an
    # incident: `cadical` was absent, `Popen` raised FileNotFoundError and the Python process
    # died -- but the kissat already launched SURVIVED AS AN ORPHAN, writing a multi-GB DRAT that
    # nobody would verify. A crash in the middle of a race leaves garbage that consumes disk and
    # looks like progress. A missing solver is now announced and skipped; zero solvers aborts
    # BEFORE launching anything.
    # `--unsat` is NOT used, and the measurement that removed it is the useful result. On the
    # SAME CNF (`0x178e0000`, k=9, 1749 vars, 229525 clauses), on the same machine:
    #
    #     kissat -q                        4765 s   UNSAT
    #     kissat -q --unsat                5672 s   UNSAT          (the flag alone: +19%)
    #     kissat -q        + DRAT          4006 s   UNSAT, 13 GB   (the proof alone: free)
    #     kissat -q --unsat + DRAT       >21600 s   NO VERDICT     (the combination: >5x)
    #
    # Neither the flag nor the proof log costs anything. The COMBINATION blows up; why was not
    # measured, so no mechanism is claimed. What matters is the consequence: `--unsat` had been
    # put here because it seemed appropriate for an instance expected to be UNSAT, without a
    # measurement; that choice produced a 6 h timeout that nearly got reported as "the DRAT route
    # does not scale at this arity". It was no wall at all: it was a flag. Without it, the leg
    # decides in 67 min and drat-trim verifies in 4637 s (`s VERIFIED`).
    plan = [("kissat", ["kissat", "-q", cnf, dk], dk),
            ("cadical", ["cadical", "-q", cnf, dc], dc)]
    procs, dpaths = {}, {}
    for name, argv, dpath in plan:
        if shutil.which(argv[0]) is None:
            print(f"  [warning] {argv[0]} not installed — left out of the race", flush=True)
            continue
        procs[name] = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        dpaths[name] = dpath
    if not procs:
        print("  ABORT: no solver of the race is installed — nothing was launched", flush=True)
        # 3 = refused to act (toolchain), not 2 (= an anomaly in the data). Nothing ran, so
        # nothing was contradicted. Aligned with SolverMissing in zc_certify.
        return 3
    t0 = time.time(); win = None; died = {}
    # SAMPLING of RSS and proof size, every 30 s. Without it, "the solver died" and "the instance
    # is hard" are indistinguishable at the end -- and the original loop only broke on
    # rc in {10,20}, so ANY other exit (crash, OS kill, signal) left the script sleeping until
    # the timeout and then writing "no verdict (no-SB still hard)". A false diagnosis: in one run
    # kissat died at ~80 min with 12.81 GB of proof and the job kept spinning for 4.5 h; the
    # same kissat runs alone at the same rate, so the instance was NOT the problem and the
    # report would have said it was.
    trace = os.path.join(CERTS, f"n5_{tt:#010x}_nosb_trace.tsv")
    with open(trace, "w") as fh:
        fh.write("t_s\tsolver\trss_mb\tdrat_gb\n")
    last = 0.0
    while time.time() - t0 < T:
        for name, p in procs.items():
            rc = p.poll()
            if rc in (10, 20):
                win = (name, rc, dpaths[name]); break
            if rc is not None and name not in died:
                # abnormal exit: record it WITH the state at that moment, and stop waiting for it
                sz = os.path.getsize(dpaths[name]) if os.path.exists(dpaths[name]) else 0
                died[name] = (rc, time.time() - t0, sz)
                print(f"  [DIED] {name} exited with rc={rc} at {died[name][1]:.0f}s with "
                      f"{sz/1e9:.2f} GB of proof — this is NOT a verdict, it is a solver death", flush=True)
        if win or (died and len(died) == len(procs)):
            break
        now = time.time() - t0
        if now - last >= 30:
            last = now
            with open(trace, "a") as fh:
                for name, p in procs.items():
                    if p.poll() is not None:
                        continue
                    try:
                        rss = int(subprocess.run(["ps", "-o", "rss=", "-p", str(p.pid)],
                                                 capture_output=True, text=True).stdout.strip() or 0)
                    except Exception:
                        rss = -1
                    sz = os.path.getsize(dpaths[name]) if os.path.exists(dpaths[name]) else 0
                    fh.write(f"{now:.0f}\t{name}\t{rss // 1024}\t{sz / 1e9:.2f}\n")
        time.sleep(3)
    for p in procs.values():
        if p.poll() is None:
            p.kill()
    dt = time.time() - t0
    if not win:
        # A partial proof is worth ZERO and costs a lot: one was left at 4.45 GiB on disk, with the
        # name of a certificate, in a directory where everything else is a certificate. Nobody can
        # verify it (it has no final empty clause) and whoever finds it with `ls` reads "proof".
        # It goes.
        for name, dpath in dpaths.items():
            if os.path.exists(dpath):
                sz = os.path.getsize(dpath)
                os.remove(dpath)
                print(f"  [cleanup] PARTIAL proof of {name} removed ({sz/1e9:.2f} GB) — without a verdict "
                      f"there is nothing to verify, and a partial file in this directory passes for a proof",
                      flush=True)
        if died:
            d = ", ".join(f"{n}: rc={r} at {s:.0f}s with {z/1e9:.2f} GB" for n, (r, s, z) in died.items())
            print(f"  RESULT: NO VERDICT because the solver(s) DIED ({d}). This does NOT say that the "
                  f"instance is hard — it says the run failed. RSS trace in {os.path.basename(trace)}.",
                  flush=True)
        else:
            print(f"  RESULT: no verdict in {dt:.0f}s. Do NOT conclude from this that the instance is hard: "
                  f"a 6 h timeout in this family was once caused by a flag (`--unsat`), not by the instance.",
                  flush=True)
        return 4
    name, rc, dpath = win
    if rc == 20:
        ver = drat_verify(cnf, dpath)
        print(f"  RESULT: no-SB amo-shared UNSAT (by {name}) drat-trim={'VERIFIED' if ver else 'FAIL'}  [{dt:.0f}s]", flush=True)
        print(f"  cnf sha16={sha16(cnf)}  drat sha16={sha16(dpath)}", flush=True)
        print("  => forced-multi certified with ZERO symmetry-break gap. VeriPB unnecessary for this witness.", flush=True)
        return 0 if ver else 1
    else:
        print(f"  RESULT: no-SB SAT (by {name}) -> a <=1-shared optimum exists WITHOUT SB => NOT forced-multi?! "
              "contradicts the SB result; investigate the SB soundness immediately.", flush=True)
        return 2


if __name__ == "__main__":
    sys.exit(main())
