#!/usr/bin/env python3
"""Show that every defect test of the package FAILS on the original scripts.

A regression test that has never failed proves nothing. For each fixed defect this script runs
the same probe (tests/defect_probes.py, tests/drat_battery.py) against

  NEW  the packaged modules (must hit the guard), and
  OLD  a temporary mirror of the original research scripts, located under --source-root by
       basename + sha256 (tools/ast_map.json), so the exact files that were translated

and prints one line per probe. Expected: NEW = RAISED (or the right class), OLD under -O =
RETURNED (or the wrong class). Exit 0 iff every probe behaves as expected on both sides.

    python3 tools/prove_fixes.py --source-root /path/to/research/checkout
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "tests"))
import defect_probes as D   # noqa: E402
import drat_battery as B    # noqa: E402

OLD_CHECK_DRAT_SHA256 = "39964c38ab72b257d32b292456a2a5700b29b17c238951dcb2ac0df4ab3914fa"
OLD_MODULES = ("aig_exact.py", "xag_exact.py", "mig_exact.py", "npn_canon.py", "n5_forced_test.py",
               "zc_certify.py", "reproduce_witness.py")


def sha256_file(p):
    with open(p, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def locate(source_root, basename, sha, prefer_dir=None):
    hits = []
    for dp, dns, fns in os.walk(source_root):
        dns[:] = [d for d in dns if d not in (".git", "__pycache__")]
        if basename in fns and sha256_file(os.path.join(dp, basename)) == sha:
            hits.append(os.path.relpath(os.path.join(dp, basename), source_root))
    if not hits:
        raise SystemExit(f"prove_fixes: {basename} with sha256 {sha[:12]} not found under the source root")
    same = [h for h in hits if prefer_dir is not None and os.path.dirname(h) == prefer_dir]
    return (same or sorted(hits))[0]


def build_mirror(source_root, mirror):
    with open(os.path.join(HERE, "ast_map.json")) as fh:
        spec = json.load(fh)
    want = {e["original_basename"]: e["original_sha256"] for e in spec["entries"]}
    want["npn4_opt_aig.csv"] = sha256_file(os.path.join(ROOT, "data", "npn4", "npn4_opt_aig.csv"))
    want["check_drat.sh"] = OLD_CHECK_DRAT_SHA256
    paths = {}
    rels = {}
    for base in list(OLD_MODULES) + ["npn4_opt_aig.csv", "check_drat.sh"]:
        # the census CSV is read by the old NPN module relative to the old AIG encoder's directory
        prefer = os.path.dirname(rels["aig_exact.py"]) if base == "npn4_opt_aig.csv" else None
        rel = rels[base] = locate(source_root, base, want[base], prefer)
        dst = os.path.join(mirror, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(os.path.join(source_root, rel), dst)
        paths[base] = dst
    pypath = os.pathsep.join(sorted({os.path.dirname(paths[b]) for b in OLD_MODULES}))
    return paths, pypath


def env_for(fakebin, pythonpath):
    env = dict(os.environ)
    env["PATH"] = fakebin + os.pathsep + env.get("PATH", "")
    env["PYTHONPATH"] = pythonpath
    env["FAKEBIN"] = fakebin
    return env


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--source-root", required=True)
    a = ap.parse_args()
    tmp = tempfile.mkdtemp(prefix="prove-fixes-")
    ok = True
    try:
        mirror = os.path.join(tmp, "mirror")
        paths, old_pp = build_mirror(a.source_root, mirror)
        new_pp = os.path.join(ROOT, "src")
        print("probe                                   mode            NEW -O                         OLD -O")
        for name in D.PROBES:
            modes = sorted(D.FAKE_KISSAT) if name.startswith("solver_failure") else [None]
            for mode in modes:
                if mode:
                    fb = D.fake_kissat_dir(tmp, mode)
                elif name.startswith("witness"):
                    fb = D.fake_kissat_dir(tmp, "exit1")
                else:
                    fb = os.path.join(tmp, "fb-" + name)
                    os.makedirs(fb, exist_ok=True)
                env_new = env_for(fb, new_pp)
                env_new["CERTLAB_CERTS"] = os.path.join(tmp, "certs"); env_new["CERTLAB_OUT"] = os.path.join(tmp, "gen")
                new = D.run_probe(name, D.IMPORTS_NEW, True, env_new, cwd=tmp)
                old = D.run_probe(name, D.IMPORTS_OLD, True, env_for(fb, old_pp), cwd=tmp)
                good = new.startswith("RAISED") and old.startswith("RETURNED")
                ok &= good
                print(f"{'ok ' if good else 'BAD'} {name:36s} {str(mode or '-'):15s} {new[:30]:30s} {old[:60]}")
        print("\ndrat-trim reader battery (exit class: NEW scripts/check_drat.sh vs OLD check_drat.sh)")
        old_sh = paths["check_drat.sh"]
        new_sh = os.path.join(ROOT, "scripts", "check_drat.sh")
        n_old_wrong = 0
        for case, body, expected in B.CASES:
            fb = os.path.join(tmp, "drat-" + case)
            os.makedirs(fb, exist_ok=True)
            B.write_fake(fb, body)
            cnf, drat = B.dummy_pair(fb)
            env = env_for(fb, new_pp)
            rn = B.run_check_drat_sh(new_sh, cnf, drat, env)
            ro = B.run_check_drat_sh(old_sh, cnf, drat, env)
            ok &= rn == expected
            n_old_wrong += ro != expected
            print(f"  {case:34s} expected {expected}  NEW {rn}  OLD {ro}{'   <- old reading wrong' if ro != expected else ''}")
        ok &= n_old_wrong > 0
        print(f"  old check_drat.sh misreads {n_old_wrong}/{len(B.CASES)} cases")
        n_old = sum(open(paths[b], encoding="utf-8").read().count("sys.path.insert") for b in OLD_MODULES)
        n_new = sum(open(os.path.join(dp, f), encoding="utf-8").read().count("sys.path.insert")
                    for dp, _, fs in os.walk(new_pp) for f in fs if f.endswith(".py"))
        print(f"\nsys.path.insert occurrences: OLD {n_old} (in the {len(OLD_MODULES)} mirrored modules), NEW {n_new} (src/)")
        ok &= n_new == 0 and n_old > 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"\nprove_fixes: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
