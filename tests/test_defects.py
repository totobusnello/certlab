"""Regression tests for the defects fixed in the package (TESTING.md, "Defects fixed").

Every probe runs in a subprocess, with and without `python3 -O`, and must hit its guard
(RAISED). tools/prove_fixes.py runs the same probes against the original scripts, where they
come back RETURNED under -O: each of these tests fails on the old code.
"""
import os
import re

import pytest

from conftest import ROOT, env_with_path_first
import defect_probes as D

SOLVER_PROBES = [n for n in D.PROBES if n.startswith("solver_failure_")]
OTHER_PROBES = [n for n in D.PROBES if not n.startswith("solver_failure_")]


@pytest.mark.parametrize("optimize", [False, True], ids=["python3", "python3-O"])
@pytest.mark.parametrize("mode", sorted(D.FAKE_KISSAT))
@pytest.mark.parametrize("probe", SOLVER_PROBES)
def test_solver_failure_is_never_unsat(tmp_path, probe, mode, optimize):
    d = D.fake_kissat_dir(str(tmp_path), mode)
    out = D.run_probe(probe, D.IMPORTS_NEW, optimize, env_with_path_first(d, {"FAKEBIN": d}))
    assert out.startswith("RAISED RuntimeError"), out


@pytest.mark.parametrize("optimize", [False, True], ids=["python3", "python3-O"])
@pytest.mark.parametrize("probe", OTHER_PROBES)
def test_guards_survive_optimize(tmp_path, probe, optimize):
    d = D.fake_kissat_dir(str(tmp_path), "exit1") if probe.startswith("witness") else str(tmp_path)
    out = D.run_probe(probe, D.IMPORTS_NEW, optimize, env_with_path_first(d, {"FAKEBIN": d}))
    assert out.startswith("RAISED"), out


def test_no_assert_as_verdict_guard_in_package():
    """No `assert` statement anywhere under src/ (asserts vanish under -O)."""
    hits = []
    for dp, _, fns in os.walk(os.path.join(ROOT, "src")):
        for fn in fns:
            if fn.endswith(".py"):
                p = os.path.join(dp, fn)
                for i, line in enumerate(open(p, encoding="utf-8"), 1):
                    if re.match(r"\s*assert\b", line):
                        hits.append(f"{os.path.relpath(p, ROOT)}:{i}")
    assert not hits, hits


def test_no_sys_path_insert_in_package():
    hits = []
    for dp, _, fns in os.walk(os.path.join(ROOT, "src")):
        for fn in fns:
            if fn.endswith(".py") and "sys.path.insert" in open(os.path.join(dp, fn), encoding="utf-8").read():
                hits.append(fn)
    assert not hits, hits
