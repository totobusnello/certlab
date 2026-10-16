"""scripts/reverify.sh, scripts/certify.sh preflight, and the certification chain end to end on
the n = 4 base (small enough for the fast suite)."""
import os
import shutil
import subprocess
import sys

import pytest

from conftest import ROOT, SRC, needs_drat_trim, needs_kissat

REVERIFY = os.path.join(ROOT, "scripts", "reverify.sh")
CERTIFY = os.path.join(ROOT, "scripts", "certify.sh")


def _env(**kw):
    e = dict(os.environ)
    e["PYTHONPATH"] = SRC
    e.update(kw)
    return e


def _unsat_pair(d, name, k):
    from certlab.encoders.aig import AIGEncoder
    from certlab.certify.zc_certify import write_cnf
    enc = AIGEncoder(5, k, 0x03DE0154).build()
    cnf = os.path.join(d, f"{name}.cnf")
    write_cnf(enc.nvars, enc.clauses, cnf)
    rc = subprocess.run(["kissat", "-q", cnf, os.path.join(d, f"{name}.drat")], capture_output=True).returncode
    assert rc == 20


@needs_kissat
@needs_drat_trim
def test_reverify_good_and_adulterated(tmp_path):
    d = str(tmp_path)
    _unsat_pair(d, "a", 2)
    _unsat_pair(d, "b", 3)
    p = subprocess.run(["bash", REVERIFY, d], capture_output=True, text=True)
    assert p.returncode == 0 and "PASS=2 FAIL=0" in p.stdout, p.stdout
    # adulterate b: keep only the final empty clause -> the proof no longer derives the conflict
    with open(os.path.join(d, "b.drat"), "w") as fh:
        fh.write("0\n")
    p = subprocess.run(["bash", REVERIFY, d], capture_output=True, text=True)
    assert p.returncode != 0 and "FAIL=1" in p.stdout, p.stdout
    # a proof without its formula is not a pass either
    os.remove(os.path.join(d, "b.drat"))
    os.remove(os.path.join(d, "a.cnf"))
    p = subprocess.run(["bash", REVERIFY, d], capture_output=True, text=True)
    assert p.returncode != 0 and "MISS=1" in p.stdout, p.stdout


def test_reverify_missing_dir(tmp_path):
    assert subprocess.run(["bash", REVERIFY, str(tmp_path / "nope")], capture_output=True).returncode == 2


def test_certify_refuses_without_toolchain(tmp_path):
    env = _env(PATH="/usr/bin:/bin", CERTLAB_CERTS=str(tmp_path))
    if shutil.which("kissat", path=env["PATH"]) and shutil.which("drat-trim", path=env["PATH"]):
        pytest.skip("kissat and drat-trim are in the system PATH")
    p = subprocess.run(["bash", CERTIFY, "0x03de0154", "8"], capture_output=True, text=True, env=env)
    assert p.returncode == 3 and "REFUSED" in p.stdout, p.stdout


@needs_kissat
@needs_drat_trim
def test_zc_chain_n4_flagship(tmp_path):
    """opt LB (DRAT), witness (simulated), at-most-one-shared UNSAT (DRAT) for 0x03de, n = 4."""
    p = subprocess.run([sys.executable, "-m", "certlab.certify.zc_certify"], capture_output=True, text=True,
                       env=_env(ZC_ONLY="0x03de", CERTLAB_CERTS=str(tmp_path)), timeout=900)
    assert p.returncode == 0, p.stdout[-2000:]
    assert "zero-conforming, DRAT-certified: True" in p.stdout


@needs_kissat
@needs_drat_trim
def test_forced_multi_chain_n4_base(tmp_path):
    """The generalised chain (forced_multi.main) on the n = 4 base: all three legs must close."""
    p = subprocess.run([sys.executable, "-m", "certlab.certify.forced_multi", "0x03de", "6", "4"],
                       capture_output=True, text=True, env=_env(CERTLAB_CERTS=str(tmp_path)), timeout=900)
    assert p.returncode == 0, p.stdout[-2000:]
    assert "FORCED MULTIPLE RECONVERGENCE at n=4" in p.stdout


@needs_kissat
@needs_drat_trim
def test_witness_n4_base_full_and_tree_chain(tmp_path):
    p = subprocess.run([sys.executable, "-m", "certlab.witness", "0x03de", "--full", "--tree-chain"],
                       capture_output=True, text=True, env=_env(CERTLAB_OUT=str(tmp_path)), timeout=900)
    assert p.returncode == 0, p.stdout[-2000:]
    assert "[FAIL]" not in p.stdout


@needs_kissat
@needs_drat_trim
@pytest.mark.slow
def test_witness_flagship_n5_quick(tmp_path):
    """The n = 5 flagship 0x03de0154: opt LB k=1..7 (DRAT), opt witness, tree witness, non-canalizing."""
    p = subprocess.run([sys.executable, "-m", "certlab.witness", "0x03de0154"],
                       capture_output=True, text=True, env=_env(CERTLAB_OUT=str(tmp_path)), timeout=3600)
    assert p.returncode == 0, p.stdout[-2000:]
    assert p.stdout.count("[PASS]") == 4
