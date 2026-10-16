"""The drat-trim verdict: scripts/check_drat.sh, certlab.certify.zc_certify.drat_verify_detailed and
`certlab check-drat` must classify every outcome the same way (tests/drat_battery.py)."""
import os
import subprocess
import sys

import pytest

from conftest import ROOT, SRC, env_with_path_first, needs_drat_trim, needs_kissat
import drat_battery as B

CHECK = os.path.join(ROOT, "scripts", "check_drat.sh")


@pytest.mark.parametrize("name,body,expected", B.CASES, ids=[c[0] for c in B.CASES])
def test_battery_all_readers_agree(tmp_path, fakebin, monkeypatch, name, body, expected):
    B.write_fake(fakebin, body)
    cnf, drat = B.dummy_pair(str(tmp_path))
    env = env_with_path_first(fakebin)

    rc_sh = B.run_check_drat_sh(CHECK, cnf, drat, env)

    monkeypatch.setenv("PATH", env["PATH"])
    from certlab.certify.zc_certify import drat_verify_detailed, drat_verify
    d = drat_verify_detailed(cnf, drat)
    rc_py = B.python_class(d["verdict"])

    rc_cli = subprocess.run([sys.executable, "-m", "certlab.cli", "check-drat", cnf, drat],
                            capture_output=True, text=True, env=env).returncode

    assert (rc_sh, rc_py, rc_cli) == (expected, expected, expected), \
        f"{name}: check_drat.sh={rc_sh} python={rc_py} ({d['verdict']}) cli={rc_cli}, expected {expected}"
    assert drat_verify(cnf, drat) is (expected == 0)


def test_usage_errors_are_exit_2(tmp_path, fakebin):
    env = env_with_path_first(fakebin)
    B.write_fake(fakebin, "printf 's VERIFIED\\n'; exit 0")
    cnf, drat = B.dummy_pair(str(tmp_path))
    assert subprocess.run(["bash", CHECK], capture_output=True, env=env).returncode == 2
    assert subprocess.run(["bash", CHECK, cnf, str(tmp_path / "missing.drat")],
                          capture_output=True, env=env).returncode == 2
    # drat-trim absent: a PATH with only the basic system tools
    env2 = dict(env, PATH="/usr/bin:/bin")
    if not os.path.exists("/usr/bin/drat-trim"):
        assert subprocess.run(["bash", CHECK, cnf, drat], capture_output=True, env=env2).returncode == 2
    assert subprocess.run([sys.executable, "-m", "certlab.cli", "check-drat", cnf,
                           str(tmp_path / "missing.drat")], capture_output=True, env=env).returncode == 2


@needs_kissat
@needs_drat_trim
def test_real_proof_and_empty_proof(tmp_path):
    """Real drat-trim on a real proof: the n = 5 flagship's opt lower-bound leg at k = 3
    (CNF pinned in data/manifest.csv as a4c2ba4cd9869694). Negative first: an empty proof."""
    from certlab.encoders.aig import AIGEncoder
    from certlab.certify.zc_certify import write_cnf, sha16, drat_verify_detailed
    enc = AIGEncoder(5, 3, 0x03DE0154).build()
    cnf = str(tmp_path / "k3.cnf")
    write_cnf(enc.nvars, enc.clauses, cnf)
    assert sha16(cnf) == "a4c2ba4cd9869694"

    empty = str(tmp_path / "empty.drat")
    with open(empty, "w") as fh:
        fh.write("0\n")
    env = dict(os.environ)
    assert subprocess.run(["bash", CHECK, cnf, empty], capture_output=True, env=env).returncode == 1
    assert drat_verify_detailed(cnf, empty)["verdict"] == "NOT_VERIFIED"

    drat = str(tmp_path / "k3.drat")
    rc = subprocess.run(["kissat", "-q", cnf, drat], capture_output=True).returncode
    assert rc == 20
    assert subprocess.run(["bash", CHECK, cnf, drat], capture_output=True, env=env).returncode == 0
    assert drat_verify_detailed(cnf, drat)["verdict"] == "VERIFIED"
    env["PYTHONPATH"] = SRC
    assert subprocess.run([sys.executable, "-m", "certlab.cli", "check-drat", cnf, drat],
                          capture_output=True, env=env).returncode == 0
