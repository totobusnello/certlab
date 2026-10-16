"""The pre-registered validation gates of the XAG and MIG encoders (tests/gates/), run as scripts:
n = 2 sanity, and all 256 functions of n = 3 against an independent exhaustive enumeration and
against opt_AIG."""
import os
import subprocess
import sys

import pytest

from conftest import ROOT, SRC, needs_kissat


@needs_kissat
@pytest.mark.slow
@pytest.mark.parametrize("gate,token", [("gate_xag.py", "GATE X1+X2: PASSED"), ("gate_mig.py", "GATE M1+M2: PASSED")])
def test_gate(gate, token):
    env = dict(os.environ, PYTHONPATH=SRC)
    p = subprocess.run([sys.executable, os.path.join(ROOT, "tests", "gates", gate)],
                       capture_output=True, text=True, env=env, timeout=3600)
    assert p.returncode == 0 and token in p.stdout, p.stdout[-2000:] + p.stderr[-2000:]
