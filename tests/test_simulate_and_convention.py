"""Independent simulators (certlab.simulate) and the truth-table bit convention.

- The word-parallel simulators must agree with each encoder's own row-by-row simulator on random
  circuits, and reject an adulterated witness.
- Bit convention: for each basis, the witness found for an ASYMMETRIC function (x1 AND NOT x2 at
  n = 3) must check under the encoders' convention (x_j = bit j-1 of the row index) and must FAIL
  under the inverted one (x_j = bit n-j). A check that passes both is blind to the convention.
"""
import os
import random
import subprocess
import tempfile

import pytest

from conftest import needs_kissat
from certlab import simulate as S
from certlab.encoders import aig, xag, mig


def random_circuit(basis, n, k, rnd):
    gates = []
    for i in range(1, k + 1):
        avail = list(range(1, n + i))
        if basis == "aig":
            a, b = sorted(rnd.sample(avail, 2))
            gates.append((a, rnd.randint(0, 1), b, rnd.randint(0, 1)))
        elif basis == "xag":
            a, b = sorted(rnd.sample(avail, 2))
            typ = rnd.choice(["and", "xor"])
            pa, pb = (rnd.randint(0, 1), rnd.randint(0, 1)) if typ == "and" else (0, 0)
            gates.append((typ, a, pa, b, pb))
        else:
            a, b, c = sorted(rnd.sample([0] + avail, 3))
            gates.append((a, rnd.randint(0, 1), b, rnd.randint(0, 1), c, rnd.randint(0, 1)))
    return gates, bool(rnd.randint(0, 1))


ENC = {"aig": aig, "xag": xag, "mig": mig}


@pytest.mark.parametrize("basis", ["aig", "xag", "mig"])
def test_independent_simulator_agrees_with_encoder_simulator(basis):
    rnd = random.Random(20261015)
    mod = ENC[basis]
    for _ in range(300):
        n = rnd.choice([2, 3, 4])
        gates, op = random_circuit(basis, n, rnd.randint(1, 6), rnd)
        tt = S.simulate(basis, n, gates, op)
        assert mod.verify_circuit(n, tt, gates, op)
        assert S.check(basis, n, tt, gates, op)
        # adulterate: flip one row of the truth table -> both must reject
        bad = tt ^ (1 << rnd.randrange(1 << n))
        assert not mod.verify_circuit(n, bad, gates, op)
        assert not S.check(basis, n, bad, gates, op)


def _solve(basis, n, tt, kmax=6):
    for k in range(1, kmax + 1):
        enc = {"aig": aig.AIGEncoder, "xag": xag.XAGEncoder, "mig": mig.MIGEncoder}[basis](n, k, tt).build()
        if any(len(c) == 0 for c in enc.clauses):
            continue
        with tempfile.NamedTemporaryFile("w", suffix=".cnf", delete=False) as fh:
            fh.write(f"p cnf {enc.nvars} {len(enc.clauses)}\n")
            fh.writelines(" ".join(map(str, c)) + " 0\n" for c in enc.clauses)
        r = subprocess.run(["kissat", "-q", fh.name], capture_output=True, text=True)
        os.unlink(fh.name)
        if r.returncode == 10:
            model = [int(x) for l in r.stdout.splitlines() if l.startswith("v ")
                     for x in l[2:].split() if x != "0"]
            return k, enc.decode(model)
        assert r.returncode == 20, r.returncode
    raise AssertionError("no circuit found")


@needs_kissat
@pytest.mark.parametrize("basis", ["aig", "xag", "mig"])
def test_bit_convention_is_load_bearing(basis):
    n = 3
    x1 = S.input_tt(n, 1)                 # bit 0 of the row index
    x2 = S.input_tt(n, 2)                 # bit 1
    tt = x1 & ~x2 & ((1 << (1 << n)) - 1)
    assert tt == sum(1 << t for t in range(8) if (t & 1) and not (t >> 1) & 1)
    k, (gates, op) = _solve(basis, n, tt)
    assert k == 1
    assert S.check(basis, n, tt, gates, op, convention="lsb")
    assert ENC[basis].verify_circuit(n, tt, gates, op)
    assert not S.check(basis, n, tt, gates, op, convention="msb"), \
        "the witness also checks under the inverted convention: the test would be blind to it"
