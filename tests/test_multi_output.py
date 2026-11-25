"""Multi-output encoders (phase 2): certlab.encoders.multi_aig and certlab.encoders.multi_mig.

Order of the checks: first what must be REJECTED (a wrong circuit, the wrong bit convention, one
gate fewer than the optimum), then the controls against values established elsewhere:

- MIG: the full adder SUM_3 = 3 and the half adder SUM_2 = 3 (exact, both directions);
  SUM_5 has no 6-gate MIG (a lower-bound step of the published SUM_5 = 9); PAR_5 = 6 (slow);
- AIG: six rows of an exhaustive audit of a published multi-output AIG database at n = 3, each
  with the database's size and the exact one (the database is suboptimal on all six);
  SUM_3 (full adder) = 7 AND gates;
- with one output, both encoders agree with the single-output encoders.

Every SAT witness is also checked by certlab.simulate.check_multi, which imports nothing from the
encoders.
"""
import itertools

import pytest

from conftest import needs_kissat
from certlab import simulate as S
from certlab.encoders import aig, mig, multi_aig, multi_mig

PAR5 = sum(1 << t for t in range(32) if bin(t).count("1") % 2)


def _single_opt(encoder_cls, trivial, n, tt, kmax=8):
    """Single-output size through the single-output encoders and kissat (no pysat needed)."""
    import os
    import subprocess
    import tempfile
    if trivial(n, tt):
        return 0
    for k in range(1, kmax + 1):
        enc = encoder_cls(n, k, tt).build()
        if any(len(c) == 0 for c in enc.clauses):
            continue
        with tempfile.NamedTemporaryFile("w", suffix=".cnf", delete=False) as fh:
            fh.write(f"p cnf {enc.nvars} {len(enc.clauses)}\n")
            for cl in enc.clauses:
                fh.write(" ".join(map(str, cl)) + " 0\n")
        rc = subprocess.run(["kissat", "-q", fh.name], capture_output=True).returncode
        os.unlink(fh.name)
        if rc == 10:
            return k
        if rc != 20:
            raise RuntimeError(f"kissat rc={rc}")
    return None


# ---------------------------------------------------------------- negatives first

@needs_kissat
def test_independent_check_rejects_a_flipped_output():
    tts = multi_mig.sum_tts(3)
    sat, (gates, outs) = multi_mig.solve_k(3, tts, 3, return_circuit=True)
    assert sat and S.check_multi("mig", 3, tts, gates, outs)
    bad = [(nd, not pol) if o == 0 else (nd, pol) for o, (nd, pol) in enumerate(outs)]
    assert not S.check_multi("mig", 3, tts, gates, bad)
    assert not S.check_multi("mig", 3, tts, gates, outs[:1])          # one output missing


@needs_kissat
def test_independent_check_is_sensitive_to_the_bit_convention():
    # asymmetric two-output target: (x1 AND NOT x2, x1 OR x3)
    n = 3
    x = {j: S.input_tt(n, j) for j in (1, 2, 3)}
    m = (1 << (1 << n)) - 1
    tts = [x[1] & (x[2] ^ m), x[1] | x[3]]
    for basis, mod in (("aig", multi_aig), ("mig", multi_mig)):
        if basis == "aig":
            sat, circ = mod.solve_k(n, tts, mod.opt_multi(n, tts))
        else:
            sat, circ = mod.solve_k(n, tts, mod.opt_multi_via_sat(n, tts), return_circuit=True)
        assert sat
        assert S.check_multi(basis, n, tts, *circ)
        assert not S.check_multi(basis, n, tts, *circ, convention="msb"), basis


@needs_kissat
@pytest.mark.parametrize("basis", ["aig", "mig"])
def test_one_gate_below_the_optimum_is_unsat(basis):
    tts = multi_mig.sum_tts(3)
    if basis == "aig":
        assert multi_aig.solve_k(3, tts, 6) == (False, None)
    else:
        assert multi_mig.solve_k(3, tts, 2) == (False, None)


# ---------------------------------------------------------------- MIG controls

@needs_kissat
def test_mig_full_adder_and_half_adder():
    for n in (2, 3):
        tts = multi_mig.sum_tts(n)
        assert multi_mig.opt_multi_via_sat(n, tts, kmax=4) == 3
        sat, circ = multi_mig.solve_k(n, tts, 3, return_circuit=True)
        assert sat and S.check_multi("mig", n, tts, *circ)


def test_sum_tts_against_a_direct_count():
    for n in range(1, 8):
        tts = multi_mig.sum_tts(n)
        assert len(tts) == n.bit_length()
        for t in range(1 << n):
            w = sum(tt_bit for tt_bit in ((S.input_tt(n, j) >> t) & 1 for j in range(1, n + 1)))
            assert sum(((tt >> t) & 1) << j for j, tt in enumerate(tts)) == w


@needs_kissat
def test_mig_fences_partition_the_search():
    assert len(list(multi_mig.fences(6))) == 2 ** 5
    tts = multi_mig.sum_tts(3)
    for k, want in ((2, False), (3, True)):
        hits = [f for f in multi_mig.fences(k)
                if multi_mig.solve_k(3, tts, k, fence=f)[0]]
        assert bool(hits) == want, (k, hits)


@needs_kissat
def test_mig_input_symmetry_break_keeps_the_optimum():
    tts = multi_mig.sum_tts(3)
    assert multi_mig.solve_k(3, tts, 2, sym_inputs=[[1, 2, 3]]) == (False, None)
    sat, circ = multi_mig.solve_k(3, tts, 3, return_circuit=True, sym_inputs=[[1, 2, 3]])
    assert sat and S.check_multi("mig", 3, tts, *circ)


@needs_kissat
def test_mig_sum5_has_no_six_gate_circuit():
    # one step of the lower bound of the published SUM_5 = 9 (no symmetry break; ~10 s)
    assert multi_mig.solve_k(5, multi_mig.sum_tts(5), 6) == (False, None)


@needs_kissat
@pytest.mark.slow
def test_mig_par5_is_six():
    # PAR_5 = 6 MAJ gates, through the multi-output encoder with one output (~80 s for k = 5)
    assert multi_mig.solve_k(5, [PAR5], 5) == (False, None)
    sat, circ = multi_mig.solve_k(5, [PAR5], 6, return_circuit=True)
    assert sat and S.check_multi("mig", 5, [PAR5], *circ)


# ---------------------------------------------------------------- AIG controls

# Rows of an exhaustive audit of a published multi-output AIG database at n = 3: the database's
# size, then the exact one. The audit read the tables with x_1 as the most significant bit; the
# size of a minimum circuit does not depend on the order of the inputs, so the tables are used
# as they are.
AUDIT_ROWS = [
    ([15, 24], 6, 5), ([15, 38], 5, 4), ([15, 62], 5, 4),
    ([9, 17, 51], 5, 4), ([10, 51, 185], 5, 4), ([15, 26, 51], 5, 4),
]


@needs_kissat
@pytest.mark.parametrize("tts,k_db,k_opt", AUDIT_ROWS)
def test_aig_audit_rows(tts, k_db, k_opt):
    assert k_opt < k_db
    assert multi_aig.solve_k(3, tts, k_opt - 1) == (False, None)
    sat, circ = multi_aig.solve_k(3, tts, k_opt)
    assert sat and S.check_multi("aig", 3, tts, *circ)


@needs_kissat
def test_aig_full_adder_is_seven():
    tts = multi_mig.sum_tts(3)
    assert multi_aig.opt_multi(3, tts) == 7
    sat, circ = multi_aig.solve_k(3, tts, 7)
    assert sat and S.check_multi("aig", 3, tts, *circ)


# ---------------------------------------------------------------- agreement with single-output

def _npn3_sample():
    # one function per NPN class is not needed here; a fixed spread of n = 3 tables suffices
    return [0x00, 0x01, 0x03, 0x06, 0x07, 0x16, 0x17, 0x18, 0x19, 0x1B, 0x1E, 0x69, 0x6B, 0x96, 0xE8]


@needs_kissat
def test_one_output_reproduces_single_output():
    for tt in _npn3_sample():
        oa = _single_opt(aig.AIGEncoder, aig.trivial_opt, 3, tt)
        om = _single_opt(mig.MIGEncoder, mig.trivial_opt, 3, tt)
        assert multi_aig.opt_multi(3, [tt]) == oa, hex(tt)
        assert multi_mig.opt_multi_via_sat(3, [tt]) == om, hex(tt)


@needs_kissat
def test_f_and_not_f_cost_opt_f():
    for tt in (0x16, 0x69, 0xE8):
        o = multi_aig.opt_multi(3, [tt])
        assert multi_aig.opt_multi(3, [tt, tt ^ 0xFF]) == o
        assert multi_mig.opt_multi_via_sat(3, [tt, tt ^ 0xFF]) == multi_mig.opt_multi_via_sat(3, [tt])


def test_trivial_multi_both_encoders():
    n = 3
    lits = [S.input_tt(n, j) for j in (1, 2, 3)]
    assert multi_aig.trivial_multi(n, [0, 0xFF] + lits + [l ^ 0xFF for l in lits])
    assert multi_mig.trivial_multi(n, [0, 0xFF] + lits)
    assert not multi_aig.trivial_multi(n, lits + [0x96])
    assert not multi_mig.trivial_multi(n, [0x80])
