"""Multi-output encoders (phase 2): certlab.encoders.multi_aig and certlab.encoders.multi_mig.

Order of the checks: first what must be REJECTED (a wrong circuit, the wrong bit convention, one
gate fewer than the optimum), then the controls against values established elsewhere:

- MIG: the full adder SUM_3 = 3 and the half adder SUM_2 = 3 (exact, both directions);
  SUM_5 has no 6-gate MIG (a lower-bound step of the published SUM_5 = 9); PAR_5 = 6 (slow);
- AIG: six rows of an exhaustive audit of a published multi-output AIG database at n = 3, each
  with the database's size and the exact one (the database is suboptimal on all six);
  SUM_3 (full adder) = 7 AND gates;
- with one output, both encoders agree with the single-output encoders.

Every SAT answer of the two encoders is decoded and checked by certlab.simulate.check_multi, which
imports nothing from the encoders (solve_k does it before returning, and raises if the check
fails); the tests below also call check_multi on the witnesses they keep.

Exact size k is not monotone in k for these encodings (every gate must be used, so a target can be
SAT at k, UNSAT at k + 1 and SAT again at k + 2), so a test that states a minimum checks every
smaller k, not only k - 1.
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


# ---------------------------------------------------------------- inputs the API must refuse
# (review of 0.2.0: each of these returned a wrong answer before the fix)

@needs_kissat
def test_an_iterator_of_tables_gives_the_same_answer_as_a_list():
    # XOR and AND of two inputs: 3 gates in both bases. An iterator used to be consumed by the
    # k = 0 test, leaving only AND for the encoder (answer 1).
    assert multi_aig.opt_multi(2, iter([6, 8])) == 3
    assert multi_mig.opt_multi_via_sat(2, iter([6, 8]), kmax=4) == 3
    sat, circ = multi_aig.solve_k(2, iter([6, 8]), 3)
    assert sat and S.check_multi("aig", 2, [6, 8], *circ)
    sat, circ = multi_mig.solve_k(2, iter([6, 8]), 3, return_circuit=True)
    assert sat and S.check_multi("mig", 2, [6, 8], *circ)


@pytest.mark.parametrize("n,tts", [(2, [24]), (2, [-1]), (2, [8, 16]), (0, [0]), (2, [])])
def test_tables_out_of_range_are_rejected(n, tts):
    # [24] has a bit above the 4 rows of n = 2: it used to be read as 8 (one AND gate).
    for call in (lambda: multi_aig.opt_multi(n, tts),
                 lambda: multi_aig.solve_k(n, tts, 1),
                 lambda: multi_aig.trivial_multi(n, tts),
                 lambda: multi_aig.MultiAIGEncoder(n, 1, tts),
                 lambda: multi_mig.opt_multi_via_sat(n, tts),
                 lambda: multi_mig.solve_k(n, tts, 1),
                 lambda: multi_mig.trivial_multi(n, tts),
                 lambda: multi_mig.MultiMIGEncoder(n, 1, tts)):
        with pytest.raises(ValueError):
            call()


@pytest.mark.parametrize("k,fence", [(1, ()), (2, (2, 0)), (2, (1, 0, 1)), (2, (3, -1)), (3, (1, 1))])
def test_invalid_fences_are_rejected(k, fence):
    # fence=() used to be read as "no fence", so a 1-gate instance searched unrestricted.
    with pytest.raises(ValueError):
        multi_mig.MultiMIGEncoder(2, k, [8], fence=fence)


def test_check_multi_rejects_an_unsupported_basis_even_without_gates():
    with pytest.raises(ValueError):
        S.check_multi("xag", 2, [10], [], [(1, 0)])


def test_verify_multi_requires_one_output_per_table():
    # AND(x1, x2) as gate 3; two outputs given for one table
    assert multi_aig.verify_multi(2, [8], [(1, 0, 2, 0)], [(3, False)])
    assert not multi_aig.verify_multi(2, [8], [(1, 0, 2, 0)], [(3, False), (3, True)])
    assert multi_mig.verify_multi(2, [8], [(0, 0, 1, 0, 2, 0)], [(3, False)])
    assert not multi_mig.verify_multi(2, [8], [(0, 0, 1, 0, 2, 0)], [(3, False), (3, True)])


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
def test_mig_fence_restricts_the_search():
    # Discriminating control: a fence that ignored its argument would give the same answer for
    # every fence. At k = 3 the full adder fits the fence (1, 1, 1) but not (3,): three gates on
    # one level read only inputs and the constant, and no majority of literals is XOR_3, the low
    # bit of SUM_3.
    tts = multi_mig.sum_tts(3)
    assert multi_mig.solve_k(3, tts, 3, fence=(3,)) == (False, None)
    sat, circ = multi_mig.solve_k(3, tts, 3, fence=(1, 1, 1), return_circuit=True)
    assert sat and S.check_multi("mig", 3, tts, *circ)


@needs_kissat
def test_mig_input_symmetry_break_keeps_the_optimum():
    tts = multi_mig.sum_tts(3)
    assert multi_mig.solve_k(3, tts, 2, sym_inputs=[[1, 2, 3]]) == (False, None)
    sat, circ = multi_mig.solve_k(3, tts, 3, return_circuit=True, sym_inputs=[[1, 2, 3]])
    assert sat and S.check_multi("mig", 3, tts, *circ)


def test_mig_input_symmetry_break_constrains_the_first_gate():
    # Discriminating control: with inputs 1 and 2 symmetric, gate 1 (nothing before it) may not
    # read x_2 without x_1, so every such option of gate 1 gets the unit clause [-s].
    tts = multi_mig.sum_tts(3)
    enc = multi_mig.MultiMIGEncoder(3, 3, tts, sym_inputs=[[1, 2]]).build()
    units = {cl[0] for cl in enc.clauses if len(cl) == 1}
    banned = [o[6] for o in enc.options[1] if 2 in (o[0], o[2], o[4]) and 1 not in (o[0], o[2], o[4])]
    assert banned and all(-s in units for s in banned)
    plain = multi_mig.MultiMIGEncoder(3, 3, tts).build()
    assert not {cl[0] for cl in plain.clauses if len(cl) == 1}


@needs_kissat
def test_mig_sum5_has_no_six_gate_circuit():
    # one step of the lower bound of the published SUM_5 = 9 (no symmetry break; ~10 s)
    assert multi_mig.solve_k(5, multi_mig.sum_tts(5), 6) == (False, None)


@needs_kissat
@pytest.mark.slow
def test_mig_par5_is_six():
    # PAR_5 = 6 MAJ gates, through the multi-output encoder with one output (~80 s for k = 5)
    assert not multi_mig.trivial_multi(5, [PAR5])
    for k in range(1, 6):
        assert multi_mig.solve_k(5, [PAR5], k) == (False, None), k
    sat, circ = multi_mig.solve_k(5, [PAR5], 6, return_circuit=True)
    assert sat and S.check_multi("mig", 5, [PAR5], *circ)


# ---------------------------------------------------------------- AIG controls

# Rows of an exhaustive audit of a published multi-output AIG database at n = 3: the database's
# size (a fixture value, copied from the database; it is not recomputed here), then the exact
# one, which the test establishes. The audit read the tables with x_1 as the most significant bit; the
# size of a minimum circuit does not depend on the order of the inputs, so the tables are used
# as they are.
AUDIT_ROWS = [
    ([15, 24], 6, 5), ([15, 38], 5, 4), ([15, 62], 5, 4),
    ([9, 17, 51], 5, 4), ([10, 51, 185], 5, 4), ([15, 26, 51], 5, 4),
]


@needs_kissat
@pytest.mark.parametrize("tts,k_db,k_opt", AUDIT_ROWS)
def test_aig_audit_rows(tts, k_db, k_opt):
    assert not multi_aig.trivial_multi(3, tts)
    for k in range(1, k_opt):
        assert multi_aig.solve_k(3, tts, k) == (False, None), k
    sat, circ = multi_aig.solve_k(3, tts, k_opt)
    assert sat and S.check_multi("aig", 3, tts, *circ)


@needs_kissat
def test_aig_full_adder_is_seven():
    tts = multi_mig.sum_tts(3)
    assert multi_aig.opt_multi(3, tts) == 7
    sat, circ = multi_aig.solve_k(3, tts, 7)
    assert sat and S.check_multi("aig", 3, tts, *circ)


# ---------------------------------------------------------------- agreement with single-output

# Fixed reference sizes (AIG, MIG) of a spread of n = 3 functions, so that the tests below compare
# against integers and not only encoder against encoder. Known anchors among them: 0xE8 = MAJ_3
# (one MAJ gate, four AND gates), 0x96 = XOR_3 (three MAJ gates, six AND gates).
REF_N3 = {
    0x00: (0, 0), 0x01: (2, 2), 0x03: (1, 1), 0x06: (4, 3), 0x07: (2, 2), 0x16: (6, 4),
    0x17: (4, 1), 0x18: (5, 4), 0x19: (4, 4), 0x1B: (3, 3), 0x1E: (4, 4), 0x69: (6, 3),
    0x6B: (6, 4), 0x96: (6, 3), 0xE8: (4, 1),
}


@needs_kissat
def test_one_output_reproduces_single_output():
    for tt, (ra, rm) in REF_N3.items():
        assert _single_opt(aig.AIGEncoder, aig.trivial_opt, 3, tt) == ra, hex(tt)
        assert _single_opt(mig.MIGEncoder, mig.trivial_opt, 3, tt) == rm, hex(tt)
        assert multi_aig.opt_multi(3, [tt]) == ra, hex(tt)
        assert multi_mig.opt_multi_via_sat(3, [tt]) == rm, hex(tt)


@needs_kissat
def test_f_and_not_f_cost_opt_f():
    for tt in (0x16, 0x69, 0xE8):
        ra, rm = REF_N3[tt]
        assert multi_aig.opt_multi(3, [tt, tt ^ 0xFF]) == ra, hex(tt)
        assert multi_mig.opt_multi_via_sat(3, [tt, tt ^ 0xFF]) == rm, hex(tt)


def test_trivial_multi_both_encoders():
    n = 3
    lits = [S.input_tt(n, j) for j in (1, 2, 3)]
    assert multi_aig.trivial_multi(n, [0, 0xFF] + lits + [l ^ 0xFF for l in lits])
    assert multi_mig.trivial_multi(n, [0, 0xFF] + lits)
    assert not multi_aig.trivial_multi(n, lits + [0x96])
    assert not multi_mig.trivial_multi(n, [0x80])
