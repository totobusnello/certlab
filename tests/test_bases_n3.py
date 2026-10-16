"""Agreement between bases at n = 3, and the AIG encoder against an independent enumeration.

- opt_XAG <= opt_AIG and opt_MIG <= opt_AIG (an AND gate is an XAG gate and a MAJ with a constant),
  checked on one representative of each of the 14 NPN classes of 3-input functions (exact size is
  NPN-invariant in all three bases, since inversions are free). The full 256-function version of
  these inequalities runs inside tests/gates/ (slow).
- opt_AIG from the encoder equals the size found by an independent breadth-first enumeration of
  AND/inverter circuits (no SAT, no shared code), wherever the enumeration reaches.
"""
import itertools
import os
import subprocess
import tempfile
from collections import deque

from conftest import needs_kissat
from certlab.encoders import aig, xag, mig

N, ROWS = 3, 8
MASK = (1 << ROWS) - 1


def npn3_reps():
    reps = set()
    for tt in range(1 << ROWS):
        best = None
        for perm in itertools.permutations(range(N)):
            for neg in range(1 << N):
                g = 0
                for t in range(ROWS):
                    u = 0
                    for j in range(N):
                        u |= (((t >> j) & 1) ^ ((neg >> j) & 1)) << perm[j]
                    if (tt >> u) & 1:
                        g |= 1 << t
                for h in (g, g ^ MASK):
                    best = h if best is None or h < best else best
        reps.add(best)
    return sorted(reps)


def opt_kissat(encoder_cls, trivial, tt, kmax=8):
    if trivial(N, tt):
        return 0
    for k in range(1, kmax + 1):
        enc = encoder_cls(N, k, tt).build()
        if any(len(c) == 0 for c in enc.clauses):
            continue
        with tempfile.NamedTemporaryFile("w", suffix=".cnf", delete=False) as fh:
            fh.write(f"p cnf {enc.nvars} {len(enc.clauses)}\n")
            fh.writelines(" ".join(map(str, c)) + " 0\n" for c in enc.clauses)
        rc = subprocess.run(["kissat", "-q", fh.name], capture_output=True).returncode
        os.unlink(fh.name)
        if rc == 10:
            return k
        assert rc == 20, rc
    return None


def aig_enum(kmax):
    """Exact AIG size by BFS over sets of computed functions (inverters free)."""
    lits = [sum(1 << t for t in range(ROWS) if (t >> j) & 1) for j in range(N)]
    base = tuple(sorted({0, *lits}))
    best = {}
    seen = {base}
    dq = deque([(base, 0)])
    while dq:
        nodes, k = dq.popleft()
        for v in nodes:
            best.setdefault(v, k)
            best.setdefault(v ^ MASK, k)
        if k == kmax:
            continue
        for a, b in itertools.combinations(nodes, 2):
            for va in (a, a ^ MASK):
                for vb in (b, b ^ MASK):
                    g = va & vb
                    ns = tuple(sorted(set(nodes) | {g}))
                    if ns not in seen:
                        seen.add(ns)
                        dq.append((ns, k + 1))
    return best


@needs_kissat
def test_bases_agree_on_npn3_classes():
    reps = npn3_reps()
    assert len(reps) == 14
    enum = aig_enum(4)
    rows = []
    for tt in reps:
        oa = opt_kissat(aig.AIGEncoder, aig.trivial_opt, tt)
        ox = opt_kissat(xag.XAGEncoder, xag.trivial_opt, tt)
        om = opt_kissat(mig.MIGEncoder, mig.trivial_opt, tt)
        rows.append((tt, oa, ox, om))
        assert ox <= oa and om <= oa, (hex(tt), oa, ox, om)
        if tt in enum:
            assert enum[tt] == oa, (hex(tt), enum[tt], oa)
        else:
            assert oa > 4, (hex(tt), oa)
    par3 = [r for r in rows if r[0] == 0x69 or r[0] == 0x96]
    assert par3 and par3[0][1:] == (6, 2, 3), par3   # parity of 3 inputs: AIG 6, XAG 2, MIG 3
