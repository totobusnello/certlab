"""
NPN canonicalisation (n=4) for lookup in the certified census.

The census CSV (data/npn4/npn4_opt_aig.csv) carries only the class representatives, without the
classification code. This module implements it by brute force (n=4 => 4! * 2^4 * 2 = 768
transformations, trivial) and VALIDATES it by self-consistency before use:
  (a) every representative in the CSV is a fixed point of the canonicalisation
      (i.e. it is already the minimum of its class under the same convention);
  (b) classifying all 65536 functions of 4 variables yields EXACTLY 222 classes,
      and the set of representatives equals the set in the CSV.
If (a) or (b) fails, the canonicalisation convention is incompatible with the CSV and the lookup
must not be used: validate() raises ValueError.

Convention: tt is a 16-bit integer, bit t = f(row t), input x_j = bit j-1 of t (the same
convention as the encoders). The canonical representative is the smallest integer in the class.
The CSV location can be overridden with $CERTLAB_NPN4_CSV.
"""
import csv
import itertools
import os

HERE = os.path.dirname(os.path.abspath(__file__))
CENSUS_CSV = os.environ.get("CERTLAB_NPN4_CSV", os.path.join(HERE, "..", "..", "data", "npn4", "npn4_opt_aig.csv"))

N = 4
ROWS = 1 << N  # 16


def _permute_inputs(tt, perm):
    """tt: 16-bit int (function of 4 variables). perm: tuple with a permutation of (0,1,2,3)."""
    out = 0
    for t in range(ROWS):
        bits = [(t >> i) & 1 for i in range(N)]
        t2 = 0
        for new_pos, old_pos in enumerate(perm):
            t2 |= bits[old_pos] << new_pos
        if (tt >> t) & 1:
            out |= 1 << t2
    return out


def _negate_input(tt, j):
    """Inverts variable j (0-indexed) in the truth table."""
    out = 0
    for t in range(ROWS):
        t2 = t ^ (1 << j)
        if (tt >> t) & 1:
            out |= 1 << t2
    return out


def _negate_output(tt):
    return ((1 << ROWS) - 1) ^ tt


_PERMS = list(itertools.permutations(range(N)))


def npn_canon(tt):
    """Smallest tt (int) over all 4! * 2^4 * 2 = 768 NPN transformations."""
    best = None
    for perm in _PERMS:
        t1 = _permute_inputs(tt, perm)
        for negmask in range(1 << N):
            t2 = t1
            m = negmask
            j = 0
            while m:
                if m & 1:
                    t2 = _negate_input(t2, j)
                m >>= 1
                j += 1
            for out_neg in (0, 1):
                t3 = _negate_output(t2) if out_neg else t2
                if best is None or t3 < best:
                    best = t3
    return best


def load_census():
    rows = list(csv.DictReader(open(CENSUS_CSV)))
    census = {}
    for r in rows:
        # `raise`, not `assert`: these checks ARE the validation promised above, and
        # `python -O` strips asserts.
        if r["status"] != "exact":
            raise ValueError(f"non-exact row in the census: {r}")
        census[int(r["npn_rep_dec"])] = int(r["opt_aig"])
    return census, rows


def validate():
    census, rows = load_census()
    # (a) every representative is a fixed point
    for r in rows:
        dec = int(r["npn_rep_dec"])
        c = npn_canon(dec)
        if c != dec:
            raise ValueError(f"rep {r['npn_rep_hex']} (dec={dec}) is not a fixed point: canon={c:#06x}")
    # (b) classifying the 65536 functions yields exactly the classes of the CSV
    seen = set()
    for tt in range(1 << ROWS):
        seen.add(npn_canon(tt))
    csv_reps = set(census.keys())
    if seen != csv_reps:
        raise ValueError(
            f"class sets diverge: {len(seen)} canonicalised vs "
            f"{len(csv_reps)} in the CSV; diff={seen.symmetric_difference(csv_reps)}"
        )
    return census


def opt_lookup(census, tt):
    """Certified opt(f) for the function tt (16 bits), through NPN canonicalisation."""
    c = npn_canon(tt)
    if c not in census:
        raise ValueError(f"canonical class {c:#06x} missing from the census (cannot happen after validate)")
    return census[c], c


if __name__ == "__main__":
    census = validate()
    print(f"[VALIDATE] {len(census)} NPN4 classes — fixed points OK, "
          f"classification of 65536 functions matches the CSV 1:1.")
