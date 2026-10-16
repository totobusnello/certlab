"""Validation gates for the XAG encoder (pre-registered before the n = 4 census).

X1: sanity n=2 — AND2 and XOR2 have opt=1; the 16 functions of n=2 check against obvious values.
X2: n=3 COMPLETE — opt_XAG of all 256 functions by encoder+kissat, cross-checked against:
    (a) INDEPENDENT exhaustive enumeration of XAG circuits (BFS over node sets,
        k as far as it fits — expected to cover all 256, opt_XAG(n=3) should be small);
    (b) invariants: opt_XAG <= opt_AIG (the n=3 AIG table recomputed here by the
        validated AIG encoder), opt_XAG(par3)=2, sampled NPN invariance.
"""
import sys
import os
import time
from itertools import combinations, permutations

from certlab.encoders.xag import opt_via_sat, trivial_opt
from certlab.encoders import aig as aig_exact

# ---------- X1: n=2 ----------
print("== X1: n=2 ==", flush=True)
AND2 = 0b1000  # rows t=0..3, bit t = (t0 AND t1)
XOR2 = 0b0110
assert opt_via_sat(2, AND2, kmax=3) == 1, "AND2 != 1"
assert opt_via_sat(2, XOR2, kmax=3) == 1, "XOR2 != 1 (the XOR gate is not working)"
o2 = {tt: opt_via_sat(2, tt, kmax=4) for tt in range(16)}
assert all(v is not None and v <= 2 for v in o2.values()), o2
n_trivial = sum(1 for tt in range(16) if trivial_opt(2, tt))
print(f"X1 OK: AND2=1, XOR2=1; n=2 completo: {sorted(set(o2.values()))} (max {max(o2.values())}), {n_trivial} triviais")

# ---------- X2a: independent exhaustive enumeration (n=3) ----------
print("== X2a: exhaustive XAG enumeration n=3 ==", flush=True)
N, ROWS = 3, 8
MASK = (1 << ROWS) - 1
t0 = time.time()
# BFS state: frozenset of available tts (closure under input complement already
# absorbed: we start from POSITIVE literals and the constant; AND carries explicit polarities)
lits = []
for j in range(N):
    lits.append(sum(1 << t for t in range(ROWS) if (t >> j) & 1))
base = tuple(sorted({0, *lits}))  # constant-0 and literals (complements come from the polarities)


def closure_opt_enum(kmax):
    """Exact opt by BFS over multisets of computed values.
    State = sorted tuple of tts of the nodes built so far; cost = number of gates.
    Prune: memo by set (equivalent states)."""
    from collections import deque
    best = {}
    start = base
    seen = {start}
    dq = deque([(start, 0)])
    while dq:
        nodes, k = dq.popleft()
        for v in nodes:
            for w in (v, v ^ MASK):
                for f in (w,):
                    best.setdefault(f, k)
        # expand
        if k == kmax:
            continue
        avail = nodes
        newstates = set()
        for a, b in combinations(avail, 2):
            for va in (a, a ^ MASK):
                for vb in (b, b ^ MASK):
                    newstates.add(va & vb)
            newstates.add(a ^ b)
        for g in newstates:
            ns = tuple(sorted(set(nodes) | {g}))
            if ns not in seen:
                seen.add(ns)
                dq.append((ns, k + 1))
    # closure under output complement
    out = {}
    for f in range(1 << ROWS):
        c = min(best.get(f, 99), best.get(f ^ MASK, 99))
        out[f] = c
    return out


KMAX_ENUM = 4
enum_opt = closure_opt_enum(KMAX_ENUM)
n_cov = sum(1 for f in range(256) if enum_opt[f] <= KMAX_ENUM)
print(f"X2a: enumeration up to k={KMAX_ENUM} covers {n_cov}/256 functions [{time.time()-t0:.0f}s]", flush=True)

# ---------- X2b: encoder+kissat on all 256 ----------
print("== X2b: encoder+kissat n=3 completo ==", flush=True)
t1 = time.time()
sat_opt = {}
for f in range(256):
    sat_opt[f] = opt_via_sat(3, f, kmax=8)
    assert sat_opt[f] is not None, f"{f:#04x} has no opt up to k=8"
print(f"X2b: 256/256 em [{time.time()-t1:.0f}s]; max opt_XAG(n=3) = {max(sat_opt.values())}", flush=True)

# ---------- X2c: cross-checks ----------
print("== X2c: cross-checks ==", flush=True)
# (i) enum vs sat where the enumeration reaches
mism = [f for f in range(256) if enum_opt[f] <= KMAX_ENUM and enum_opt[f] != sat_opt[f]]
assert not mism, f"enum != sat em {[(hex(f), enum_opt[f], sat_opt[f]) for f in mism[:5]]}"
# and where the enumeration does NOT reach, sat must be > KMAX_ENUM
mism2 = [f for f in range(256) if enum_opt[f] > KMAX_ENUM and sat_opt[f] <= KMAX_ENUM]
assert not mism2, f"sat found k<=%d where exhaustive enum did not: {mism2[:5]}" % KMAX_ENUM
# (ii) opt_XAG <= opt_AIG on all 256 (AIG via the validated encoder)
t2 = time.time()
aig_opt = {}
for f in range(256):
    if aig_exact.trivial_opt(3, f):
        aig_opt[f] = 0
        continue
    for k in range(1, 9):
        enc = aig_exact.AIGEncoder(3, k, f).build()
        if any(len(c) == 0 for c in enc.clauses):
            continue
        import subprocess, tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".cnf", delete=False) as fh:
            p = fh.name
            fh.write(f"p cnf {enc.nvars} {len(enc.clauses)}\n")
            for cl in enc.clauses:
                fh.write(" ".join(map(str, cl)) + " 0\n")
        rc = subprocess.run(["kissat", "-q", p], capture_output=True).returncode
        os.unlink(p)
        if rc == 10:
            aig_opt[f] = k
            break
        assert rc == 20
viol = [f for f in range(256) if sat_opt[f] > aig_opt[f]]
assert not viol, f"opt_XAG > opt_AIG em {[hex(v) for v in viol[:5]]}"
n_better = sum(1 for f in range(256) if sat_opt[f] < aig_opt[f])
print(f"X2c(ii): opt_XAG <= opt_AIG on all 256 ✓; XAG strictly better on {n_better} functions [{time.time()-t2:.0f}s]")
# (iii) parity-3
assert sat_opt[0x96] == 2, f"opt_XAG(par3) = {sat_opt[0x96]} != 2"
print(f"X2c(iii): opt_XAG(par3) = 2 ✓ (AIG era {aig_opt[0x96]})")
# (iv) sampled NPN invariance: permute/negate inputs of 10 functions and compare
import random
random.seed(20260713)
def apply_perm_neg(tt, perm, neg):
    g = 0
    for t in range(ROWS):
        u = 0
        for j in range(N):
            bit = (t >> j) & 1
            if (neg >> j) & 1:
                bit ^= 1
            u |= bit << perm[j]
        if (tt >> u) & 1:
            g |= 1 << t
    return g
for _ in range(10):
    f = random.randrange(256)
    perm = list(random.choice(list(permutations(range(N)))))
    neg = random.randrange(8)
    g = apply_perm_neg(f, perm, neg)
    assert sat_opt[f] == sat_opt[g], f"NPN quebrada: {f:#04x}->{g:#04x}"
print("X2c(iv): sampled NPN invariance (10 transformations) ✓")

from collections import Counter
print(f"\nDistribution of opt_XAG at n=3 (256 functions): {sorted(Counter(sat_opt.values()).items())}")
print(f"Distribution of opt_AIG at n=3 (256 functions): {sorted(Counter(aig_opt.values()).items())}")
print("\nGATE X1+X2: PASSED")
