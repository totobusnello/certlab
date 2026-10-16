"""Validation gates for the MIG encoder (modelled on gate_xag.py).

M1: n=2 — AND2=OR2=1 (MAJ with a constant); n=2 complete with opt <= 3.
M2: n=3 COMPLETE — encoder+kissat vs independent exhaustive enumeration +
    invariants: opt_MIG <= opt_AIG (256), MAJ3 = 1, sampled NPN.
"""
import sys
import os
import time
import random
from itertools import combinations, permutations
from collections import Counter, deque

from certlab.encoders.mig import opt_via_sat, trivial_opt
from certlab.encoders import aig as aig_exact

# ---------- M1 ----------
print("== M1: n=2 ==", flush=True)
AND2, OR2, XOR2 = 0b1000, 0b1110, 0b0110
assert opt_via_sat(2, AND2, kmax=3) == 1
assert opt_via_sat(2, OR2, kmax=3) == 1
x2 = opt_via_sat(2, XOR2, kmax=4)
o2 = {tt: opt_via_sat(2, tt, kmax=4) for tt in range(16)}
assert all(v is not None for v in o2.values())
print(f"M1 OK: AND2=OR2=1, XOR2={x2}; n=2 max = {max(o2.values())}")

# ---------- M2a: exhaustive enumeration n=3 ----------
print("== M2a: exhaustive MIG enumeration n=3 ==", flush=True)
N, ROWS = 3, 8
MASK = (1 << ROWS) - 1
t0 = time.time()
lits = [sum(1 << t for t in range(ROWS) if (t >> j) & 1) for j in range(N)]
base = tuple(sorted({0, *lits}))  # constant-0 + positive literals


def maj(a, b, c):
    return (a & b) | (a & c) | (b & c)


def closure_opt_enum(kmax):
    best = {}
    seen = {base}
    dq = deque([(base, 0)])
    while dq:
        nodes, k = dq.popleft()
        for v in nodes:
            best.setdefault(v, k)
        if k == kmax:
            continue
        news = set()
        for a, b, c in combinations(nodes, 3):
            for va in (a, a ^ MASK):
                for vb in (b, b ^ MASK):
                    for vc in (c, c ^ MASK):
                        news.add(maj(va, vb, vc))
        for g in news:
            ns = tuple(sorted(set(nodes) | {g}))
            if ns not in seen:
                seen.add(ns)
                dq.append((ns, k + 1))
    out = {}
    for f in range(1 << ROWS):
        out[f] = min(best.get(f, 99), best.get(f ^ MASK, 99))
    return out


KMAX_ENUM = 3
enum_opt = closure_opt_enum(KMAX_ENUM)
n_cov = sum(1 for f in range(256) if enum_opt[f] <= KMAX_ENUM)
print(f"M2a: enumeration up to k={KMAX_ENUM} covers {n_cov}/256 [{time.time()-t0:.0f}s]", flush=True)

# ---------- M2b: encoder+kissat on all 256 ----------
print("== M2b: encoder+kissat n=3 completo ==", flush=True)
t1 = time.time()
sat_opt = {}
for f in range(256):
    sat_opt[f] = opt_via_sat(3, f, kmax=8)
    assert sat_opt[f] is not None, f"{f:#04x} has no opt"
print(f"M2b: 256/256 em [{time.time()-t1:.0f}s]; max opt_MIG(n=3) = {max(sat_opt.values())}", flush=True)

# ---------- M2c: cross-checks ----------
mism = [f for f in range(256) if enum_opt[f] <= KMAX_ENUM and enum_opt[f] != sat_opt[f]]
assert not mism, f"enum != sat: {[(hex(f), enum_opt[f], sat_opt[f]) for f in mism[:5]]}"
mism2 = [f for f in range(256) if enum_opt[f] > KMAX_ENUM and sat_opt[f] <= KMAX_ENUM]
assert not mism2, f"sat < enum exaustiva: {[hex(f) for f in mism2[:5]]}"
print("M2c(i): enum <-> sat consistent in both directions ✓")

# opt_MIG <= opt_AIG (AND is MAJ with a constant ⟹ every AIG maps gate-for-gate to a MIG)
import subprocess, tempfile
aig_opt = {}
for f in range(256):
    if aig_exact.trivial_opt(3, f):
        aig_opt[f] = 0
        continue
    for k in range(1, 9):
        enc = aig_exact.AIGEncoder(3, k, f).build()
        if any(len(c) == 0 for c in enc.clauses):
            continue
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
assert not viol, f"opt_MIG > opt_AIG em {[hex(v) for v in viol[:5]]}"
n_b = sum(1 for f in range(256) if sat_opt[f] < aig_opt[f])
print(f"M2c(ii): opt_MIG <= opt_AIG on all 256 ✓ (strictly better on {n_b})")

MAJ3 = 0
for t in range(8):
    if bin(t).count("1") >= 2:
        MAJ3 |= 1 << t
assert sat_opt[MAJ3] == 1, f"opt_MIG(MAJ3) = {sat_opt[MAJ3]} != 1"
print(f"M2c(iii): opt_MIG(MAJ3) = 1 ✓ | opt_MIG(par3) = {sat_opt[0x96]}")

random.seed(20260713)
def apply_pn(tt, perm, neg):
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
    assert sat_opt[f] == sat_opt[apply_pn(f, perm, neg)]
print("M2c(iv): sampled NPN invariance ✓")

print(f"\nDistribution of opt_MIG at n=3: {sorted(Counter(sat_opt.values()).items())}")
print("\nGATE M1+M2: PASSED")
