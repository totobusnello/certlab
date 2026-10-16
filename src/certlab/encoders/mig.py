"""MIG exact synthesis via SAT -- MAJ-3 gates with polarities on the edges, a constant-0 node
available as an input (MAJ(a,b,0)=AND, MAJ(a,b,1)=OR), free output negation. Cost = number of MAJ
gates. Modelled on certlab.encoders.xag.

Pre-registered replication: the published target distribution (the MIG catalogue of the DATE 2016
exact-synthesis paper, Table I; see README) = {0:2, 1:2, 2:5, 3:18, 4:42, 5:117, 6:35, 7:1} over
the 222 NPN classes of n = 4.
"""
import subprocess
import tempfile
import os
from itertools import combinations


def tt_bit(tt, t):
    return (tt >> t) & 1


class MIGEncoder:
    def __init__(self, n, k, tt, formula=False):
        # formula=True => tree (fan-out 1 at every internal gate, no dedup):
        # computes tree_MIG(f). Default False => DAG (opt_MIG), the validated behaviour.
        self.n, self.k, self.tt = n, k, tt
        self.formula = formula
        self.rows = 1 << n
        self.nvars = 0
        self.clauses = []
        self.v = {(i, t): self._new() for i in range(1, k + 1) for t in range(self.rows)}
        # nodes: 0 = constant-0; 1..n = inputs; n+j = gate j
        # option: (a, pa, b, pb, c, pc, s) with a<b<c
        self.options = {}
        for i in range(1, k + 1):
            opts = []
            nodes = list(range(0, self.n + i))  # includes the constant node
            for a, b, c in combinations(nodes, 3):
                for pa in (0, 1):
                    for pb in (0, 1):
                        for pc in (0, 1):
                            opts.append((a, pa, b, pb, c, pc, self._new()))
            self.options[i] = opts
        self.out_pol = self._new()

    def _new(self):
        self.nvars += 1
        return self.nvars

    def _lit(self, node, pol, t):
        """('const', 0|1) or ('lit', +-var)."""
        if node == 0:
            return "const", pol  # constant-0 with polarity
        if node <= self.n:
            bit = (t >> (node - 1)) & 1
            return "const", bit ^ pol
        var = self.v[(node - self.n, t)]
        return "lit", (-var if pol else var)

    def _maj_clauses(self, s, x, lits):
        """x <-> MAJ(l1,l2,l3), conditioned on s. lits = [(kind, val), ...].
        Templates: for each pair {li,lj}: (NOT x OR li OR lj) and (x OR NOT li OR NOT lj)."""
        out = []
        # 3 clauses (-x, li, lj) and 3 (x, -li, -lj), with constants simplified
        for i, j in combinations(range(3), 2):
            # (-s, -x, li, lj)
            cl = [-s, -x]
            sat = False
            for idx in (i, j):
                kind, val = lits[idx]
                if kind == "const":
                    if val == 1:
                        sat = True
                        break
                else:
                    cl.append(val)
            if not sat:
                out.append(cl)
            # (-s, x, -li, -lj)
            cl = [-s, x]
            sat = False
            for idx in (i, j):
                kind, val = lits[idx]
                if kind == "const":
                    if val == 0:
                        sat = True
                        break
                else:
                    cl.append(-val)
            if not sat:
                out.append(cl)
        return out

    def build(self):
        c = self.clauses
        for i in range(1, self.k + 1):
            svars = [o[6] for o in self.options[i]]
            c.append(svars)
            c.extend([-x, -y] for x, y in combinations(svars, 2))
            for a, pa, b, pb, cc, pc, s in self.options[i]:
                for t in range(self.rows):
                    x = self.v[(i, t)]
                    lits = [self._lit(a, pa, t), self._lit(b, pb, t), self._lit(cc, pc, t)]
                    c.extend(self._maj_clauses(s, x, lits))
        # dedup across gates (minimality -- holds for identical MAJ gates). In a formula (tree),
        # identical gates are NECESSARY (duplicating a subresult is exactly the cost of the
        # tree), so the dedup applies to the DAG only.
        if not self.formula:
            by_tuple = {}
            for i in range(1, self.k + 1):
                for a, pa, b, pb, cc, pc, s in self.options[i]:
                    by_tuple.setdefault((a, pa, b, pb, cc, pc), []).append(s)
            for svars in by_tuple.values():
                if len(svars) > 1:
                    c.extend([-x, -y] for x, y in combinations(svars, 2))
        # every gate i<k used. In formula mode, fan-out EXACTLY 1 (tree):
        # adds at-most-one among the consumers.
        for i in range(1, self.k):
            node = self.n + i
            users = [o[6] for j in range(i + 1, self.k + 1)
                     for o in self.options[j] if node in (o[0], o[2], o[4])]
            c.append(users if users else [])
            if self.formula:
                c.extend([-x, -y] for x, y in combinations(users, 2))
        # output
        op = self.out_pol
        for t in range(self.rows):
            x = self.v[(self.k, t)]
            if tt_bit(self.tt, t):
                c.append([op, x]); c.append([-op, -x])
            else:
                c.append([op, -x]); c.append([-op, x])
        return self

    def decode(self, model):
        pos = {abs(l) for l in model if l > 0}
        gates = []
        for i in range(1, self.k + 1):
            sel = [o for o in self.options[i] if o[6] in pos]
            # `raise`, not `assert` (stripped by `python -O`).
            if len(sel) != 1:
                raise ValueError(f"gate {i}: {len(sel)} active options")
            gates.append(sel[0][:6])
        return gates, (self.out_pol in pos)


def simulate(n, gates, out_pol, t):
    vals = {0: 0}
    for j in range(1, n + 1):
        vals[j] = (t >> (j - 1)) & 1
    node = n
    for a, pa, b, pb, c, pc in gates:
        node += 1
        va, vb, vc = vals[a] ^ pa, vals[b] ^ pb, vals[c] ^ pc
        vals[node] = 1 if va + vb + vc >= 2 else 0
    return vals[node] ^ (1 if out_pol else 0)


def verify_circuit(n, tt, gates, out_pol):
    return all(simulate(n, gates, out_pol, t) == tt_bit(tt, t) for t in range(1 << n))


def trivial_opt(n, tt):
    rows = 1 << n
    mask = (1 << rows) - 1
    cands = {0, mask}
    for j in range(n):
        v = sum(1 << t for t in range(rows) if (t >> j) & 1)
        cands |= {v, v ^ mask}
    return tt in cands


def solve_k(n, tt, k, return_circuit=False, timeout=None, formula=False):
    """formula=True searches for a FORMULA (tree) => answers 'tree <= k'.

    kissat exit code 10 = SAT, 20 = UNSAT; any other exit code raises RuntimeError (neither
    verdict -- see certlab.encoders.xag.solve_k)."""
    enc = MIGEncoder(n, k, tt, formula=formula).build()
    if any(len(cl) == 0 for cl in enc.clauses):
        return False, None
    with tempfile.NamedTemporaryFile("w", suffix=".cnf", delete=False) as f:
        path = f.name
        f.write(f"p cnf {enc.nvars} {len(enc.clauses)}\n")
        for cl in enc.clauses:
            f.write(" ".join(map(str, cl)) + " 0\n")
    try:
        r = subprocess.run(["kissat", "-q", path], capture_output=True,
                           text=True, timeout=timeout)
    finally:
        os.unlink(path)
    if r.returncode == 10:
        if not return_circuit:
            return True, None
        model = []
        for line in r.stdout.splitlines():
            if line.startswith("v "):
                model.extend(int(x) for x in line[2:].split() if x != "0")
        gates, out_pol = enc.decode(model)
        if not verify_circuit(n, tt, gates, out_pol):
            raise RuntimeError("SAT model does not simulate! bug")
        return True, (gates, out_pol)
    # `raise`, not `assert`: with `python -O` a solver failure came back as UNSAT.
    if r.returncode != 20:
        raise RuntimeError(f"kissat rc={r.returncode}")
    return False, None


def opt_via_sat(n, tt, kmax=10, timeout=None, verify=True):
    if trivial_opt(n, tt):
        return 0
    for k in range(1, kmax + 1):
        sat, _ = solve_k(n, tt, k, return_circuit=verify, timeout=timeout)
        if sat:
            return k
    return None


def tree_via_sat(n, tt, kmax=20, timeout=None, verify=True, start=1):
    """Smallest MIG FORMULA (tree) for tt = tree_MIG(f). Ascending search with the encoder in
    formula mode (fan-out 1, no dedup). `start` allows beginning from opt_MIG (tree >= opt
    always)."""
    if trivial_opt(n, tt):
        return 0
    for k in range(max(1, start), kmax + 1):
        sat, _ = solve_k(n, tt, k, return_circuit=verify, timeout=timeout, formula=True)
        if sat:
            return k
    return None
