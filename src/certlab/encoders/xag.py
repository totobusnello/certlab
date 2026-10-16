"""XAG exact synthesis via SAT -- an extension of the AIG encoder (certlab.encoders.aig) with XOR
gates.

XAG basis: each gate is AND(+-a, +-b) OR XOR(a, b) (XOR inputs positive -- negation commutes with
XOR: ~a^b = ~(a^b), so any negation on an XOR input is absorbed by the consumer's polarity or by
the output negation; standard normalisation, no loss of generality). Output negation is free.
Cost = total number of gates.

Inherits from the validated AIG encoder: one-hot options per gate, gate dedup (sound for
minimality: a minimal circuit has no duplicate gates, whatever the gate type), every non-final
gate used, output with polarity.
"""
import subprocess
import tempfile
import os
from itertools import combinations


def tt_bit(tt, t):
    return (tt >> t) & 1


class XAGEncoder:
    def __init__(self, n, k, tt, formula=False):
        # formula=True => tree (fan-out 1 at every internal gate, no dedup):
        # computes tree_XAG(f). Default False => DAG (opt_XAG), the validated behaviour.
        self.n, self.k, self.tt = n, k, tt
        self.formula = formula
        self.rows = 1 << n
        self.nvars = 0
        self.clauses = []
        self.v = {(i, t): self._new() for i in range(1, k + 1) for t in range(self.rows)}
        # options: AND -> ('and', a, pa, b, pb, s); XOR -> ('xor', a, b, s)
        self.options = {}
        for i in range(1, k + 1):
            opts = []
            nodes = list(range(1, self.n + i))
            for a, b in combinations(nodes, 2):
                for pa in (0, 1):
                    for pb in (0, 1):
                        opts.append(("and", a, pa, b, pb, self._new()))
                opts.append(("xor", a, 0, b, 0, self._new()))
            self.options[i] = opts
        self.out_pol = self._new()

    def _new(self):
        self.nvars += 1
        return self.nvars

    def build(self):
        c = self.clauses
        for i in range(1, self.k + 1):
            svars = [o[5] for o in self.options[i]]
            c.append(svars)
            c.extend([-x, -y] for x, y in combinations(svars, 2))
            for typ, a, pa, b, pb, s in self.options[i]:
                for t in range(self.rows):
                    x = self.v[(i, t)]
                    ka, la = self._lit(a, pa, t)
                    kb, lb = self._lit(b, pb, t)
                    if typ == "and":
                        if (ka == "const" and la == 0) or (kb == "const" and lb == 0):
                            c.append([-s, -x])
                        elif ka == "const" and kb == "const":
                            c.append([-s, x])
                        elif ka == "const":
                            c.append([-s, -x, lb]); c.append([-s, x, -lb])
                        elif kb == "const":
                            c.append([-s, -x, la]); c.append([-s, x, -la])
                        else:
                            c.append([-s, -x, la]); c.append([-s, -x, lb])
                            c.append([-s, x, -la, -lb])
                    else:  # xor: x <-> la ^ lb
                        if ka == "const" and kb == "const":
                            c.append([-s, x] if (la ^ lb) else [-s, -x])
                        elif ka == "const":
                            if la:  # x <-> ~lb
                                c.append([-s, -x, -lb]); c.append([-s, x, lb])
                            else:   # x <-> lb
                                c.append([-s, -x, lb]); c.append([-s, x, -lb])
                        elif kb == "const":
                            if lb:
                                c.append([-s, -x, -la]); c.append([-s, x, la])
                            else:
                                c.append([-s, -x, la]); c.append([-s, x, -la])
                        else:
                            c.append([-s, -x, la, lb]); c.append([-s, -x, -la, -lb])
                            c.append([-s, x, -la, lb]); c.append([-s, x, la, -lb])
        # dedup of identical options across gates (DAG minimality). In a formula (tree),
        # identical gates are NECESSARY (duplicating a subresult is exactly the cost of the
        # tree), so the dedup applies to the DAG only.
        if not self.formula:
            by_tuple = {}
            for i in range(1, self.k + 1):
                for typ, a, pa, b, pb, s in self.options[i]:
                    by_tuple.setdefault((typ, a, pa, b, pb), []).append(s)
            for svars in by_tuple.values():
                if len(svars) > 1:
                    c.extend([-x, -y] for x, y in combinations(svars, 2))
        # every gate i < k is used by some later one (>=1). In formula mode, fan-out is
        # EXACTLY 1 (tree): adds at-most-one among the consumers.
        for i in range(1, self.k):
            users = [o[5] for j in range(i + 1, self.k + 1)
                     for o in self.options[j] if o[1] == self.n + i or o[3] == self.n + i]
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

    def _lit(self, node, pol, t):
        if node <= self.n:
            bit = (t >> (node - 1)) & 1
            return "const", bit ^ pol
        var = self.v[(node - self.n, t)]
        return "lit", (-var if pol else var)

    def decode(self, model):
        pos = {abs(l) for l in model if l > 0}
        gates = []
        for i in range(1, self.k + 1):
            sel = [o for o in self.options[i] if o[5] in pos]
            # `raise`, not `assert` (stripped by `python -O`).
            if len(sel) != 1:
                raise ValueError(f"gate {i}: {len(sel)} active options")
            typ, a, pa, b, pb, _ = sel[0]
            gates.append((typ, a, pa, b, pb))
        return gates, (self.out_pol in pos)


def simulate(n, gates, out_pol, t):
    vals = [(t >> j) & 1 for j in range(n)]  # nodes 1..n
    for typ, a, pa, b, pb in gates:
        va = vals[a - 1] ^ pa
        vb = vals[b - 1] ^ pb
        vals.append((va & vb) if typ == "and" else (va ^ vb))
    return vals[-1] ^ (1 if out_pol else 0)


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
    """SAT: is there an XAG with exactly k gates for tt? (via the minimality lemma, answers
    'opt <= k' when used in an ascending search).
    formula=True searches for a FORMULA (tree) => answers 'tree <= k'.

    The solver verdict is read from kissat's exit code: 10 = SAT, 20 = UNSAT. ANY other exit
    code (crash, signal, missing binary, internal error) raises RuntimeError: it is neither SAT
    nor UNSAT, and reporting it as UNSAT would publish a tool failure as a lower bound."""
    enc = XAGEncoder(n, k, tt, formula=formula).build()
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
            raise RuntimeError("SAT model does not simulate! encoding bug")
        return True, (gates, out_pol)
    # `raise`, not `assert`: with `python -O` the assert vanished and any solver failure
    # (rc=1, a kill signal, ...) came back as (False, None), i.e. as UNSAT.
    if r.returncode != 20:
        raise RuntimeError(f"kissat rc={r.returncode}")
    return False, None


def opt_via_sat(n, tt, kmax=12, timeout=None, verify=True):
    if trivial_opt(n, tt):
        return 0
    for k in range(1, kmax + 1):
        sat, cert = solve_k(n, tt, k, return_circuit=verify, timeout=timeout)
        if sat:
            return k
    return None


def tree_via_sat(n, tt, kmax=20, timeout=None, verify=True, start=1):
    """Smallest XAG FORMULA (tree) for tt = tree_XAG(f). Ascending search with the encoder in
    formula mode (fan-out 1, no dedup). `start` allows beginning from opt (tree >= opt always)."""
    if trivial_opt(n, tt):
        return 0
    for k in range(max(1, start), kmax + 1):
        sat, cert = solve_k(n, tt, k, return_circuit=verify, timeout=timeout, formula=True)
        if sat:
            return k
    return None
