"""Multi-output AIG exact synthesis via SAT, an extension of certlab.encoders.aig.

Model: k AND-2 gates with free edge polarities; m outputs, each selecting ONE node (the constant 0,
an input, or a gate) plus an output polarity. Cost = k, the number of AND gates, counted once even
when several outputs use the same gate (sharing between outputs is where the gain is).

Normalisations (sound for an ascending search, same argument as the single-output encoder):
- gate dedup: a MINIMUM multi-output circuit has no two identical gates (dropping the duplicate and
  rewiring its consumers and outputs gives a smaller circuit);
- every gate is used by another gate OR selected by some output.

Truth-table convention: the certlab one (see certlab.encoders): bit t of each tt is the output on
row t, and input x_j is bit j-1 of t. The research script this module was translated from read
x_j as bit n-j of t (x_1 the most significant bit), matching the external database it audited.
The size of a minimum circuit is invariant under a permutation of the inputs, so no size changes;
the decoded circuit is now read in the same convention as every other certlab module, and the
independent simulator certlab.simulate.check_multi checks it in that convention.

Validation, run by the test suite: with m = 1 the encoder reproduces the single-output AIG size,
and (f, ~f) costs opt(f).

Every SAT answer is decoded and checked twice before it is returned: by `verify_multi` below, which
shares the encoder's conventions, and by certlab.simulate.check_multi, which imports nothing from
the encoders. Lower bounds (UNSAT) rest on kissat's verdict; this module writes plain CNF and
produces no DRAT proof.
"""
import subprocess
import tempfile
import os
from itertools import combinations

from certlab.simulate import check_multi
from certlab.encoders._multi_common import check_tables, kissat_verdict


def tt_bit(tt, t):
    return (tt >> t) & 1


class MultiAIGEncoder:
    def __init__(self, n, k, tts):
        self.n, self.k = n, k
        self.tts = check_tables(n, tts)
        self.m = len(self.tts)
        self.rows = 1 << n
        self.nvars = 0
        self.clauses = []
        self.v = {(i, t): self._new() for i in range(1, k + 1) for t in range(self.rows)}
        self.options = {}
        for i in range(1, k + 1):
            opts = []
            nodes = list(range(1, self.n + i))
            for a, b in combinations(nodes, 2):
                for pa in (0, 1):
                    for pb in (0, 1):
                        opts.append((a, pa, b, pb, self._new()))
            self.options[i] = opts
        # output selection: node 0 = constant 0; 1..n inputs; n+1..n+k gates
        self.osel = {}   # (o, node) -> var
        self.opol = {}   # o -> var
        for o in range(self.m):
            for node in range(0, self.n + k + 1):
                self.osel[(o, node)] = self._new()
            self.opol[o] = self._new()

    def _new(self):
        self.nvars += 1
        return self.nvars

    def _lit(self, node, pol, t):
        if node <= self.n:
            # x_j = bit j-1 of t (certlab convention; see the module docstring)
            bit = 0 if node == 0 else (t >> (node - 1)) & 1
            return "const", bit ^ pol
        var = self.v[(node - self.n, t)]
        return "lit", (-var if pol else var)

    def build(self):
        c = self.clauses
        # gates (identical to the single-output encoder)
        for i in range(1, self.k + 1):
            svars = [o[4] for o in self.options[i]]
            c.append(svars)
            c.extend([-x, -y] for x, y in combinations(svars, 2))
            for a, pa, b, pb, s in self.options[i]:
                for t in range(self.rows):
                    x = self.v[(i, t)]
                    ka, la = self._lit(a, pa, t)
                    kb, lb = self._lit(b, pb, t)
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
        # dedup across gates
        by_tuple = {}
        for i in range(1, self.k + 1):
            for a, pa, b, pb, s in self.options[i]:
                by_tuple.setdefault((a, pa, b, pb), []).append(s)
        for svars in by_tuple.values():
            if len(svars) > 1:
                c.extend([-x, -y] for x, y in combinations(svars, 2))
        # output selection: one-hot per output
        for o in range(self.m):
            sv = [self.osel[(o, node)] for node in range(0, self.n + self.k + 1)]
            c.append(sv)
            c.extend([-x, -y] for x, y in combinations(sv, 2))
        # semantics of output o at row t: sel(node) -> (value(node) ^ opol) == tt_o(t)
        for o in range(self.m):
            po = self.opol[o]
            for node in range(0, self.n + self.k + 1):
                s = self.osel[(o, node)]
                for t in range(self.rows):
                    want = tt_bit(self.tts[o], t)
                    kd, val = self._lit(node, 0, t)
                    if kd == "const":
                        # (val ^ pol) == want  <=>  pol == (val ^ want)
                        need_pol = val ^ want
                        c.append([-s, po] if need_pol else [-s, -po])
                    else:
                        x = val  # the gate variable
                        if want:  # x ^ pol = 1
                            c.append([-s, -po, -x]); c.append([-s, po, x])
                        else:
                            c.append([-s, -po, x]); c.append([-s, po, -x])
        # every gate used: by another gate, or by an output selection
        for i in range(1, self.k + 1):
            node = self.n + i
            users = [op[4] for j in range(i + 1, self.k + 1)
                     for op in self.options[j] if op[0] == node or op[2] == node]
            users += [self.osel[(o, node)] for o in range(self.m)]
            c.append(users if users else [])
        return self

    def decode(self, model):
        pos = {abs(l) for l in model if l > 0}
        gates = []
        for i in range(1, self.k + 1):
            sel = [o for o in self.options[i] if o[4] in pos]
            # `raise`, not `assert` (stripped by `python -O`).
            if len(sel) != 1:
                raise ValueError(f"gate {i}: {len(sel)} active options")
            gates.append(sel[0][:4])
        outs = []
        for o in range(self.m):
            nodes = [node for node in range(0, self.n + self.k + 1) if self.osel[(o, node)] in pos]
            if len(nodes) != 1:
                raise ValueError(f"output {o}: {len(nodes)} selected nodes")
            outs.append((nodes[0], self.opol[o] in pos))
        return gates, outs


def simulate_multi(n, gates, outs, t):
    # Not an independent check: it lives next to the encoder and shares its bit convention.
    # The independent check is certlab.simulate.check_multi.
    vals = {0: 0}
    for j in range(1, n + 1):
        vals[j] = (t >> (j - 1)) & 1  # x_j = bit j-1 of t (see _lit)
    node = n
    for a, pa, b, pb in gates:
        node += 1
        vals[node] = (vals[a] ^ pa) & (vals[b] ^ pb)
    return [vals[nd] ^ (1 if pol else 0) for nd, pol in outs]


def verify_multi(n, tts, gates, outs):
    if len(outs) != len(tts):
        return False
    for t in range(1 << n):
        got = simulate_multi(n, gates, outs, t)
        for o, tt in enumerate(tts):
            if got[o] != tt_bit(tt, t):
                return False
    return True


def trivial_multi(n, tts):
    """Is k = 0 enough? Every output must be a constant or a +/- literal."""
    tts = check_tables(n, tts)
    rows = 1 << n
    mask = (1 << rows) - 1
    cands = {0, mask}
    for j in range(n):
        # x_{j+1} = bit j of t, aligned with _lit and simulate_multi. The predicate itself is
        # invariant under input order (the set {const, +/-x_i} is the same).
        v = sum(1 << t for t in range(rows) if (t >> j) & 1)
        cands |= {v, v ^ mask}
    return all(tt in cands for tt in tts)


def solve_k(n, tts, k, timeout=None):
    """Is there a multi-output AIG with k AND gates for `tts`? Returns (sat, (gates, outs) or None).

    The verdict needs exactly one kissat status line agreeing with the exit code (10 = SAT,
    20 = UNSAT); anything else raises RuntimeError (see _multi_common.kissat_verdict). A SAT model
    is decoded and checked by verify_multi and by the independent certlab.simulate.check_multi
    before it is returned."""
    tts = check_tables(n, tts)
    enc = MultiAIGEncoder(n, k, tts).build()
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
    # `raise`, not `assert`: with `python -O` a solver failure came back as UNSAT.
    if not kissat_verdict(r):
        return False, None
    model = []
    for line in r.stdout.splitlines():
        if line.startswith("v "):
            model.extend(int(x) for x in line[2:].split() if x != "0")
    gates, outs = enc.decode(model)
    if not verify_multi(n, tts, gates, outs):
        raise RuntimeError("SAT model does not reproduce the truth tables")
    if not check_multi("aig", n, tts, gates, outs):
        raise RuntimeError("SAT model rejected by the independent simulator (certlab.simulate)")
    return True, (gates, outs)


def opt_multi(n, tts, kmax=15, timeout=None):
    """Smallest k such that a multi-output AIG for `tts` exists, by an ascending search from
    k = 0; None if no k <= kmax is SAT."""
    tts = check_tables(n, tts)
    if trivial_multi(n, tts):
        return 0
    for k in range(1, kmax + 1):
        sat, _ = solve_k(n, tts, k, timeout=timeout)
        if sat:
            return k
    return None
