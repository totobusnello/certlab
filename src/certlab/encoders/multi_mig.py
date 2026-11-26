"""Multi-output MIG exact synthesis via SAT (3-input majority gates).

Why multi-output. SUM_n (the binary weight of n inputs) has n inputs and ceil(log2(n+1))
outputs, and the gain is in SHARING between the outputs: a 3:2 compressor produces sum and carry
from the same cone. certlab.encoders.mig is single-output; certlab.encoders.multi_aig shares gates
between outputs but uses AND-2 gates. This module crosses the two. Cost = k, the number of MAJ
gates, counted once even when several outputs use the same gate.

Bit convention: the certlab one, x_j = bit (j-1) of t (x_1 the least significant bit), as in
certlab.encoders.mig. For SUM_n the choice changes no value, since the function is totally
symmetric in its inputs, but it decides how the decoded circuit is read.

The OUTPUTS, unlike the inputs, are not interchangeable: output j is bit j of the Hamming weight.
`sum_tts(n)` returns them from least to most significant.

Two optional reductions of the search, both off by default:
- `fence`: restrict the search to one fence (number of gates per level). Every DAG of k gates
  belongs to exactly one fence, so running all of them covers the space without overlap
  (`fences(k)`); see the comments in __init__ for the condition that makes it a partition.
- `sym_inputs`: the ordered-symmetric-variables break of Haaswijk et al. (TCAD 2020,
  Sec. III-D-6) for groups of mutually symmetric inputs. Its soundness is a lemma about the
  encoding, not something this module checks; a lower bound proved with it is conditional on that
  lemma. The certification chain in certlab does not use it.

Every SAT answer is decoded and checked twice before it is reported: by `verify_multi` below,
which shares the encoder's conventions, and by certlab.simulate.check_multi, which imports nothing
from the encoders. Lower bounds (UNSAT) rest on kissat's verdict; this module writes plain CNF and
produces no DRAT proof.

Library use:
    from certlab.encoders.multi_mig import opt_multi_via_sat, sum_tts
    opt_multi_via_sat(3, sum_tts(3), kmax=4)   # -> 3, the full adder
"""
import subprocess
import tempfile
import os
from itertools import combinations

from certlab.simulate import check_multi
from certlab.encoders._multi_common import check_tables, kissat_verdict


def tt_bit(tt, t):
    return (tt >> t) & 1


def sum_tts(n):
    """Truth tables of SUM_n: output j = bit j of the Hamming weight of the input.

    Returns the bits needed to write n, least significant first. The input convention is the
    module's (x_j = bit j-1 of t); the Hamming weight is symmetric, so the list does not depend
    on it.
    """
    m = max(1, (n).bit_length())        # bits needed to represent n
    tts = []
    for j in range(m):
        tt = 0
        for t in range(1 << n):
            if (bin(t).count("1") >> j) & 1:
                tt |= 1 << t
        tts.append(tt)
    return tts


def fences(k):
    """All fences of k nodes: ORDERED partitions of k into non-empty levels.

    A fence F = (l1,...,ll) says how many gates sit on each level. Every DAG of k nodes
    corresponds to EXACTLY ONE fence (give each node its level in the partial order), so
    sweeping all fences covers the whole space without overlap; that is what makes the
    decomposition correct, not merely faster.

    There are 2^(k-1) fences (compositions of k): 128 for k=8, 1024 for k=11.
    """
    if k == 0:
        yield ()
        return
    for first in range(1, k + 1):
        for rest in fences(k - first):
            yield (first,) + rest


def levels_of(fence):
    """Map gate -> level (1-based), from the fence."""
    level, level_no = {}, 1
    i = 1
    for size in fence:
        for _ in range(size):
            level[i] = level_no
            i += 1
        level_no += 1
    return level


class MultiMIGEncoder:
    def __init__(self, n, k, tts, fence=None, sym_inputs=None):
        self.n, self.k = n, k
        # `fence=None` means no fence; any other value, the empty tuple included, is a fence and
        # must be an ordered partition of k into non-empty levels.
        if fence is not None:
            fence = tuple(fence)
            if any(not isinstance(s, int) or s < 1 for s in fence):
                raise ValueError(f"fence {fence}: every level needs at least one gate")
        self.fence = fence
        # groups of mutually symmetric inputs, e.g. [[1,2,3,4,5]] for SUM_5
        self.sym_inputs = sym_inputs or []
        self.tts = check_tables(n, tts)
        self.m = len(self.tts)
        self.rows = 1 << n
        self.nvars = 0
        self.clauses = []
        # value of gate i on row t
        self.v = {(i, t): self._new() for i in range(1, k + 1) for t in range(self.rows)}
        # nodes: 0 = constant; 1..n = inputs; n+j = gate j
        self.options = {}
        level = levels_of(fence) if fence is not None else None
        if fence is not None:
            if sum(fence) != k:
                raise ValueError(f"fence {fence} does not sum to {k}")
            # last gate of each level, to know what each level "sees"
            last_of_level, acc = {}, 0
            for lv, size in enumerate(fence, start=1):
                acc += size
                last_of_level[lv] = acc
        for i in range(1, k + 1):
            opts = []
            if fence is not None:
                # A gate on level L sees the constant, the inputs, and the gates of STRICTLY
                # earlier levels, and, for L>1, must USE at least one gate of level L-1.
                #
                # The second condition is what makes the fences a partition rather than an
                # overlapping cover: without it the fence (1,1,...,1) is identical to the
                # unrestricted encoding. The level of a node is the LONGEST path to it; a gate
                # that does not touch level L-1 belongs to a lower level and is counted in
                # ANOTHER fence.
                L = level[i]
                visible = last_of_level[L - 1] if L > 1 else 0
                nodes = list(range(0, self.n + 1 + visible))
                if L > 1:
                    floor_ = self.n + 1 + (last_of_level[L - 2] if L > 2 else 0)
                    ceil_ = self.n + 1 + visible          # exclusive
                    previous_level = set(range(floor_, ceil_))
                else:
                    previous_level = None
            else:
                previous_level = None
                nodes = list(range(0, self.n + i))     # includes the constant node
            for a, b, c in combinations(nodes, 3):
                if previous_level is not None and not (previous_level & {a, b, c}):
                    continue          # does not touch level L-1: belongs to another fence
                for pa in (0, 1):
                    for pb in (0, 1):
                        for pc in (0, 1):
                            opts.append((a, pa, b, pb, c, pc, self._new()))
            self.options[i] = opts
        # each output selects ONE node (0..n+k) and a polarity
        self.osel = {(o, node): self._new()
                     for o in range(self.m) for node in range(0, self.n + k + 1)}
        self.opol = {o: self._new() for o in range(self.m)}

    def _new(self):
        self.nvars += 1
        return self.nvars

    def _lit(self, node, pol, t):
        """('const', 0|1) or ('lit', +-var). x_j = bit (j-1) of t, see the module docstring."""
        if node == 0:
            return "const", pol
        if node <= self.n:
            bit = (t >> (node - 1)) & 1
            return "const", bit ^ pol
        return "lit", (lambda var: -var if pol else var)(self.v[(node - self.n, t)])

    def _maj_clauses(self, s, x, lits):
        """x <-> MAJ(l1,l2,l3) conditioned on s. Identical to certlab.encoders.mig."""
        out = []
        for i, j in combinations(range(3), 2):
            cl, sat = [-s, -x], False
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
            cl, sat = [-s, x], False
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
        # --- gates: exactly one option per gate, and its semantics
        for i in range(1, self.k + 1):
            svars = [o[6] for o in self.options[i]]
            c.append(svars)
            c.extend([-x, -y] for x, y in combinations(svars, 2))
            for a, pa, b, pb, cc, pc, s in self.options[i]:
                for t in range(self.rows):
                    lits = [self._lit(a, pa, t), self._lit(b, pb, t), self._lit(cc, pc, t)]
                    c.extend(self._maj_clauses(s, self.v[(i, t)], lits))
        # --- dedup: a MINIMUM circuit has no two identical gates (deleting the duplicate and
        #     rewiring its consumers and outputs gives a smaller circuit)
        by_tuple = {}
        for i in range(1, self.k + 1):
            for a, pa, b, pb, cc, pc, s in self.options[i]:
                by_tuple.setdefault((a, pa, b, pb, cc, pc), []).append(s)
        for svars in by_tuple.values():
            if len(svars) > 1:
                c.extend([-x, -y] for x, y in combinations(svars, 2))
        # --- outputs: one-hot node selection
        for o in range(self.m):
            sv = [self.osel[(o, node)] for node in range(0, self.n + self.k + 1)]
            c.append(sv)
            c.extend([-x, -y] for x, y in combinations(sv, 2))
        # --- semantics of output o on row t
        for o in range(self.m):
            po = self.opol[o]
            for node in range(0, self.n + self.k + 1):
                s = self.osel[(o, node)]
                for t in range(self.rows):
                    want = tt_bit(self.tts[o], t)
                    kd, val = self._lit(node, 0, t)
                    if kd == "const":
                        # (val ^ pol) == want  <=>  pol == (val ^ want)
                        c.append([-s, po] if (val ^ want) else [-s, -po])
                    else:
                        x = val
                        if want:
                            c.append([-s, -po, -x]); c.append([-s, po, x])
                        else:
                            c.append([-s, -po, x]); c.append([-s, po, -x])
        # --- every gate serves someone: another gate, or an output
        for i in range(1, self.k + 1):
            node = self.n + i
            users = [o[6] for j in range(i + 1, self.k + 1)
                     for o in self.options[j] if node in (o[0], o[2], o[4])]
            users += [self.osel[(o, node)] for o in range(self.m)]
            c.append(users if users else [])
        if self.sym_inputs:
            self._break_input_symmetry()
        return self

    def _break_input_symmetry(self):
        """Ordered symmetric variables (Haaswijk et al., TCAD 2020, Sec. III-D-6). If inputs p
        and q are symmetric (p<q), one may require that p is used BEFORE q. For a totally
        symmetric function (SUM_n), ordering CONSECUTIVE pairs (p, p+1) forces the total order.

        The clause: if gate i uses q and not p, then some EARLIER gate uses p. A gate using q
        before p has appeared could be renamed by swapping p and q, and that is exactly the
        solution being discarded. Off by default; see the module docstring.
        """
        c = self.clauses
        self.sym_input_clauses = 0
        for group in self.sym_inputs:
            g = sorted(group)
            for p, q in zip(g, g[1:]):          # consecutive pairs suffice
                for i in range(1, self.k + 1):
                    # gates before i that could have used p
                    earlier = [o[6] for j in range(1, i)
                               for o in self.options[j] if p in (o[0], o[2], o[4])]
                    for o in self.options[i]:
                        uses_q = q in (o[0], o[2], o[4])
                        uses_p = p in (o[0], o[2], o[4])
                        if uses_q and not uses_p:
                            c.append([-o[6]] + earlier)
                            self.sym_input_clauses += 1

    def decode(self, model):
        pos = {abs(l) for l in model if l > 0}
        gates = []
        for i in range(1, self.k + 1):
            sel = [o for o in self.options[i] if o[6] in pos]
            # `raise`, not `assert` (stripped by `python -O`).
            if len(sel) != 1:
                raise ValueError(f"gate {i}: {len(sel)} active options")
            gates.append(sel[0][:6])
        outs = []
        for o in range(self.m):
            nodes = [nd for nd in range(0, self.n + self.k + 1) if self.osel[(o, nd)] in pos]
            if len(nodes) != 1:
                raise ValueError(f"output {o}: {len(nodes)} selected nodes")
            outs.append((nodes[0], self.opol[o] in pos))
        return gates, outs


def simulate_multi(n, gates, outs, t):
    """Not an independent check: it shares the bit convention with the encoder. The independent
    check is certlab.simulate.check_multi."""
    vals = {0: 0}
    for j in range(1, n + 1):
        vals[j] = (t >> (j - 1)) & 1
    node = n
    for a, pa, b, pb, cc, pc in gates:
        node += 1
        x, y, z = vals[a] ^ pa, vals[b] ^ pb, vals[cc] ^ pc
        vals[node] = (x & y) | (x & z) | (y & z)
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
    for j in range(1, n + 1):
        v = sum(1 << t for t in range(rows) if (t >> (j - 1)) & 1)
        cands |= {v, v ^ mask}
    return all(tt in cands for tt in tts)


def solve_k(n, tts, k, return_circuit=False, timeout=None,
            fence=None, sym_inputs=None):
    """Is there a multi-output MIG with k MAJ gates for `tts`? Returns (sat, circuit or None).

    The verdict needs exactly one kissat status line agreeing with the exit code (10 = SAT,
    20 = UNSAT); anything else raises RuntimeError (see _multi_common.kissat_verdict). A SAT model
    is always decoded and checked by verify_multi and by the independent
    certlab.simulate.check_multi; `return_circuit` only decides whether the circuit is returned.
    """
    tts = check_tables(n, tts)
    enc = MultiMIGEncoder(n, k, tts, fence=fence,
                          sym_inputs=sym_inputs).build()
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
    # A missing "s SATISFIABLE" is NOT UNSAT: a crash, an out-of-memory kill and a missing binary
    # all end up here (kissat_verdict raises).
    if not kissat_verdict(r):
        return False, None
    model = []
    for line in r.stdout.splitlines():
        if line.startswith("v "):
            model.extend(int(x) for x in line[2:].split())
    gates, outs = enc.decode(model)
    if not verify_multi(n, tts, gates, outs):
        raise RuntimeError("SAT model does not reproduce the truth tables")
    if not check_multi("mig", n, tts, gates, outs):
        raise RuntimeError("SAT model rejected by the independent simulator (certlab.simulate)")
    return True, ((gates, outs) if return_circuit else None)


def opt_multi_via_sat(n, tts, kmax=16, timeout=None):
    """Smallest k such that a multi-output MIG for `tts` exists, by an ascending search from
    k = 0; None if no k <= kmax is SAT. Every SAT answer is decoded and checked (see solve_k)."""
    tts = check_tables(n, tts)
    if trivial_multi(n, tts):
        return 0
    for k in range(1, kmax + 1):
        sat, _ = solve_k(n, tts, k, timeout=timeout)
        if sat:
            return k
    return None
