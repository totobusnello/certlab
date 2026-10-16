"""
AIG exact-synthesis encoder via SAT.

Encoded question: "is there an AIG circuit with exactly k AND gates that computes f?"
AIG model (the convention of the n = 4 NPN catalogue in data/npn4/): 2-input AND gates, free
inversions on every edge and on the output; size = number of AND gates.

Semantics of the encoding (validated against an independent enumeration):
- Nodes: inputs 1..n (fixed values per truth-table row), gates n+1..n+k.
- Each gate i selects (one-hot) an option (a, pa, b, pb): operands a < b among earlier nodes,
  with polarities pa, pb.
- v[i][t] = value of gate i on row t; conditional clauses impose
  v[i][t] <-> (val(a,t) xor pa) AND (val(b,t) xor pb).
- Output = gate k with free polarity op: v[k][t] <-> (f(t) xor op).
- Symmetry breaking (sound): every gate i < k must be used by some later gate.
- k = 0 is handled outside SAT (f constant or a literal).

RULE: a DRAT proof certifies the CNF, not the encoding. That is why the encoder is
cross-checked against an independent enumeration, and why every SAT circuit is verified by
simulation.

===============================================================================================
`relax=` -- THIS ENCODER CAN RUN OUTSIDE ITS OWN CANONICAL SPACE, AND THAT SERVES ANY CLAIM
THAT DEPENDS ON ONE OF ITS WLOG ASSUMPTIONS
===============================================================================================

Every exact-synthesis claim built on this encoder goes through the structural constraints listed
above, and for a long time their defence was PROSE: the write-up listed the constraints, argued
that each is without loss of generality at `k = opt`, and asked the reader to accept the
analysis. That was the weakest link of the argument.

Part of it does not need an argument. The constraints come in two kinds, and the difference is
OPERATIONAL, not stylistic:

  RELAXABLE -- they forbid objects that exist in the problem but are redundant.
    'dup'    two gates with the SAME (a, pa, b, pb)
    'aeqb'   a == b, admitting `x AND x` (buffer) and `x AND NOT x` (constant 0)
    'const'  the free constant as an operand (never offered by default)
  SWITCH IT OFF AND RUN AGAIN. If the verdict SURVIVES, the constraint was not carrying the
  result: it leaves the argument and the reader need not accept anything about it. If it
  CHANGES, it was load-bearing -- and now that is known by measurement, not by assumption.

  DEFINITIONAL -- they encode what the question means.
    every gate i<k feeds a later one  .  the output is gate k
  DO NOT relax them. A dead gate means a strictly SMALLER circuit, which contradicts `opt = k`;
  relaxing them turns the question into "is there a circuit of <= k gates with little
  reconvergence", whose answer is trivially yes and says nothing about optima. Here the
  argument is irreducible -- but it is small and nearly tautological, the kind one can only
  reject by rejecting the definition of an optimum.

VALIDATE THE INSTRUMENT BEFORE USING IT, through a property that MUST hold: relaxing only admits
circuits that are NOT BETTER, so the measured `opt` cannot change -- UNSAT at `k = opt-1`, SAT
at `k = opt`. If it changes, the relaxation is wrong and nothing measured afterwards counts.
Without that step, a buggy relaxation yields an easy UNSAT and SEEMS to confirm the result.

WHAT `relax` DOES NOT REACH: that the truth table, the Tseitin semantics and the notion of
fan-out in the CNF correspond to the mathematical object. Relaxation audits WHICH OBJECTS the
encoder admits; it does not audit WHAT IT MEANS. Closing that gap is formalisation, not more
solving. A claim saying "the WLOG assumptions were tested" while suggesting that the semantic
bridge is certified is an overclaim.

`relax` is for AUDITING an argument, NEVER for producing a claim: the trust path of every result
is the encoder at its default (`relax=()`).
"""

from itertools import combinations, combinations_with_replacement, product


def tt_bit(tt, t):
    return (tt >> t) & 1


class AIGEncoder:
    # CONSTANT source node, used only under relax='const'. Its value is 1; the operand polarity
    # gives the 0. Index 0 is free because inputs are 1..n and gates are n+i.
    CONST_NODE = 0

    def __init__(self, n, k, tt, formula=False, relax=(), reconv_budget_opt=None):
        """n inputs, k AND gates, tt = truth table as an integer of 2^n bits (bit t = f(row t),
        input x_j = bit j-1 of the row index t).

        formula=True: FORMULA mode (fan-out 1) -- every non-output gate is used by EXACTLY one
        later gate (a tree). SAT at k => tree(f) <= k. Identical to the formula mode of
        XAGEncoder; the only additional constraint is the fan-out one.

        `relax` switches WLOG constraints off to AUDIT the argument for them, never to produce a
        claim. The argument says that the structural constraints of the encoder are WLOG at
        k=opt and that none of them changes fan-out -- the one place where prose stands in for a
        certificate. Several of them can be TESTED instead of argued: if the UNSAT of the
        amo-shared instance survives with the constraint RELAXED, the constraint was not carrying
        the result and leaves the argument.

          'dup'   allows two gates with the SAME (a,pa,b,pb)
          'aeqb'  allows a == b  (AND(x,x)=x buffer; AND(x,~x)=0 constant)
          'const' admits 0 and 1 as operands (the cost model admits a free constant; the
                  encoder does not)
          'order' admits (a,b) AND (b,a) -- relaxes the ORDERING `a < b`, which is a symmetry by
                  commutativity of AND. NOTE: `aeqb` alone does NOT relax the ordering --
                  `combinations_with_replacement` returns ordered pairs, only admitting a==b.

        `reconv_budget_opt` is a TRIPWIRE, not an option. A caller that imposes a RECONVERGENCE
        BUDGET on top of these clauses (an at-most-k over the fan-out>=2 gates) declares here the
        `opt` of the function, and the encoder refuses the illegal combination instead of
        returning a false UNSAT: the dedup -- forbidding two gates with the same `(a,pa,b,pb)` --
        is WLOG only at `k <= opt`, because merging two identical gates gives `opt-1` and
        contradicts minimality. Above `opt`, under a reconvergence budget, it stops being WLOG:
        sharing SPENDS a reconvergence, so DUPLICATING can be strictly optimal, and forbidding
        the duplicate erases the right circuit. That is what produced `R_1(0x07e9) = 10` with
        `rc=20`, `status=ok` and no timeout, when the true value is 9 and a 9-gate circuit is
        exhibited.

        The other two -- every gate feeds a later one, and the output is gate k -- are NOT
        relaxable: a dead gate means a smaller circuit, so they are not a symmetry, they are the
        DEFINITION of "optimum with k gates". Relaxing them would change the question.
        """
        self.n, self.k, self.tt, self.formula = n, k, tt, formula
        self.relax = set(relax)
        # TRIPWIRE: a correct verdict about the wrong space. See the docstring.
        if (reconv_budget_opt is not None and not formula
                and "dup" not in self.relax and k > reconv_budget_opt):
            raise ValueError(
                "AIGEncoder: reconvergence budget at k=%d > opt=%d with the dedup ON. "
                "The dedup is WLOG only for k <= opt; above that, duplicating can be strictly optimal "
                "(sharing spends a reconvergence) and this encoder would return a FALSE UNSAT. "
                "Pass relax=(\"dup\",) when k > opt. See the AIGEncoder docstring"
                % (k, reconv_budget_opt))
        self.rows = 1 << n
        self.nvars = 0
        self.clauses = []
        # v[i][t] for gates i=1..k
        self.v = {(i, t): self._new() for i in range(1, k + 1) for t in range(self.rows)}
        # options of each gate: (a, pa, b, pb); nodes 1..n are inputs, n+j is gate j
        self.options = {}
        for i in range(1, k + 1):
            opts = []
            nodes = list(range(1, self.n + i))  # available nodes (< n+i)
            if "const" in self.relax:
                nodes = [self.CONST_NODE] + nodes   # 0/1 via the polarity over a constant source
            # 'order' relaxes the OPERAND ORDERING (`a < b`), a symmetry by commutativity of AND.
            # A review caught that `combinations_with_replacement` still returns ORDERED pairs: it
            # relaxes `a != b`, not `a < b`. Without `order` the ordering stayed in force, and a
            # count of "three of the five relaxed" was false -- two of the five, plus a silent sixth.
            if "order" in self.relax:
                pairs = product(nodes, repeat=2)          # (a,b) AND (b,a); includes a==b
            elif "aeqb" in self.relax:
                pairs = combinations_with_replacement(nodes, 2)   # a <= b
            else:
                pairs = combinations(nodes, 2)                    # a < b
            for a, b in pairs:
                for pa in (0, 1):
                    for pb in (0, 1):
                        opts.append((a, pa, b, pb, self._new()))
            self.options[i] = opts
        self.out_pol = self._new()

    def _new(self):
        self.nvars += 1
        return self.nvars

    def _node_val(self, node, t):
        """Value of the node on row t: (const, None) for inputs; (None, var) for gates."""
        if node == self.CONST_NODE:
            return (1, None)          # constant source 1; ~1 = 0 through the polarity
        if node <= self.n:
            return ((t >> (node - 1)) & 1, None)
        return (None, self.v[(node - self.n, t)])

    def build(self):
        c = self.clauses
        for i in range(1, self.k + 1):
            svars = [o[4] for o in self.options[i]]
            c.append(svars)  # at-least-one
            c.extend([-x, -y] for x, y in combinations(svars, 2))  # at-most-one
            for a, pa, b, pb, s in self.options[i]:
                for t in range(self.rows):
                    x = self.v[(i, t)]
                    # BUGFIX (caught by the first validation run): the constants 0/1 collided
                    # with the DIMACS literals +-1 -- they are now separate kinds.
                    ka, la = self._lit(a, pa, t)  # ('const', 0|1) or ('lit', +-var)
                    kb, lb = self._lit(b, pb, t)
                    # x <-> la AND lb, conditioned on s
                    if (ka == "const" and la == 0) or (kb == "const" and lb == 0):
                        c.append([-s, -x])           # AND with false => x false
                    elif ka == "const" and kb == "const":  # both true
                        c.append([-s, x])
                    elif ka == "const":              # la=true: x <-> lb
                        c.append([-s, -x, lb]); c.append([-s, x, -lb])
                    elif kb == "const":              # lb=true: x <-> la
                        c.append([-s, -x, la]); c.append([-s, x, -la])
                    else:
                        c.append([-s, -x, la]); c.append([-s, -x, lb])
                        c.append([-s, x, -la, -lb])
        # SYMMETRY BREAKING (sound for the question "opt = k?"): two gates never select the SAME
        # option (a,pa,b,pb) -- a MINIMAL circuit never has duplicate gates (removing the
        # duplicate would give a smaller circuit). When the probe asks k with opt in {k, k+1},
        # every relevant solution is minimal, hence free of duplicates.
        # SYMMETRY BREAKING -- in CIRCUIT mode only. In FORMULA mode (a tree), a subtree may
        # appear DUPLICATED (that is the very reason tree > opt); forbidding duplicates would
        # exclude valid minimal formulas and give a FALSE UNSAT (a wrong lower bound on tree).
        # Hence the dedup is off when formula is set.
        if not self.formula and "dup" not in self.relax:
            by_tuple = {}
            for i in range(1, self.k + 1):
                for a, pa, b, pb, s in self.options[i]:
                    by_tuple.setdefault((a, pa, b, pb), []).append(s)
            for svars in by_tuple.values():
                if len(svars) > 1:
                    c.extend([-x, -y] for x, y in combinations(svars, 2))
        # every gate i < k is used by later gate(s).
        # circuit: AT LEAST one (fan-out >= 1). formula: EXACTLY one (fan-out 1).
        for i in range(1, self.k):
            users = [o[4] for j in range(i + 1, self.k + 1)
                     for o in self.options[j] if o[0] == self.n + i or o[2] == self.n + i]
            if users:
                self.clauses.append(users)                       # at-least-one
                if self.formula:
                    c.extend([-x, -y] for x, y in combinations(users, 2))  # at-most-one => fan-out 1
            else:  # no possible users => k infeasible in this shape
                self.clauses.append([])
        # output: v[k][t] <-> (f(t) xor op)
        op = self.out_pol
        for t in range(self.rows):
            x = self.v[(self.k, t)]
            if tt_bit(self.tt, t):   # op=0 -> x=1 ; op=1 -> x=0
                self.clauses.append([op, x]); self.clauses.append([-op, -x])
            else:
                self.clauses.append([op, -x]); self.clauses.append([-op, x])
        return self

    def _lit(self, node, pol, t):
        """Returns ('const', 0|1) for inputs, ('lit', +-var) for gates."""
        const, var = self._node_val(node, t)
        if var is None:
            return ("const", const ^ pol)
        return ("lit", -var if pol else var)

    def to_dimacs(self, path):
        with open(path, "w") as f:
            f.write(f"p cnf {self.nvars} {len(self.clauses)}\n")
            for cl in self.clauses:
                f.write(" ".join(map(str, cl)) + " 0\n")

    def decode(self, model):
        """model = list of ints (pysat) or a set of true literals. Returns the circuit."""
        pos = {abs(l) for l in model if l > 0}
        gates = []
        for i in range(1, self.k + 1):
            sel = [o for o in self.options[i] if o[4] in pos]
            # `raise`, not `assert`: under `python -O` an assert disappears, and a model that
            # selects zero or two options per gate would be decoded silently.
            if len(sel) != 1:
                raise ValueError(f"gate {i}: selection is not unique ({len(sel)})")
            a, pa, b, pb, _ = sel[0]
            gates.append((a, pa, b, pb))
        return gates, (self.out_pol in pos)


def simulate(n, gates, out_pol, t):
    """Simulation of the decoded circuit, row t (input x_j = bit j-1 of t)."""
    vals = {j: (t >> (j - 1)) & 1 for j in range(1, n + 1)}
    for idx, (a, pa, b, pb) in enumerate(gates, start=1):
        vals[n + idx] = (vals[a] ^ pa) & (vals[b] ^ pb)
    return vals[n + len(gates)] ^ (1 if out_pol else 0)


def verify_circuit(n, tt, gates, out_pol):
    """SEMANTIC CHECK: does the circuit match the whole truth table?"""
    return all(simulate(n, gates, out_pol, t) == tt_bit(tt, t) for t in range(1 << n))


def trivial_opt(n, tt):
    """opt=0: constants and literals (with polarity)."""
    rows = 1 << n
    if tt in (0, (1 << rows) - 1):
        return True
    for j in range(1, n + 1):
        lit = sum(((t >> (j - 1)) & 1) << t for t in range(rows))
        if tt == lit or tt == ((1 << rows) - 1) ^ lit:
            return True
    return False


def solve_k(n, tt, k, return_circuit=False):
    """SAT check with pysat/Glucose4. Returns (bool, circuit|None)."""
    from pysat.solvers import Glucose4
    enc = AIGEncoder(n, k, tt).build()
    if any(len(cl) == 0 for cl in enc.clauses):
        return False, None
    with Glucose4(bootstrap_with=enc.clauses) as s:
        if not s.solve():
            return False, None
        model = s.get_model()
    gates, op = enc.decode(model)
    # `raise`, not `assert`: this check IS the verdict guard. Under `python -O` an assert is
    # stripped and a model that does not compute tt would be reported as SAT.
    if not verify_circuit(n, tt, gates, op):
        raise RuntimeError("REJECTED: the circuit does not match the truth table")
    return True, (gates, op) if return_circuit else None


def opt_via_sat(n, tt, kmax=12):
    """Smallest k with a solution (0 = trivial)."""
    if trivial_opt(n, tt):
        return 0
    for k in range(1, kmax + 1):
        sat, _ = solve_k(n, tt, k)
        if sat:
            return k
    return None
