"""Simulators that are INDEPENDENT of the encoders.

Each encoder module carries its own `simulate`/`verify_circuit`, written next to the code that
generates the circuit. A defect shared by the generator and its own checker (for example, a wrong
reading of which bit of the row index is input x_1) would pass both. The functions here import
nothing from certlab.encoders and use a different technique: word-parallel simulation over whole
truth tables (one Python integer of 2^n bits per node), instead of row-by-row evaluation.

Circuit formats (the ones returned by the encoders' `decode`):
  AIG: gates = [(a, pa, b, pb), ...]           node = AND(a ^ pa, b ^ pb)
  XAG: gates = [(typ, a, pa, b, pb), ...]      typ in {"and", "xor"}
  MIG: gates = [(a, pa, b, pb, c, pc), ...]    node = MAJ(a ^ pa, b ^ pb, c ^ pc); node 0 = constant 0
Nodes 1..n are the inputs, node n+i is gate i, and the output is the last gate, complemented
when out_pol is true.

Truth-table convention (`convention="lsb"`, the encoders' convention): bit t of tt = f(row t), and
input x_j is bit j-1 of t. `convention="msb"` reads x_j as bit n-j of t; it exists so that a test
can show that the check is sensitive to the convention.
"""

_BASES = ("aig", "xag", "mig")


def input_tt(n, j, convention="lsb"):
    """Truth table (2^n bits) of input x_j, j = 1..n."""
    if not 1 <= j <= n:
        raise ValueError(f"input index {j} out of range 1..{n}")
    if convention not in ("lsb", "msb"):
        raise ValueError(f"unknown convention {convention!r}")
    bit = (j - 1) if convention == "lsb" else (n - j)
    out = 0
    for t in range(1 << n):
        if (t >> bit) & 1:
            out |= 1 << t
    return out


def _mask(n):
    return (1 << (1 << n)) - 1


def _node_tables(n, convention):
    return {j: input_tt(n, j, convention) for j in range(1, n + 1)}


def simulate_aig(n, gates, out_pol, convention="lsb"):
    m = _mask(n)
    val = _node_tables(n, convention)
    node = n
    for (a, pa, b, pb) in gates:
        node += 1
        va = val[a] ^ (m if pa else 0)
        vb = val[b] ^ (m if pb else 0)
        val[node] = va & vb
    if node == n:
        raise ValueError("empty circuit")
    return val[node] ^ (m if out_pol else 0)


def simulate_xag(n, gates, out_pol, convention="lsb"):
    m = _mask(n)
    val = _node_tables(n, convention)
    node = n
    for (typ, a, pa, b, pb) in gates:
        node += 1
        va = val[a] ^ (m if pa else 0)
        vb = val[b] ^ (m if pb else 0)
        if typ == "and":
            val[node] = va & vb
        elif typ == "xor":
            val[node] = va ^ vb
        else:
            raise ValueError(f"unknown XAG gate type {typ!r}")
    if node == n:
        raise ValueError("empty circuit")
    return val[node] ^ (m if out_pol else 0)


def simulate_mig(n, gates, out_pol, convention="lsb"):
    m = _mask(n)
    val = _node_tables(n, convention)
    val[0] = 0
    node = n
    for (a, pa, b, pb, c, pc) in gates:
        node += 1
        va = val[a] ^ (m if pa else 0)
        vb = val[b] ^ (m if pb else 0)
        vc = val[c] ^ (m if pc else 0)
        val[node] = (va & vb) | (va & vc) | (vb & vc)
    if node == n:
        raise ValueError("empty circuit")
    return val[node] ^ (m if out_pol else 0)


def simulate(basis, n, gates, out_pol, convention="lsb"):
    if basis == "aig":
        return simulate_aig(n, gates, out_pol, convention)
    if basis == "xag":
        return simulate_xag(n, gates, out_pol, convention)
    if basis == "mig":
        return simulate_mig(n, gates, out_pol, convention)
    raise ValueError(f"unknown basis {basis!r}; expected one of {_BASES}")


def check(basis, n, tt, gates, out_pol, convention="lsb"):
    """True iff the circuit computes tt on all 2^n rows."""
    return simulate(basis, n, gates, out_pol, convention) == tt


def fanout(basis, n, gates):
    """Number of gate operands that read each internal node (inputs and the constant excluded)."""
    cnt = {}
    for g in gates:
        if basis == "aig":
            ops = (g[0], g[2])
        elif basis == "xag":
            ops = (g[1], g[3])
        elif basis == "mig":
            ops = (g[0], g[2], g[4])
        else:
            raise ValueError(f"unknown basis {basis!r}")
        for o in ops:
            if o > n:
                cnt[o] = cnt.get(o, 0) + 1
    return cnt
