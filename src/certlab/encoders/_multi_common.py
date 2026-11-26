"""Input checks and the kissat verdict reader shared by the two multi-output encoders."""
import operator


def check_n(n):
    """n as an int (anything with __index__, e.g. numpy.int64, is accepted); n >= 0."""
    n = operator.index(n)
    if n < 0:
        raise ValueError(f"n must be >= 0, got {n}")
    return n


def check_size(name, k):
    """A gate count or a search bound as an int; must be >= 0."""
    k = operator.index(k)
    if k < 0:
        raise ValueError(f"{name} must be >= 0, got {k}")
    return k


def check_tables(n, tts):
    """Return (n, tts) with tts as a list of ints, after checking them; ValueError otherwise.

    The list is built once, so an iterator is not consumed by a first pass (the k = 0 test) and
    then seen empty or shortened by the next. Each table must fit in the 2**n rows of n inputs
    (n = 0 is one row: the constants 0 and 1): a larger integer would be read only on its low bits
    by the encoders, which would then solve a different function from the one given. An empty
    list of outputs is rejected: there is nothing to synthesise. Integer types other than int are
    accepted through operator.index.
    """
    n = check_n(n)
    tts = [operator.index(tt) for tt in tts]
    if not tts:
        raise ValueError("at least one output table is required")
    rows = 1 << n
    for o, tt in enumerate(tts):
        if tt < 0 or tt.bit_length() > rows:
            raise ValueError(f"table {o} = {tt} does not fit in {rows} rows (n = {n})")
    return n, tts


def kissat_verdict(r):
    """True for SAT, False for UNSAT, from a finished kissat run; RuntimeError otherwise.

    A verdict needs exactly one status line (a line starting with "s ") that agrees with the
    DIMACS exit code: "s SATISFIABLE" with 10, or "s UNSATISFIABLE" with 20. A crash, an
    out-of-memory kill, a missing binary, a missing or repeated status line, or a status line
    that contradicts the exit code is neither verdict. Comment lines ("c ...") are never read,
    even when they quote a status.
    """
    status = [line.strip() for line in r.stdout.splitlines() if line.startswith("s ")]
    if len(status) == 1:
        if status[0] == "s SATISFIABLE" and r.returncode == 10:
            return True
        if status[0] == "s UNSATISFIABLE" and r.returncode == 20:
            return False
    raise RuntimeError(
        f"kissat gave no verdict: returncode={r.returncode}, status lines={status!r}, "
        f"stderr[:200]={r.stderr[:200]!r}")
