"""Input checks and the kissat verdict reader shared by the two multi-output encoders."""


def check_tables(n, tts):
    """Return `tts` as a list after checking it; raise ValueError otherwise.

    The list is built once, so an iterator is not consumed by a first pass (the k = 0 test) and
    then seen empty or shortened by the next. Each table must fit in the 2**n rows of n inputs:
    a larger integer would be read only on its low bits by the encoders, which would then solve a
    different function from the one given.
    """
    if not isinstance(n, int) or n < 1:
        raise ValueError(f"n must be a positive integer, got {n!r}")
    tts = list(tts)
    if not tts:
        raise ValueError("at least one output table is required")
    top = 1 << (1 << n)
    for o, tt in enumerate(tts):
        if not isinstance(tt, int) or not 0 <= tt < top:
            raise ValueError(f"table {o} = {tt!r} does not fit in {1 << n} rows (n = {n})")
    return tts


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
