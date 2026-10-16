"""One battery of drat-trim outcomes, run against every reader of the drat-trim verdict.

Before this battery, the verdict of drat-trim was read in several places, each with its own test,
and no test checked that the readers agreed. Each case below is a fake `drat-trim` (stdout + exit
status) and the class it must be read as:

    0 VERIFIED        the proof is correct
    1 NOT_VERIFIED    the proof is wrong (only `s NOT VERIFIED` says this)
    3 TIMEOUT         drat-trim's time limit: neither verified nor refuted
    4 CHECKER_FAILED  killed / out of memory / no status line / VERIFIED with rc != 0:
                      neither verified nor refuted

The battery starts with the NEGATIVE cases (a proof that must NOT pass), because the historical
defect was a check that passed every good proof and was never shown a bad one.
"""
import os
import subprocess

# (name, shell body of the fake drat-trim, expected class)
CASES = [
    ("not_verified_substring_trap", "printf 'c ERROR: no conflict\\ns NOT VERIFIED\\nc verification time: 0.088 seconds\\n'; exit 0", 1),
    ("not_verified_rc1", "printf 's NOT VERIFIED\\n'; exit 1", 1),
    ("verified_then_nonzero_exit", "printf 's VERIFIED\\n'; exit 1", 4),
    ("killed_sigkill", "printf 'c parsing\\n'; kill -9 $$", 4),
    ("memout_no_status_line", "printf 'c MEMOUT\\n'; exit 0", 4),
    ("empty_output", "exit 0", 4),
    ("timeout_status", "printf 'c progress\\ns TIMEOUT\\n'; exit 0", 3),
    ("timeout_message_only", "printf 'c ERROR: time limit exceeded\\n'; exit 0", 3),
    ("verified_plain", "printf 'c 10 of 20 clauses in core\\ns VERIFIED\\nc verification time: 0.01 seconds\\n'; exit 0", 0),
    ("verified_after_carriage_return", "printf 'c 1886 of 13349 clauses in core          \\rs VERIFIED\\nc verification time: 0.09 seconds\\n'; exit 0", 0),
]

PY_CLASS = {"VERIFIED": 0, "NOT_VERIFIED": 1, "TIMEOUT": 3}


def write_fake(fakebin, body):
    p = os.path.join(fakebin, "drat-trim")
    with open(p, "w") as fh:
        fh.write("#!/bin/sh\n" + body + "\n")
    os.chmod(p, 0o755)
    return p


def dummy_pair(directory):
    cnf = os.path.join(directory, "x.cnf")
    drat = os.path.join(directory, "x.drat")
    with open(cnf, "w") as fh:
        fh.write("p cnf 1 2\n1 0\n-1 0\n")
    with open(drat, "w") as fh:
        fh.write("0\n")
    return cnf, drat


def run_check_drat_sh(script, cnf, drat, env):
    return subprocess.run(["bash", script, cnf, drat], capture_output=True, text=True, env=env).returncode


def python_class(verdict):
    return PY_CLASS.get(verdict, 4)
