#!/usr/bin/env bash
# check_drat.sh <cnf> <drat> -- decide whether a DRAT proof actually verifies. ONE place.
#
# Why this exists. The check was once reimplemented ad hoc and got it wrong:
#
#   ok = "VERIFIED" in drat_trim_stdout
#
# "s NOT VERIFIED" CONTAINS "VERIFIED", so a FAILED proof read as a passing one. A review
# reproduced it. Against four real drat-trim outputs, that check misclassified three. The chain
# survived only because the reviewer replayed the proof independently -- not because the check worked.
#
# The same day, the mirror-image mistake: `grep -E "^s "` finds NOTHING, because drat-trim writes
# progress with CARRIAGE RETURNS (9 in a typical run), so the status line does not start a physical
# line. That empty result was read as a broken spot check and mis-diagnosed twice.
#
# So the rule is not "remember the trap", it is "call this script". Correct check, both traps:
#   - the status line must be exactly `s VERIFIED` (CR- and space-tolerant), never a substring;
#   - drat-trim must exit 0.
#
# Exit codes:
#   0 -- proof VERIFIED
#   1 -- proof NOT verified: drat-trim printed `s NOT VERIFIED` (the proof is wrong; this includes
#        SAT instances, where there is no UNSAT to prove)
#   2 -- usage error, missing file, or drat-trim absent
#   3 -- NOT CONCLUDED: drat-trim hit its time limit (`s TIMEOUT`, rc=0). Neither verified nor refuted.
#   4 -- CHECKER FAILED: drat-trim was killed (e.g. by the OOM killer), ran out of memory
#        (`c MEMOUT`, no status line), printed no status line, or printed `s VERIFIED` with a
#        non-zero exit. Neither verified nor refuted. Until this code existed, all of these were
#        reported as exit 1, i.e. as a refutation of the proof; only `s NOT VERIFIED` says
#        anything about the PROOF. (Same four-way reading as
#        certlab.certify.zc_certify.drat_verify_detailed; tests/test_drat_verdict.py runs both on
#        the same outputs.)
#
# Note for callers reading a SAT instance: `s NOT VERIFIED` here is indistinguishable from a
# truncated proof. Ask the SOLVER (exit 10 = SAT, 20 = UNSAT), not the checker.
#
# drat-trim has an INTERNAL ceiling of 40000 s (`#define TIMEOUT 40000`, flag `-t`) and, on hitting
# it, prints `s TIMEOUT` and exits 0. Without `-t` every "s TIMEOUT" was that ceiling, not a property
# of the proof. The ceiling is explicit: env DRAT_TIMEOUT_S, default 604800 s (7 days).
set -u

if [ "$#" -ne 2 ]; then
  echo "usage: check_drat.sh <cnf> <drat>" >&2
  exit 2
fi
cnf="$1"; drat="$2"
for f in "$cnf" "$drat"; do
  [ -f "$f" ] || { echo "check_drat: file not found: $f" >&2; exit 2; }
done
command -v drat-trim >/dev/null 2>&1 || { echo "check_drat: drat-trim is not on PATH" >&2; exit 2; }

# tr '\r' '\n' turns the progress-line carriage returns into real line breaks, so the status line
# can be anchored. Then match it exactly, tolerating trailing whitespace.
out="$(drat-trim "$cnf" "$drat" -t "${DRAT_TIMEOUT_S:-604800}" 2>&1)"; rc=$?
norm="$(printf '%s' "$out" | tr '\r' '\n')"
status="$(printf '%s\n' "$norm" | grep -E '^s +(NOT +)?VERIFIED[[:space:]]*$' | tail -1 | tr -s ' ' | sed 's/[[:space:]]*$//')"

if [ "$status" = "s VERIFIED" ] && [ "$rc" -eq 0 ]; then
  echo "VERIFIED  $(basename "$drat")  (drat-trim rc=0)"
  exit 0
fi
if [ "$status" = "s NOT VERIFIED" ]; then
  echo "NOT VERIFIED  $(basename "$drat")  (status='$status' drat-trim rc=$rc)"
  exit 1
fi
if printf '%s\n' "$norm" | grep -qE '^s +TIMEOUT[[:space:]]*$' \
   || printf '%s\n' "$norm" | grep -qi 'time limit exceeded'; then
  echo "NOT CONCLUDED  $(basename "$drat")  (drat-trim time limit, -t ${DRAT_TIMEOUT_S:-604800} s; neither verified nor refuted)"
  exit 3
fi
echo "CHECKER FAILED  $(basename "$drat")  (status='${status:-<none>}' drat-trim rc=$rc; neither verified nor refuted)"
exit 4
