#!/usr/bin/env bash
# certify.sh -- certify forced-multi (DRAT, no symmetry breaking) for an n = 5 witness: the
# all-optima structural invariant "every size-optimal AIG has >= 2 reconvergent gates".
# Level 1 (the only one implemented): no-SB DRAT (certlab.certify.cert_nosb) -- kissat on the
#   at-most-one-shared instance, drat-trim VERIFIED. This is NOT a general certification tool.
# Level 2 (NOT implemented): VeriPB-certified symmetry breaking, for instances that only close with
#   the gate-permutation break. Falls through to a message.
# Appends a row to $CERTLAB_CERTS/certify_manifest.csv, a claim -> certificate -> sha -> verdict ledger.
# Usage: scripts/certify.sh <tt_hex> <opt> [timeout_s]
#
# Exit codes (a timeout is NEVER 0, and a missing binary is NEVER a verdict):
#   0  certified: amo-shared UNSAT and drat-trim VERIFIED
#   1  refuted:   amo-shared SAT with no SB => NOT forced-multi
#   2  anomaly:   UNSAT but drat-trim FAILED -- solver and checker disagree, state inconsistent
#   3  refused:   toolchain missing, or cert_nosb aborted before running anything
#   4  inconclusive: no verdict in the timeout, or output this script cannot classify
#
# Two defects of the same family once lived here -- infrastructure reported as mathematics:
#   (a) the SAT branch was `grep -q "SAT"`, which MATCHES "UNSAT". A proof of UNSAT whose drat-trim
#       leg FAILED fell through the VERIFIED test, matched here, and was reported as "amo-shared SAT
#       => NOT forced-multi". An inverted verdict, not merely a lost one.
#   (b) the interpreter was hardcoded to one Python minor version that was not installed, so every
#       run died in `command not found`, matched nothing, and landed on the closing message "level 1
#       did not close (likely intractable no-SB)". A broken interpreter was reported as mathematical
#       intractability. Hence the preflight below: assert the toolchain, then run.
set -uo pipefail
tt="${1:?tt hex}"; opt="${2:?opt}"; T="${3:-3600}"
CERTS="${CERTLAB_CERTS:-$PWD/certlab_certs}"; export CERTLAB_CERTS="$CERTS"
MAN="$CERTS/certify_manifest.csv"

# --- preflight: refuse to act rather than misattribute an absence -------------------------------
PY="${CERTIFY_PY:-}"
if [ -z "$PY" ]; then
  for c in python3 python; do command -v "$c" >/dev/null 2>&1 && { PY="$c"; break; }; done
fi
missing=""
[ -n "$PY" ] || missing="$missing python3"
for b in kissat drat-trim; do command -v "$b" >/dev/null 2>&1 || missing="$missing $b"; done
if [ -n "$PY" ] && ! "$PY" -c "import certlab.certify.cert_nosb" >/dev/null 2>&1; then
  missing="$missing certlab(python package)"
fi
if [ -n "$missing" ]; then
  echo "[certify] REFUSED: missing ->$missing"
  echo "          Nothing was run, so there is no verdict. This is NOT a sign that the instance is hard."
  exit 3
fi
mkdir -p "$CERTS"
[ -f "$MAN" ] || echo "date,tt,opt,level,verdict,cnf_sha,cert_sha,cert" > "$MAN"

echo "[certify] $tt opt=$opt -- level 1 (no-SB DRAT), interpreter=$PY..."
out="$("$PY" -u -m certlab.certify.cert_nosb "$tt" "$opt" "$T" 2>&1)"; echo "$out"

# Order matters: VERIFIED before FAIL, and "no-SB SAT" anchored so that it cannot match "UNSAT".
if echo "$out" | grep -q "drat-trim=VERIFIED"; then
  csha="$(echo "$out" | sed -n 's/.*cnf sha16=\([0-9a-f]*\).*/\1/p' | head -1)"
  dsha="$(echo "$out" | sed -n 's/.*drat sha16=\([0-9a-f]*\).*/\1/p' | head -1)"
  echo "$(date -u +%FT%TZ),$tt,$opt,1-nosb-drat,VERIFIED,$csha,$dsha,n5_${tt}_amo1shared_nosb.drat" >> "$MAN"
  echo "[certify] LEVEL 1 certified (pure DRAT, zero symmetry-break gap). Manifest updated."
  exit 0
fi
if echo "$out" | grep -q "drat-trim=FAIL"; then
  echo "[certify] ANOMALY: the solver said UNSAT and drat-trim did NOT verify the proof."
  echo "          Inconsistent state -- not recorded in the manifest. Investigate the proof, not the instance."
  exit 2
fi
if echo "$out" | grep -qE "RESULT: no-SB SAT"; then
  echo "[certify] amo-shared SAT with ZERO SB => NOT forced-multi (or a real counterexample) -- investigate."
  exit 1
fi
if echo "$out" | grep -q "ABORT:"; then
  echo "[certify] REFUSED: cert_nosb aborted before deciding (see the ABORT line above)."
  exit 3
fi
if echo "$out" | grep -q "RESULT: no verdict"; then
  echo "[certify] NO VERDICT within the ${T}s timeout. Do not conclude hardness from this; level 2"
  echo "          (VeriPB-certified symmetry breaking) is not implemented."
  exit 4
fi
echo "[certify] UNCLASSIFIED OUTPUT -- no known sentinel matched. This is a harness failure, not a"
echo "          result about the instance. Read the output above before drawing any conclusion."
exit 4
