#!/usr/bin/env bash
# reverify.sh -- re-check EVERY certificate in a certificates directory from scratch. The
# durability guard: a paper-grade claim is "all N certificates re-verify". DRAT via drat-trim
# (needs the sibling .cnf), through check_drat.sh; pseudo-Boolean proofs via veripb (needs the
# sibling .opb), if veripb is on PATH.
# Usage: scripts/reverify.sh [certs_dir]   (default: $CERTLAB_CERTS, else ./certlab_certs)
# Exit 0 iff every certificate passes; 1 if any fails or is missing its formula; 2 if the
# directory does not exist.
set -uo pipefail
CERTS="${1:-${CERTLAB_CERTS:-$PWD/certlab_certs}}"
[ -d "$CERTS" ] || { echo "[reverify] no certs dir: $CERTS"; exit 2; }
pass=0; fail=0; miss=0
shopt -s nullglob
for drat in "$CERTS"/*.drat; do
  cnf="${drat%.drat}.cnf"
  if [ ! -f "$cnf" ]; then echo "MISS  $(basename "$drat") (no .cnf)"; miss=$((miss+1)); continue; fi
  # DELEGATES to check_drat.sh -- it does not reimplement the verdict. This line used to be
  # `drat-trim ... | grep -q "VERIFIED"`, which ALSO matches `s NOT VERIFIED`: a REJECTED proof
  # counted as PASS, in the tool whose whole job is to be the durability guard of the claims.
  if "$(dirname "$0")/check_drat.sh" "$cnf" "$drat" >/dev/null 2>&1; then pass=$((pass+1));
  else echo "FAIL  $(basename "$drat")"; fail=$((fail+1)); fi
done
for pbp in "$CERTS"/*.pbp; do
  opb="${pbp%.pbp}.opb"
  if [ ! -f "$opb" ]; then echo "MISS  $(basename "$pbp") (no .opb)"; miss=$((miss+1)); continue; fi
  if veripb "$opb" "$pbp" 2>/dev/null | grep -q "^s VERIFIED"; then pass=$((pass+1));
  else echo "FAIL  $(basename "$pbp")"; fail=$((fail+1)); fi
done
echo "[reverify] PASS=$pass FAIL=$fail MISS=$miss  @ $(date -u +%FT%TZ)"
[ "$fail" -eq 0 ] && [ "$miss" -eq 0 ]
