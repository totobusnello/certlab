# Changelog

## 0.1.0 (unreleased)

Phase 1, single-output. Consolidates, as one package, code first published inside the deposits
listed in README ("How to cite"), translated and checked line by line against the originals
(tools/ast_equal.py).

- Encoders: AIG (`certlab.encoders.aig`), XAG (`.xag`), MIG (`.mig`), circuit and formula modes.
- Certification chain: `certlab.certify.zc_certify` (n = 4), `certlab.certify.forced_multi`
  (any n), `certlab.certify.cert_nosb` (n = 5, no symmetry breaking), `scripts/certify.sh`,
  `scripts/check_drat.sh`, `scripts/reverify.sh`.
- `certlab.npn` (n = 4 NPN canonicalisation), `certlab.witness` (regeneration of the n = 5
  witnesses), `certlab.simulate` (independent simulators, new), `certlab.cli` (new).
- Fixed with respect to the original scripts (TESTING.md, "Defects fixed"): verdict guards that
  were `assert` statements (removed by `python -O`) are now exceptions; `check_drat.sh` no longer
  reports a killed or out-of-memory checker as a refuted proof (new exit code 4) and reads drat-trim's
  "time limit exceeded" as a time limit; `build_amo_shared` requires `n`; imports are package
  imports; `reverify.sh` fails when a proof has no formula to be checked against.
