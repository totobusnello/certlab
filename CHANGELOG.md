# Changelog

## 0.1.0 (unreleased)

Phase 1, single-output. Consolidates, as one package, code first published inside the deposits
listed in README ("How to cite"), translated and checked against the originals before release.

- Encoders: AIG (`certlab.encoders.aig`), XAG (`.xag`), MIG (`.mig`), circuit and formula modes.
- Certification chain: `certlab.certify.zc_certify` (n = 4), `certlab.certify.forced_multi`
  (any n), `certlab.certify.cert_nosb` (n = 5, no symmetry breaking), `scripts/certify.sh`,
  `scripts/check_drat.sh`, `scripts/reverify.sh`.
- `certlab.npn` (n = 4 NPN canonicalisation), `certlab.witness` (regeneration of the n = 5
  witnesses), `certlab.simulate` (independent simulators, new), `certlab.cli` (new).
- Fixed with respect to the original scripts (TESTING.md, "Defects fixed"): verdict guards that
  were `assert` statements (removed by `python -O`) are now exceptions; `check_drat.sh` no longer
  reports a killed or out-of-memory checker as a refuted proof (new exit code 4) and reads
  drat-trim's "time limit exceeded" as a time limit (see "Changed contract" below);
  `build_amo_shared` requires `n`; imports are package imports; `reverify.sh` fails when a proof
  has no formula to be checked against.
- `certlab.certify.forced_multi.build_amo_shared`: the `gate_order_sb` parameter is removed. That
  gate-ordering symmetry break (by the smaller operand) was unsound, with a counterexample
  (tt = 0x80008000), and no certificate used it. `gate_order_b` stays as an experimental opt-in
  (default False), not proved WLOG; no certification path of the package sets it.

### Changed contract

- `scripts/check_drat.sh` exit codes: 0 verified, 1 not verified (`s NOT VERIFIED`, the proof is
  wrong), 2 usage error / missing file / drat-trim absent, 3 drat-trim time limit (not concluded),
  4 checker failure (killed, out of memory, no status line, or `s VERIFIED` with a non-zero exit;
  neither verified nor refuted). The copy published earlier (Zenodo, DOI 10.5281/zenodo.23375519)
  returns 1 in the cases that now return 4, and 1 for a time limit reported only as "time limit
  exceeded" (now 3). A caller that treated any non-zero exit as failure is unaffected; a caller
  that read 1 as "proof refuted" must now also handle 3 and 4 as inconclusive.
