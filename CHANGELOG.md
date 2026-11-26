# Changelog

## 0.2.0 (2026-11-26)

Phase 2, multi-output.

- Encoders: multi-output AIG (`certlab.encoders.multi_aig`) and multi-output MIG
  (`certlab.encoders.multi_mig`, with `sum_tts`, optional fences and an optional
  input-symmetry break). Python API only; the CLI is unchanged. A multi-output XAG encoder is not
  included: none existed in the research code this package is drawn from.
- `certlab.simulate.simulate_multi` / `check_multi`: independent word-parallel simulators for
  multi-output circuits.
- With respect to the original scripts (TESTING.md, section 4): verdict guards that were `assert`
  statements are exceptions; the multi-output AIG encoder now reads input x_j as bit j-1 of the row
  index, like every other certlab module (the original read it as bit n-j; minimum sizes do not
  change, decoded circuits are now read in the certlab convention); the gate-ordering symmetry
  break of the multi-output MIG encoder (`symbreak`) is removed, since it constrained nothing and
  no certificate used it.
- Fixed before release, after review (TESTING.md, section 4.1): an iterator of tables lost outputs;
  out-of-range tables were read on their low bits; `fence=()` and empty levels were accepted;
  the kissat verdict is now read from exactly one status line that must agree with the exit code,
  in both multi-output encoders; `check_multi` rejects an unsupported basis even with no gates, and
  `verify_multi` requires one output per table. Every SAT answer of the multi-output encoders is
  decoded and checked by the independent `certlab.simulate.check_multi` before it is reported;
  the `verify` argument of `opt_multi_via_sat` is removed.
- Not included in this release: a multi-output XAG encoder, a command-line entry point for the
  multi-output encoders, and a DRAT-certified lower-bound path for them. Multi-output minimum
  sizes returned by `opt_multi` / `opt_multi_via_sat` rest on the solver's UNSAT answer, not on a
  checked proof.

## 0.1.0 (2026-10-16)

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
  reports a killed or out-of-memory checker as an unverified proof (new exit code 4) and reads
  drat-trim's "time limit exceeded" as a time limit (see "Changed contract" below);
  `build_amo_shared` requires `n`; imports are package imports; `reverify.sh` fails when a proof
  has no formula to be checked against.
- `certlab.certify.forced_multi.build_amo_shared`: the `gate_order_sb` parameter is removed. That
  gate-ordering symmetry break (by the smaller operand) was unsound, with a counterexample
  (tt = 0x80008000), and no certificate used it. `gate_order_b` stays as an experimental opt-in
  (default False), not proved WLOG; no certification path of the package sets it.

### Changed contract

- `scripts/check_drat.sh` exit codes: 0 verified, 1 not verified (`s NOT VERIFIED`: the checker
  did not verify the proof, so no lower bound is certified), 2 usage error / missing file / drat-trim absent, 3 drat-trim time limit (not concluded),
  4 checker failure (killed, out of memory, no status line, or `s VERIFIED` with a non-zero exit;
  neither verified nor refuted). The copy published earlier (Zenodo, DOI 10.5281/zenodo.23375519)
  returns 1 in the cases that now return 4, and 1 for a time limit reported only as "time limit
  exceeded" (now 3). A caller that treated any non-zero exit as failure is unaffected; a caller
  that read 1 as "proof refuted" must now also handle 3 and 4 as inconclusive.
