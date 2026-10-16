# Testing

Recorded on 2026-10-15, macOS (Apple M4), Python 3.14.6, kissat 4.0.4, drat-trim built from
source, pytest 8.2.2, python-sat 1.9.dev5.

Two checks gate the package, and each one is run on inputs it must reject:

| check | command | what it guarantees | proof that it can fail |
|---|---|---|---|
| leak scan | `python3 tools/scrub_check.py` | no AI model or vendor name, person name, host, machine path, internal identifier, secret, tool mark or Portuguese word in any file (file-scoped allowlist in the script) | `--prove`: one planted infringing file per pattern, each must give rc 1 |
| test suite | `python3 -m pytest` | see below | section 1: every probe plants a failure (fake solver, bad model, corrupt census) and the drat-trim battery starts with the proofs that must not pass |

Equivalence of the translated modules to the original research scripts was checked before release; the record is kept with the research repository.

## 1. Defects fixed, and their regression tests

Each probe of `tests/defect_probes.py` runs in a subprocess, with and without `python3 -O` (which
strips `assert` statements), and must hit its guard. The drat-trim battery of
`tests/drat_battery.py` runs every reader of the drat-trim verdict on the same ten fake outputs,
negative cases first.

| defect (with respect to the original scripts) | fix | test |
|---|---|---|
| `assert rc == 20` decided UNSAT in `xag.solve_k` and `mig.solve_k`: under `python3 -O` a crashed, killed or failing kissat (rc 0, 1, -9, 3) returned `(False, None)`, i.e. UNSAT | `if rc != 20: raise RuntimeError` | `test_defects.py::test_solver_failure_is_never_unsat` (2 bases x 4 fake-kissat modes x with/without -O) |
| `assert verify_circuit(...)` guarded the SAT witness in `aig/xag/mig.solve_k`: under -O a model that does not compute tt was returned as the circuit | `raise RuntimeError` | `test_guards_survive_optimize[bad_model_*]` |
| `assert len(sel) == 1` in `decode` (3 encoders): under -O a model with two options for one gate was decoded silently | `raise ValueError` | `test_guards_survive_optimize[decode_two_options_*]` |
| `npn.validate` / `load_census` / `opt_lookup` validated with `assert`: under -O a corrupt census passed validation | `raise ValueError` | `test_guards_survive_optimize[npn_validate_corrupt_csv]` |
| `witness` legs checked the solver exit code with `assert`: under -O a solver failure continued into drat-trim (the leg still failed, but for the wrong reason) | `raise RuntimeError` | `test_guards_survive_optimize[witness_leg_solver_failure]` |
| `build_amo_shared(n=None)` fell back to a module-level `N = 5`: a 4-variable function was silently encoded with 5 variables (833 instead of 581 variables for 0x03de) | `n` required (`TypeError`); the two callers pass it | `test_guards_survive_optimize[amo_shared_requires_n]` |
| several readers of the drat-trim verdict, never checked against each other; `check_drat.sh` reported a killed or out-of-memory checker, an empty output, `s VERIFIED` with rc != 0 and drat-trim's "time limit exceeded" as exit 1 (proof refuted) | `check_drat.sh` exit 4 (checker failed) and the time-limit message read as exit 3; one battery run against `check_drat.sh`, `drat_verify_detailed` and `certlab check-drat` | `test_drat_verdict.py::test_battery_all_readers_agree` (10 cases; the earlier script misread 5). Exit 4 is a change of contract with respect to the copy published earlier (CHANGELOG) |
| `sys.path.insert` across directories | package imports | `test_defects.py::test_no_sys_path_insert_in_package`, `test_no_assert_as_verdict_guard_in_package` |
| `certify.sh` presented as general certification | named "certify forced-multi (DRAT, no symmetry breaking)" in the script and README; level 2 stated as not implemented | `test_reverify_and_chain.py::test_certify_refuses_without_toolchain` |
| `reverify.sh` exited 0 when a proof had no formula (`MISS`), contradicting its own "exit 0 iff all pass" | exit 1 on any `MISS` | `test_reverify_good_and_adulterated` |
| import-time directories (`certs/`, `_generated/`) created next to the module | `$CERTLAB_CERTS` / `$CERTLAB_OUT`, default under the working directory | (all chain tests run with temporary directories) |
| `build_amo_shared(gate_order_sb=True)` added a gate-ordering symmetry break by the smaller operand, which is unsound (counterexample tt = 0x80008000) | parameter and branch removed; `gate_order_b` kept as an experimental opt-in (default False), set by no certification path | `test_encoder_regression.py` (the 4 amo-shared pins regenerate byte for byte without it) |

Not applicable in phase 1: the MSB/LSB bit-convention divergence lives in the multi-output AIG
encoder (phase 2); all phase-1 encoders use x_j = bit j-1, and `test_simulate_and_convention.py`
shows the check is sensitive to the convention. The `sha256sum` portability issue is in a
multi-output script (phase 2). `aig.solve_k` still uses python-sat (optional extra); the CLI and
the certification chain use kissat.

## 2. Leak scan

```
$ python3 tools/scrub_check.py
scrub_check: 0 finding(s) in 54 files under certlab/
$ python3 tools/scrub_check.py --prove --plants <token list kept outside the package>
control (clean file)              -> rc 0 (want 0)
  coverage ai_model  : 22/22 hashes planted
  coverage person    : 6/6 hashes planted
  coverage host      : 6/6 hashes planted
  coverage tool_mark : 2/2 hashes planted
  plants detected: 117/117 (each in its own directory, each must give rc 1)
scrub_check --prove: PASS
```

The model, person, host and tool-mark lists are stored hashed, so the clear-text plants come from
a list kept outside the package; the built-in `--prove` (no list) uses canaries and passes too.
Allowlist (file-scoped, in `tools/scrub_check.py`): the author's name in LICENSE, data/LICENSE,
CITATION.cff, pyproject.toml and README.md; the upstream copyright line of the third-party data
notice; the model and vendor named by the AI-use statement of README.md.

## 3. Test suite

| test file | guarantees | origin |
|---|---|---|
| `test_encoder_regression.py` | the 40 CNFs pinned in `data/manifest.csv` (28 circuit, 4 amo-shared, 8 formula) regenerate byte for byte; floor of 40; plus the 4 `opt witness` rows and the 32 per-leg tree-chain pins of `data/witness/` | research `encoder_regression.sh` |
| `test_drat_verdict.py` | one drat-trim battery, negative cases first, three readers agree; real proof verified, empty proof rejected, usage errors exit 2 | research `test-check_drat.sh` + the out-of-memory/timeout cases of `test-run_cell_drat.sh` |
| `test_defects.py` | section 2 | new |
| `gates/gate_xag.py`, `gates/gate_mig.py` via `test_gates.py` (slow) | n = 2 sanity; all 256 functions of n = 3 against an independent exhaustive enumeration and against opt_AIG | research gates X1+X2, M1+M2 |
| `test_bases_n3.py` | opt_XAG <= opt_AIG and opt_MIG <= opt_AIG on the 14 NPN classes of n = 3; opt_AIG equals an independent BFS enumeration; parity of 3 = (6, 2, 3) | new |
| `test_simulate_and_convention.py` | independent simulators agree with the encoders' on 900 random circuits and reject adulterated tables; a witness of x1 AND NOT x2 checks under the encoders' bit convention and fails under the inverted one, in all three bases | new |
| `test_cli.py` | exit code of every subcommand, including adulterated witness, solver failure, missing solver, bad input | new |
| `test_reverify_and_chain.py` | `reverify.sh` on good, adulterated and formula-less proofs; `certify.sh` refuses without toolchain; the n = 4 chain end to end (opt LB with DRAT, witness, amo-shared UNSAT with DRAT; forced-multi chain; witness `--full --tree-chain`); the n = 5 flagship quick chain (slow) | research `zc_certify` / `n5_forced_test` / `reproduce_witness` runs |
| `test_npn.py` | lookup and NPN invariance; full validation of the 222 classes over 65536 functions (slow) | research `npn_canon` self-validation |
| `test_tools.py` | scrub clean, plants detected, an infringing file flagged | new |

Not run here (out of phase 1 or by cost): the multi-output gates (`gate_multi_mig`,
`gate_unsat_real`, `gate_multi`, `gate_symbreak`), the AIG gate G2 (4 h budget per instance), the
`--full` forced-multi certificate of the n = 5 witnesses (a 247 MB DRAT each), and
`scripts/certify.sh` on an n = 5 witness.

Full run (`python3 -m pytest -v --durations=15 tests`):

```
tests/test_bases_n3.py::test_bases_agree_on_npn3_classes PASSED          [  1%]
tests/test_cli.py::test_synth_found_and_simulate_roundtrip PASSED        [  2%]
tests/test_cli.py::test_synth_none_up_to_kmax PASSED                     [  3%]
tests/test_cli.py::test_synth_solver_failure_and_missing_solver PASSED   [  5%]
tests/test_cli.py::test_synth_trivial_and_bad_input PASSED               [  6%]
tests/test_cli.py::test_cnf_matches_manifest_pin PASSED                  [  7%]
tests/test_cli.py::test_npn_lookup PASSED                                [  8%]
tests/test_cli.py::test_witness_unknown_tt_refused PASSED                [ 10%]
tests/test_defects.py::test_solver_failure_is_never_unsat[solver_failure_xag-exit0-python3] PASSED [ 11%]
tests/test_defects.py::test_solver_failure_is_never_unsat[solver_failure_xag-exit0-python3-O] PASSED [ 12%]
tests/test_defects.py::test_solver_failure_is_never_unsat[solver_failure_xag-exit1-python3] PASSED [ 13%]
tests/test_defects.py::test_solver_failure_is_never_unsat[solver_failure_xag-exit1-python3-O] PASSED [ 15%]
tests/test_defects.py::test_solver_failure_is_never_unsat[solver_failure_xag-no_status_line-python3] PASSED [ 16%]
tests/test_defects.py::test_solver_failure_is_never_unsat[solver_failure_xag-no_status_line-python3-O] PASSED [ 17%]
tests/test_defects.py::test_solver_failure_is_never_unsat[solver_failure_xag-sigkill-python3] PASSED [ 18%]
tests/test_defects.py::test_solver_failure_is_never_unsat[solver_failure_xag-sigkill-python3-O] PASSED [ 20%]
tests/test_defects.py::test_solver_failure_is_never_unsat[solver_failure_mig-exit0-python3] PASSED [ 21%]
tests/test_defects.py::test_solver_failure_is_never_unsat[solver_failure_mig-exit0-python3-O] PASSED [ 22%]
tests/test_defects.py::test_solver_failure_is_never_unsat[solver_failure_mig-exit1-python3] PASSED [ 24%]
tests/test_defects.py::test_solver_failure_is_never_unsat[solver_failure_mig-exit1-python3-O] PASSED [ 25%]
tests/test_defects.py::test_solver_failure_is_never_unsat[solver_failure_mig-no_status_line-python3] PASSED [ 26%]
tests/test_defects.py::test_solver_failure_is_never_unsat[solver_failure_mig-no_status_line-python3-O] PASSED [ 27%]
tests/test_defects.py::test_solver_failure_is_never_unsat[solver_failure_mig-sigkill-python3] PASSED [ 29%]
tests/test_defects.py::test_solver_failure_is_never_unsat[solver_failure_mig-sigkill-python3-O] PASSED [ 30%]
tests/test_defects.py::test_guards_survive_optimize[bad_model_xag-python3] PASSED [ 31%]
tests/test_defects.py::test_guards_survive_optimize[bad_model_xag-python3-O] PASSED [ 32%]
tests/test_defects.py::test_guards_survive_optimize[bad_model_mig-python3] PASSED [ 34%]
tests/test_defects.py::test_guards_survive_optimize[bad_model_mig-python3-O] PASSED [ 35%]
tests/test_defects.py::test_guards_survive_optimize[bad_model_aig-python3] PASSED [ 36%]
tests/test_defects.py::test_guards_survive_optimize[bad_model_aig-python3-O] PASSED [ 37%]
tests/test_defects.py::test_guards_survive_optimize[decode_two_options_aig-python3] PASSED [ 39%]
tests/test_defects.py::test_guards_survive_optimize[decode_two_options_aig-python3-O] PASSED [ 40%]
tests/test_defects.py::test_guards_survive_optimize[decode_two_options_xag-python3] PASSED [ 41%]
tests/test_defects.py::test_guards_survive_optimize[decode_two_options_xag-python3-O] PASSED [ 43%]
tests/test_defects.py::test_guards_survive_optimize[decode_two_options_mig-python3] PASSED [ 44%]
tests/test_defects.py::test_guards_survive_optimize[decode_two_options_mig-python3-O] PASSED [ 45%]
tests/test_defects.py::test_guards_survive_optimize[npn_validate_corrupt_csv-python3] PASSED [ 46%]
tests/test_defects.py::test_guards_survive_optimize[npn_validate_corrupt_csv-python3-O] PASSED [ 48%]
tests/test_defects.py::test_guards_survive_optimize[witness_leg_solver_failure-python3] PASSED [ 49%]
tests/test_defects.py::test_guards_survive_optimize[witness_leg_solver_failure-python3-O] PASSED [ 50%]
tests/test_defects.py::test_guards_survive_optimize[amo_shared_requires_n-python3] PASSED [ 51%]
tests/test_defects.py::test_guards_survive_optimize[amo_shared_requires_n-python3-O] PASSED [ 53%]
tests/test_defects.py::test_no_assert_as_verdict_guard_in_package PASSED [ 54%]
tests/test_defects.py::test_no_sys_path_insert_in_package PASSED         [ 55%]
tests/test_drat_verdict.py::test_battery_all_readers_agree[not_verified_substring_trap] PASSED [ 56%]
tests/test_drat_verdict.py::test_battery_all_readers_agree[not_verified_rc1] PASSED [ 58%]
tests/test_drat_verdict.py::test_battery_all_readers_agree[verified_then_nonzero_exit] PASSED [ 59%]
tests/test_drat_verdict.py::test_battery_all_readers_agree[killed_sigkill] PASSED [ 60%]
tests/test_drat_verdict.py::test_battery_all_readers_agree[memout_no_status_line] PASSED [ 62%]
tests/test_drat_verdict.py::test_battery_all_readers_agree[empty_output] PASSED [ 63%]
tests/test_drat_verdict.py::test_battery_all_readers_agree[timeout_status] PASSED [ 64%]
tests/test_drat_verdict.py::test_battery_all_readers_agree[timeout_message_only] PASSED [ 65%]
tests/test_drat_verdict.py::test_battery_all_readers_agree[verified_plain] PASSED [ 67%]
tests/test_drat_verdict.py::test_battery_all_readers_agree[verified_after_carriage_return] PASSED [ 68%]
tests/test_drat_verdict.py::test_usage_errors_are_exit_2 PASSED          [ 69%]
tests/test_drat_verdict.py::test_real_proof_and_empty_proof PASSED       [ 70%]
tests/test_encoder_regression.py::test_manifest_pins_regenerate_byte_identical PASSED [ 72%]
tests/test_encoder_regression.py::test_opt_witness_rows_regenerate_byte_identical PASSED [ 73%]
tests/test_encoder_regression.py::test_tree_chain_pins_regenerate_byte_identical PASSED [ 74%]
tests/test_gates.py::test_gate[gate_xag.py-GATE X1+X2: PASSED] PASSED    [ 75%]
tests/test_gates.py::test_gate[gate_mig.py-GATE M1+M2: PASSED] PASSED    [ 77%]
tests/test_npn.py::test_lookup_known_classes PASSED                      [ 78%]
tests/test_npn.py::test_full_validation PASSED                           [ 79%]
tests/test_reverify_and_chain.py::test_reverify_good_and_adulterated PASSED [ 81%]
tests/test_reverify_and_chain.py::test_reverify_missing_dir PASSED       [ 82%]
tests/test_reverify_and_chain.py::test_certify_refuses_without_toolchain PASSED [ 83%]
tests/test_reverify_and_chain.py::test_zc_chain_n4_flagship PASSED       [ 84%]
tests/test_reverify_and_chain.py::test_forced_multi_chain_n4_base PASSED [ 86%]
tests/test_reverify_and_chain.py::test_witness_n4_base_full_and_tree_chain PASSED [ 87%]
tests/test_reverify_and_chain.py::test_witness_flagship_n5_quick PASSED  [ 88%]
tests/test_simulate_and_convention.py::test_independent_simulator_agrees_with_encoder_simulator[aig] PASSED [ 89%]
tests/test_simulate_and_convention.py::test_independent_simulator_agrees_with_encoder_simulator[xag] PASSED [ 91%]
tests/test_simulate_and_convention.py::test_independent_simulator_agrees_with_encoder_simulator[mig] PASSED [ 92%]
tests/test_simulate_and_convention.py::test_bit_convention_is_load_bearing[aig] PASSED [ 93%]
tests/test_simulate_and_convention.py::test_bit_convention_is_load_bearing[xag] PASSED [ 94%]
tests/test_simulate_and_convention.py::test_bit_convention_is_load_bearing[mig] PASSED [ 96%]
tests/test_tools.py::test_scrub_package_is_clean PASSED                  [ 97%]
tests/test_tools.py::test_scrub_plants_are_detected PASSED               [ 98%]
tests/test_tools.py::test_scrub_flags_an_infringing_file PASSED          [100%]
============================= slowest 15 durations =============================
100.63s call     tests/test_npn.py::test_full_validation
62.95s call     tests/test_reverify_and_chain.py::test_witness_flagship_n5_quick
49.01s call     tests/test_gates.py::test_gate[gate_mig.py-GATE M1+M2: PASSED]
23.32s call     tests/test_gates.py::test_gate[gate_xag.py-GATE X1+X2: PASSED]
7.11s call     tests/test_reverify_and_chain.py::test_witness_n4_base_full_and_tree_chain
7.04s call     tests/test_reverify_and_chain.py::test_forced_multi_chain_n4_base
3.56s call     tests/test_bases_n3.py::test_bases_agree_on_npn3_classes
3.53s call     tests/test_reverify_and_chain.py::test_zc_chain_n4_flagship
3.24s call     tests/test_encoder_regression.py::test_manifest_pins_regenerate_byte_identical
1.85s call     tests/test_encoder_regression.py::test_tree_chain_pins_regenerate_byte_identical
0.71s call     tests/test_drat_verdict.py::test_real_proof_and_empty_proof
0.57s call     tests/test_drat_verdict.py::test_battery_all_readers_agree[verified_then_nonzero_exit]
0.56s call     tests/test_drat_verdict.py::test_battery_all_readers_agree[killed_sigkill]
0.56s call     tests/test_drat_verdict.py::test_battery_all_readers_agree[memout_no_status_line]
0.54s call     tests/test_drat_verdict.py::test_battery_all_readers_agree[timeout_status]
======================== 79 passed in 279.25s (0:04:39) ========================
real 279,66
user 238,37
sys 19,33
EXIT=0
```
