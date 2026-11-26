# Testing

Recorded on 2026-10-15, macOS (Apple M4), Python 3.14.6, kissat 4.0.4, drat-trim built from
source, pytest 8.2.2, python-sat 1.9.dev5.

Two checks gate the package, and each one is run on inputs it must reject:

| check | command | what it guarantees | proof that it can fail |
|---|---|---|---|
| leak scan | `python3 tools/scrub_check.py` | no match, in any file, for the configured patterns (AI model or vendor name, person name, host, machine path, internal identifier, secret, tool mark, Portuguese word), with a file-scoped allowlist in the script; a pattern scan, not a full confidentiality audit | `--prove`: one planted infringing file per pattern, each must give rc 1 |
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
| `test_defects.py` | section 1 | new |
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

## 4. Phase 2, multi-output encoders (0.2.0)

Recorded on 2026-11-25, same machine and toolchain as above. Two modules were added,
`certlab.encoders.multi_aig` and `certlab.encoders.multi_mig`, translated from the research
scripts that produced the multi-output results cited in README ("How to cite"):
`multi_aig_exact.py` in [10.5281/zenodo.23375519](https://doi.org/10.5281/zenodo.23375519) and
`multi_mig_exact.py` in [10.5281/zenodo.23382607](https://doi.org/10.5281/zenodo.23382607). The translation
was checked against the originals by the same AST-equality procedure as phase 1 (2/2 modules
equal after the declared changes below; the check rejects a planted one-token code change in
either module), and the record is kept with the research repository.

Declared code changes with respect to the originals:

| change | where | why |
|---|---|---|
| `assert` verdict guards (decode, witness re-simulation, kissat exit code, fence sum) are exceptions | both | `python -O` strips asserts; same fix as phase 1 |
| input x_j read as bit j-1 of the row index (was bit n-j) | `multi_aig` | the certlab convention; minimum sizes are invariant under a permutation of the inputs, so only how a decoded circuit is read changes |
| `symbreak` (gate-ordering ladder) removed | `multi_mig` | the ladder only implies its order variables, so setting them all true satisfies it: it constrained nothing; no certificate used it |
| dead assignment removed in `sum_tts` | `multi_mig` | overwritten on the next line |

The multi-output MIG encoder kept the stricter kissat reading of its original (a status line and
the matching exit code). After the review below, both multi-output encoders read the verdict the
same way, stricter than either original (section 4.1).

New tests (`tests/test_multi_output.py`, plus probes in `tests/defect_probes.py`):

| test | what it checks |
|---|---|
| `test_independent_check_rejects_a_flipped_output` | `simulate.check_multi` rejects a witness with one output polarity flipped, and one with an output missing |
| `test_independent_check_is_sensitive_to_the_bit_convention` | an asymmetric two-output witness checks under the certlab convention and fails under the inverted one, in both bases |
| `test_one_gate_below_the_optimum_is_unsat` | full adder: no 6-AND AIG, no 2-MAJ MIG |
| `test_mig_full_adder_and_half_adder` | SUM_3 = 3 and SUM_2 = 3 MAJ gates, witnesses checked independently |
| `test_mig_fences_partition_the_search` | 2^(k-1) fences; over all fences, SUM_3 is UNSAT at k = 2 and SAT at k = 3 |
| `test_mig_input_symmetry_break_keeps_the_optimum` | with `sym_inputs`, SUM_3 is still UNSAT at 2 and SAT at 3 |
| `test_mig_sum5_has_no_six_gate_circuit` | SUM_5 at k = 6 is UNSAT, no symmetry breaking (~15 s) |
| `test_mig_par5_is_six` (slow) | PAR_5 through the multi-output encoder with one output: UNSAT at 5, SAT at 6 |
| `test_aig_audit_rows` | six rows of an exhaustive audit of a published multi-output AIG database at n = 3: UNSAT at the exact size minus one, SAT at the exact size (the database's size is a fixture value, not recomputed); extended in 4.1 |
| `test_aig_full_adder_is_seven` | SUM_3 = 7 AND gates |
| `test_one_output_reproduces_single_output` | with one output, both encoders give the single-output size on 15 functions of n = 3 |
| `test_f_and_not_f_cost_opt_f` | (f, NOT f) costs the size of f, both bases |
| `test_trivial_multi_both_encoders` | k = 0 detection, positive and negative |
| probes `solver_failure_multi_*`, `bad_model_multi_*`, `decode_two_options_multi_*`, `decode_two_output_nodes_multi_*`, `fence_must_sum_to_k_multi_mig` | every guard raises, with and without `python3 -O` (fake kissat in four failure modes; a decodable SAT model that computes NOR for an AND target) |

The test functions themselves use plain `assert` (pytest); the `python3 -O` coverage is the
probes, which run in a subprocess. Leak scan after the change: `scrub_check: 0 finding(s)`, and a
planted name in each of the three new files is detected (rc 1).

Full run, including the slow tests (`python3 -m pytest -q --durations=8 tests`):

```
129 passed in 339.20s (0:05:39)
119.71s call     tests/test_multi_output.py::test_mig_par5_is_six
80.58s call     tests/test_npn.py::test_full_validation
41.82s call     tests/test_reverify_and_chain.py::test_witness_flagship_n5_quick
31.56s call     tests/test_gates.py::test_gate[gate_mig.py-GATE M1+M2: PASSED]
15.29s call     tests/test_multi_output.py::test_mig_sum5_has_no_six_gate_circuit
```

Not covered: SUM_5 = 9 itself (the k = 8 UNSAT took hours and a 59 GB proof), SUM_6 and SUM_7,
DRAT certification of multi-output lower bounds (the encoders write plain CNF; nothing in the
multi-output path calls drat-trim yet), and a multi-output CLI.

### 4.1 Review fixes before release (2026-11-26)

Two read-only reviews of the 0.2.0 candidate (models of two other families, under the author's
direction) reported the defects below; each was reproduced before it was fixed. The tests listed
after the table fail on the candidate and pass now, except the wiring of the independent check
into `solve_k`, which got its discriminating test only in 4.2.

| defect in the candidate | where | fix |
|---|---|---|
| an iterator of tables was consumed by the k = 0 test, so the encoder saw fewer outputs: `opt_multi(2, iter([6, 8]))` returned 1 (the answer is 3) | both | the tables are read once into a list on entry (`_multi_common.check_tables`) |
| a table larger than 2^(2^n) was read on its low bits: `opt_multi(2, [24])` returned 1 | both | `0 <= tt < 2**(2**n)`, `n >= 1` and at least one output are required (`ValueError`) |
| `fence=()` was read as "no fence": `solve_k(2, [8], 1, fence=())` searched unrestricted and returned SAT; levels of size 0 were accepted | `multi_mig` | `None` means no fence; any other value must be an ordered partition of k into non-empty levels (`ValueError`) |
| the verdict was read by substring over the whole output: a comment quoting `s UNSATISFIABLE` turned a SAT run into UNSAT (MIG), and exit code 10 was accepted without a status line (AIG) | both | exactly one status line (a line starting with `s `), agreeing with the exit code, else `RuntimeError` (`_multi_common.kissat_verdict`) |
| `check_multi` validated the basis inside the gate loop, so with no gates it accepted `"xag"`; the encoders' `verify_multi` accepted more outputs than tables | `simulate`, both | basis checked first; `len(outs) == len(tts)` required |
| SAT answers were checked only by each encoder's own simulator, and `multi_mig.solve_k` did not decode at all unless `return_circuit=True` | both | every SAT answer is decoded and checked by `verify_multi` and by the independent `certlab.simulate.check_multi` before it is reported; `return_circuit` only decides what is returned, and the `verify` argument of `opt_multi_via_sat` is removed (made a deprecated, ignored argument in 4.2) |

Tests added or tightened:

| test | what it checks |
|---|---|
| `test_an_iterator_of_tables_gives_the_same_answer_as_a_list` | XOR and AND of two inputs cost 3 in both bases, with the tables given as an iterator |
| `test_tables_out_of_range_are_rejected` | `[24]`, `[-1]`, `[8, 16]` at n = 2, n = 0, and no outputs raise `ValueError` in every entry point of both encoders |
| `test_invalid_fences_are_rejected` | `()` for k = 1, levels of size 0 or negative, and a wrong sum raise `ValueError` |
| `test_check_multi_rejects_an_unsupported_basis_even_without_gates`, `test_verify_multi_requires_one_output_per_table` | the two acceptance gaps above |
| `test_mig_fence_restricts_the_search` | discriminating control: SUM_3 at k = 3 is UNSAT under the fence (3,) and SAT under (1, 1, 1), witness checked independently |
| `test_mig_input_symmetry_break_constrains_the_first_gate` | with inputs 1 and 2 symmetric, every option of gate 1 that reads x_2 without x_1 gets a unit clause, and the plain encoding has none |
| `test_aig_audit_rows`, `test_mig_par5_is_six` | UNSAT at every k below the stated minimum, not only at k - 1: exact-k satisfiability is not monotone in k here, since every gate must be used |
| `test_one_output_reproduces_single_output`, `test_f_and_not_f_cost_opt_f` | compared with fixed reference sizes (`REF_N3`) instead of only encoder against encoder |
| probes `verdict_*_multi_aig`, `verdict_*_multi_mig` | fake kissat with a correct model: a comment quoting a status is ignored (SAT returned); a missing status line, two status lines, or a status that contradicts the exit code raise `RuntimeError` |
| `bad_model_*`, `decode_*`, fence and the other non-solver probes | each pins the exception type and the start of the guard's message (`defect_probes.EXPECT`), so an unrelated error in the call does not pass for the guard (the `solver_failure_*` probes were pinned in 4.2) |

Full run after the fixes, in a working copy (`python3 -m pytest -q --durations=8 tests`, then the
same under `python3 -O`):

```
1 failed, 159 passed in 652.05s (0:10:52)
1 failed, 159 passed, 1 warning in 709.16s (0:11:49)     # python3 -O
237.83s call     tests/test_multi_output.py::test_mig_par5_is_six
```

The one failure, in both runs, is `test_scrub_package_is_clean` reading the working copy's `.git`
pointer file, which holds a local path and is not part of the package (in the `-O` run it also
read the log of the first run, kept in the working copy); on a `git archive` export of the commit
the scan reports 0 findings and `tests/test_tools.py` passes.

### 4.2 Second review round (2026-11-26)

A second read-only review of the fixed candidate reported the items below. Each defect was
reproduced, and its test failed before the fix, except where the table says the test guards
behaviour that was already right.

| item | where | fix | test |
|---|---|---|---|
| two contradictory drat-trim status lines (`s VERIFIED` then `s TIMEOUT`, rc 0) read as VERIFIED by `check_drat.sh` and as TIMEOUT by the Python reader | both DRAT readers | contradictory status lines are a checker failure: exit 4 / `CHECKER_FAILED_contradictory_status` (CHANGELOG, "Changed contract") | four new cases in `tests/drat_battery.py`, run against `check_drat.sh`, `drat_verify_detailed` and `certlab check-drat` (`test_battery_all_readers_agree`) |
| the table checks of 4.1 rejected n = 0 (`sum_tts(0)`, the constants `[0, 1]`, size 0 before) and integer types other than int | both encoders | n >= 0; tables through `operator.index`, width by `tt.bit_length() <= 2**n`; an empty output list still raises (declared in the CHANGELOG) | `test_zero_inputs_and_integer_like_tables_are_accepted`; `test_tables_out_of_range_are_rejected` extended (n = 0 with `[2]`, n = -1, floats, strings) |
| a negative `k` or `kmax` could answer through the k = 0 shortcut (`solve_k(2, [10], -1)` SAT, `kmax=-1` gave 0) | both encoders | `k` and `kmax` must be >= 0, checked before the shortcut | `test_negative_sizes_are_rejected_before_the_k0_shortcut` |
| `verify_multi` called directly accepted `[24]` at n = 2 | both encoders | it applies the same table checks | `test_tables_out_of_range_are_rejected` (the two `verify_multi` calls) |
| nothing in the suite guarded the wiring of `check_multi` into `solve_k`: correct models pass either way, and the planted bad model is caught first by `verify_multi` | both encoders | (wiring already right) | `test_solve_k_rejects_a_witness_the_independent_simulator_rejects`: `check_multi` replaced by a function returning False, a correct AND witness must raise the specific `RuntimeError`, in the MIG with default arguments too |
| the dangerous verdict, exit code 20 with a `s SATISFIABLE` line, was not a permanent probe | both encoders | (reader already right) | probes `verdict_sat_line_with_unsat_exit_code_multi_*` |
| `solver_failure_*` probes accepted any `RuntimeError` | probes | (guards already right) | `defect_probes.SOLVER_FAILURE_EXPECT` pins the message |
| `opt_multi_via_sat(..., verify=...)` raised `TypeError` after 4.1 | `multi_mig` | `verify` accepted, deprecated and ignored (`DeprecationWarning`); verification always on | `test_opt_multi_via_sat_still_accepts_verify_and_always_verifies` (keyword and positional; with `verify=False` and the independent check forced to fail, it still raises) |

README, the `CITATION.cff` abstract and this file now say what each path checks: the single-output
certification workflow checks DRAT proofs with drat-trim; `certlab synth` and multi-output
optimization use the solver's verdict for lower bounds; both multi-output `solve_k` APIs
independently simulate every decoded SAT witness. `CITATION.cff` lists
10.5281/zenodo.23382607 among its references.

Full run after the second round, in a working copy (`python3 -m pytest -q --durations=5 tests`,
then the same under `python3 -O`):

```
1 failed, 180 passed in 494.29s (0:08:14)
1 failed, 180 passed, 1 warning in 507.35s (0:08:27)     # python3 -O
179.39s call     tests/test_multi_output.py::test_mig_par5_is_six
```

The one failure is again `test_scrub_package_is_clean` reading the working copy's `.git` pointer
file (and, in the `-O` run, the log of the first run); on a `git archive` export of the commit the scan reports 0 findings and
`tests/test_tools.py` passes.

