# certlab

Exact synthesis of small Boolean circuits by SAT, with lower bounds certified by DRAT proofs.

certlab answers questions of the form "what is the smallest circuit computing f?" for
single-output functions of up to five or six inputs, in three bases:

- **AIG**: 2-input AND gates, inversions free on every edge (size = number of AND gates);
- **XAG**: AND and XOR gates;
- **MIG**: 3-input majority gates with a constant input.

Each encoder also has a **formula mode** (every gate has fan-out 1), which gives the smallest
formula (`tree`) instead of the smallest circuit (`opt`).

A size bound is only as good as its evidence, so the package separates the two directions:

- **upper bound**: a satisfying assignment is decoded into a circuit and re-simulated on the whole
  truth table, by the encoder's own simulator and by an independent one (`certlab.simulate`);
- **lower bound**: "no circuit with k gates" is an UNSAT result, certified by a DRAT proof checked
  with `drat-trim`, and read by one documented verdict (`scripts/check_drat.sh`, exit codes
  0 verified / 1 refuted / 2 usage / 3 time limit / 4 checker failed).

On top of the encoders, the certification chain proves structural facts about **all** optimal
circuits of a function, for example that every size-optimal AIG has at least two reconvergent
gates ("forced multiple reconvergence"): the at-most-one-shared constraint is added to the
encoding at `k = opt` and the result is UNSAT with a DRAT proof, with no symmetry breaking.

This is release 0.1 (phase 1, single-output). Multi-output encoders, depth-bounded encoders,
multiplicative complexity and VeriPB-certified symmetry breaking are not included.

## Installation

Requirements: Python 3.9 or later, and two binaries on `PATH`:

- [kissat](https://github.com/arminbiere/kissat) (SAT solver; any 3.x or 4.x release):
  `brew install kissat`, or build from source (`./configure && make`).
- [drat-trim](https://github.com/marijnheule/drat-trim) (proof checker):
  `git clone https://github.com/marijnheule/drat-trim && cd drat-trim && make`, then put the
  `drat-trim` binary on `PATH`.

Then, from a checkout:

```
python3 -m pip install -e .            # add [pysat] for certlab.encoders.aig.solve_k, [test] for pytest
```

The data files (`data/`) are read from the checkout; install in editable mode or point
`CERTLAB_NPN4_CSV` at `data/npn4/npn4_opt_aig.csv`.

## Minimal use

```
# smallest XAG for 3-input parity (prints the circuit as JSON; witness re-simulated)
certlab synth --basis xag --n 3 --tt 0x96

# the CNF of one cell, with the sha256 that data/manifest.csv pins
certlab cnf --basis aig --n 5 --tt 0x03de0154 --k 3 -o k3.cnf
kissat -q k3.cnf k3.drat            # exit 20 = UNSAT, proof written to k3.drat
certlab check-drat k3.cnf k3.drat    # exit 0 = VERIFIED   (or: scripts/check_drat.sh k3.cnf k3.drat)

# regenerate a published witness chain from scratch (opt lower bound with DRAT, witnesses,
# non-canalizing; --full adds the forced-multi certificate, --tree-chain the formula lower bound)
certlab witness 0x03de0154
certlab witness 0x03de --full --tree-chain

# NPN class (n = 4) and its exact AIG size from the census
certlab npn 0x03de
```

From Python:

```python
from certlab.encoders.mig import opt_via_sat, tree_via_sat
opt_via_sat(3, 0x96)            # 3: MIG size of 3-input parity
from certlab.encoders.aig import AIGEncoder
enc = AIGEncoder(5, 8, 0x03DE0154).build()   # enc.nvars, enc.clauses: the CNF of one cell
```

Truth tables are integers: bit `t` is `f(row t)` and input `x_j` is bit `j-1` of `t`.

`synth` reports the smallest `k` of an ascending search; the UNSAT answers below it are
kissat's, **not** DRAT-certified. A certified lower bound is the chain of `certlab witness` or of
`certlab.certify` (every `k < opt` UNSAT with a verified proof). Certificates are written to
`$CERTLAB_CERTS` (default `./certlab_certs`), regenerated witnesses to `$CERTLAB_OUT` (default
`./certlab_generated`).

`scripts/certify.sh <tt> <opt>` is "certify forced-multi (DRAT, no symmetry breaking)" for n = 5
witnesses; it is not a general certification tool. `scripts/reverify.sh DIR` re-checks every
`.drat` of a directory against its `.cnf`.

## Tests

```
python3 -m pytest -m "not slow"     # fast suite (about a minute)
python3 -m pytest                   # everything, including the n = 3 validation gates
python3 tools/scrub_check.py        # leak scan of the package (rc 0 = clean)
```

`TESTING.md` lists what each test guarantees, the defects fixed with respect to the research
scripts the package was copied from, and the recorded output of every run.

## How to cite

The encoders and the certification chain were first published inside these deposits; please cite
the one whose results you reproduce, and this package for the software:

- L. A. Busnello, *unit-gap-artefacts: machine-checkable artefacts for a refutation of Theorem 2 of
  arXiv:2603.08033* (title of v1.0.2; v1.1.0 covers Theorems 2 and 7), Zenodo, concept DOI
  [10.5281/zenodo.21630762](https://doi.org/10.5281/zenodo.21630762): the AIG, XAG and MIG
  encoders, the forced-reconvergence witnesses and their regeneration script.
- L. A. Busnello, *opt(0x1669) = opt(0x166b) = 10: CNFs, DRAT proofs for k <= 8 and a normalization
  lemma for the last two open entries of the NPN-4 exact AIG catalog*, Zenodo,
  [10.5281/zenodo.23329385](https://doi.org/10.5281/zenodo.23329385): the AIG encoder.
- L. A. Busnello, *Atlas of the 222 NPN classes of 4-variable Boolean functions in three bases (AIG,
  MIG, XAG)*, Zenodo, concept DOI [10.5281/zenodo.23329554](https://doi.org/10.5281/zenodo.23329554)
  (versions 1.0 and 1.1): the n = 4 tables in the three bases.
- L. A. Busnello, *Exact-synthesis audit of the SPbSAT/simplifier AIG database*, Zenodo, version
  1.0.2, [10.5281/zenodo.23375519](https://doi.org/10.5281/zenodo.23375519): the DRAT verdict
  script.

The software itself: see `CITATION.cff` (no DOI yet).

The MIG results replicate the exact-synthesis catalogue of M. Soeken, L. G. Amarù,
P.-E. Gaillardon and G. De Micheli, "Optimizing Majority-Inverter Graphs with Functional Hashing",
DATE 2016 (Table I).

## Use of generative AI

This software was written with AI models, under the author's direction: Anthropic's Claude for
the code, the encodings and the documentation, and models of other families for read-only review.
The author is responsible for it. Correctness does not rest on the models: upper bounds are checked
by simulation, lower bounds by drat-trim, and the encoders are checked against independent
exhaustive enumerations (tests/).

## Licence

Code: MIT (`LICENSE`), Copyright (c) 2026 Luiz Antonio Busnello.
Data (`data/`): CC BY 4.0 (`data/LICENSE`), except `data/npn4/npn4_opt_aig.csv`, which is
third-party data under MIT (notice in `data/npn4/LICENSE-npn4_opt_aig.txt`).
