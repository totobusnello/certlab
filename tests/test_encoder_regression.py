"""Every CNF pinned in data/manifest.csv must regenerate byte for byte, in ALL encoder modes.

WHY. The manifest pins the SHA-256 of each certified instance -- that is what lets a reader say
"the formula I verified is the formula you claim". Any change to the encoder that alters one byte
of a CNF silently invalidates those hashes: a paper keeps citing hashes nobody can reproduce, and
the defect only shows when an outside reviewer tries. Three families of pins are covered:

  circuit       AIGEncoder(n, k, tt)                    -> `opt lower bound` / `opt witness` legs
  amo-shared    build_amo_shared(tt, k, n=n)            -> `forced-multi (amo-shared ...)` legs
  formula       AIGEncoder(n, k, tt, formula=True)      -> `tree upper/lower bound (fan-out-1)` legs

COUNT FLOOR: the test requires a MINIMUM number of pins. Without it, a renamed or deleted manifest
row would make the filter match fewer instances and report "all OK" on a set that shrank -- green
by measuring less, the worst kind of green. The floor only goes up together with new pins.
"""
import csv
import hashlib
import os
import re

from conftest import ROOT

from certlab.encoders.aig import AIGEncoder
from certlab.certify.forced_multi import build_amo_shared

MANIFEST = os.path.join(ROOT, "data", "manifest.csv")
WITNESS_DIR = os.path.join(ROOT, "data", "witness")
MIN_PINS = 40   # 28 circuit + 4 amo-shared + 8 formula
WITNESS = {"0x03de0154": (5, 0x03DE0154), "0x09c50800": (5, 0x09C50800),
           "0xabfe03de": (5, 0xABFE03DE), "0x57df03de": (5, 0x57DF03DE)}


def cnf_sha16(nvars, clauses):
    body = [f"p cnf {nvars} {len(clauses)}\n"] + [" ".join(map(str, c)) + " 0\n" for c in clauses]
    return hashlib.sha256("".join(body).encode()).hexdigest()[:16]


def manifest_pins(opt_witness_rows=False):
    pins = []   # (name, mode, n, tt, k, expected sha16)
    with open(MANIFEST) as fh:
        for r in csv.reader(fh):
            if len(r) < 5 or not r[3].strip():
                continue
            name = next((w for w in WITNESS if w in r[0]), None)
            if not name:
                continue
            n, tt = WITNESS[name]
            leg, kfield, sha = r[1], r[2].strip(), r[3].strip()
            m = re.match(r"([0-9a-f]{16})", sha)   # the cell may carry an annotation after the hash
            if not m:
                continue
            sha = m.group(1)
            if "opt lower bound" in leg and kfield.isdigit():
                pins.append((name, "circuit", n, tt, int(kfield), sha))
            elif "opt witness" in leg and kfield.isdigit():
                if opt_witness_rows:
                    pins.append((name, "circuit", n, tt, int(kfield), sha))
            elif "amo-shared" in leg and kfield.isdigit():
                pins.append((name, "amo-shared", n, tt, int(kfield), sha))
            elif "fan-out-1" in leg:
                # 'tree upper bound' pins k=9; 'tree lower bound ... k=1..8' pins the k=8 leg
                k = int(kfield) if kfield.isdigit() else (8 if "1-8" in kfield else None)
                if k:
                    pins.append((name, "formula", n, tt, k, sha))
    return pins


def regenerate(mode, n, tt, k):
    if mode == "circuit":
        e = AIGEncoder(n, k, tt).build()
        return cnf_sha16(e.nvars, e.clauses)
    if mode == "formula":
        e = AIGEncoder(n, k, tt, formula=True).build()
        return cnf_sha16(e.nvars, e.clauses)
    nv, cl = build_amo_shared(tt, k, n=n)[:2]
    return cnf_sha16(nv, cl)


def test_manifest_pins_regenerate_byte_identical():
    pins = manifest_pins()
    by_mode = {}
    for p in pins:
        by_mode[p[1]] = by_mode.get(p[1], 0) + 1
    assert len(pins) >= MIN_PINS, f"only {len(pins)} pins matched (floor {MIN_PINS}): {by_mode}"
    bad = [(name, mode, k, want, got) for name, mode, n, tt, k, want in pins
           if (got := regenerate(mode, n, tt, k)) != want]
    assert not bad, f"{len(bad)} pinned CNF(s) no longer regenerate: {bad}"
    print(f"{len(pins)}/{len(pins)} pinned CNFs regenerate byte-identical {by_mode}")


def test_opt_witness_rows_regenerate_byte_identical():
    """The four `opt witness` (k = 8, SAT) rows, outside the floor of 40."""
    extra = [p for p in manifest_pins(opt_witness_rows=True) if p not in manifest_pins()]
    assert len(extra) == 4, extra
    bad = [p for p in extra if regenerate(p[1], p[2], p[3], p[4]) != p[5]]
    assert not bad, bad


def test_tree_chain_pins_regenerate_byte_identical():
    """The per-leg formula-mode hashes (k = 1..8) of the four n = 5 witnesses."""
    pins = []
    for fn in sorted(os.listdir(WITNESS_DIR)):
        for r in csv.DictReader(open(os.path.join(WITNESS_DIR, fn))):
            if r["mode"] == "formula" and r["cnf_sha16"]:
                pins.append((int(r["tt_hex"], 16), int(r["n"]), int(r["k"]), r["cnf_sha16"]))
    assert len(pins) == 32, len(pins)
    bad = [(hex(tt), k, want) for tt, n, k, want in pins if regenerate("formula", n, tt, k) != want]
    assert not bad, bad
