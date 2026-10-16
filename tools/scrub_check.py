#!/usr/bin/env python3
"""Leak scan of the whole package before any publication: rc 0 = clean, rc 1 = findings.

Categories:
  ai_model      names of AI models and vendors (hashed list, see below)
  person        names of people (hashed list); the author's name is allowed only in the files
                that carry authorship (LICENSE, CITATION.cff, pyproject.toml, README.md), and the
                third-party data notice may carry its upstream copyright line
  host          names of machines and hosting providers (hashed list) and any IPv4 address
  home_path     the home-directory variable and shortcut, the macOS and Linux home roots, the
                macOS private temporary root -- paths of one machine
  internal_id   identifiers of the research tree: review, experiment and source IDs, claim
                numbers, item numbers, references to logs of model calls and to pull requests,
                paths into the notes directory, the private directory and file names
  secret        API-key and private-key shapes
  tool_mark     tool attribution footers injected into text, and tool names
  portuguese    words of the working language of the research tree (accented letters and a
                lexicon); the package is in English

Why some lists are HASHED: this file is part of the package and is scanned like every other
file. Listing the blocked names in clear would publish them; so single tokens are compared by
sha256(lower(token))[:16]. The other patterns are written so that their own source text does not
match them (character classes, \\u escapes, the lexicon stored reversed). The scan therefore
covers this file too: no self-exclusion.

Proving the scan (a gate that has never rejected anything proves nothing):

    python3 tools/scrub_check.py                  # scan the package
    python3 tools/scrub_check.py --prove          # one planted infringing file per regex pattern
                                                  # and per lexicon word, plus canaries for the
                                                  # hashed lists; each plant must give rc 1, a
                                                  # clean control must give rc 0
    python3 tools/scrub_check.py --prove --plants FILE
                                                  # also plant every clear-text token of FILE
                                                  # (lines "category<TAB>token", kept outside the
                                                  # package) and require that FILE covers every
                                                  # hash of every list
"""
import argparse
import hashlib
import os
import re
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "build", "dist", ".venv", "venv"}
SKIP_SUFFIXES = (".egg-info",)


def _h(token):
    return hashlib.sha256(token.lower().encode()).hexdigest()[:16]


# The canary of each list is a nonsense token whose hash is listed, so that --prove can show the
# hashed matching works without clear text (the canaries are built by concatenation, so that they do not appear here as one token).
CANARY = {"ai_model": "zzcanary" + "model", "person": "zzcanary" + "person",
          "host": "zzcanary" + "host", "tool_mark": "zzcanary" + "mark"}

HASHED = {
    "ai_model": {
        "e4f9c522e1c89280", "57de4cf40144bdf7", "2bf548d8056029c7", "add92b9cde2bdbf3",
        "5d72436256ada538", "6f7ac1823da81d2e", "c857d09db23e6822", "09cf980b5ff304ac",
        "053ea4804ef1bb33", "60965168ce762e94", "e12ce8285efc67c6", "c9ad8f2cc1294afa",
        "5a5110ebe1544b31", "45d780f82c9247fc", "7d3194f79e645c42", "c70eca6b0f88f44d",
        "6749675d80a1faa7", "b5d641b432cca81e", "67f2d22514622d1b", "fc5a1047f5919892",
        "920510199770f4d6", "3ea125d0bff386e6",
    },
    "person": {
        "16542a7fc9760c61", "93aff3f3e133044a", "0e8212763bcaca61", "4b569e80caa6ba1d",
        "680e1d454da8df64", "31f7a65e315586ac",
    },
    "host": {
        "9790b8f4a5994bc8", "cfe062be1bbee227", "8164de150dd69fe8", "fefaa42da40ecf93",
        "795b104abe3e4134", "ec6f049478046f72",
    },
    "tool_mark": {"e0c924608fdcda85", "5394dd39da24db23"},
}
for _c, _t in CANARY.items():
    HASHED[_c].add(_h(_t))

# (file relative to the package root, category, token hash). File-scoped: the same token in any
# other file is still a finding.
_AUTHOR = "4b569e80caa6ba1d"      # first name of the author
_AUTHOR2 = "680e1d454da8df64"     # surname of the author
ALLOW = {
    ("LICENSE", "person", _AUTHOR), ("LICENSE", "person", _AUTHOR2),
    ("data/LICENSE", "person", _AUTHOR), ("data/LICENSE", "person", _AUTHOR2),
    ("CITATION.cff", "person", _AUTHOR), ("CITATION.cff", "person", _AUTHOR2),
    ("pyproject.toml", "person", _AUTHOR), ("pyproject.toml", "person", _AUTHOR2),
    ("README.md", "person", _AUTHOR), ("README.md", "person", _AUTHOR2),
    # third-party data notice: the upstream copyright line and repository URL, verbatim (MIT
    # requires the notice to travel with the data)
    ("data/npn4/LICENSE-npn4_opt_aig.txt", "person", _AUTHOR),
    ("data/npn4/LICENSE-npn4_opt_aig.txt", "person", _AUTHOR2),
    ("data/npn4/LICENSE-npn4_opt_aig.txt", "person", "93aff3f3e133044a"),
    ("data/npn4/LICENSE-npn4_opt_aig.txt", "person", "0e8212763bcaca61"),
    # README, section "Use of generative AI": the standard disclosure names the model and vendor
    ("README.md", "ai_model", "c857d09db23e6822"), ("README.md", "ai_model", "c70eca6b0f88f44d"),
}

REGEX = {
    "host": [r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"],
    "home_path": [r"\$HOM[E]\b", r"(?<![\w.])[~]/", r"/User[s]/", r"/hom[e]/", r"/privat[e]/"],
    "internal_id": [r"\bREV-\d+", r"\bEXP-[A-Z0-9]", r"\bSRC-\d{3,}", r"\b[Cc]laims?\s+0\d{3}\b",
                    r"\b7P-P[N]P", r"\bitem\s+\d+\b", r"\bcall[ -]log\b", r"\bPR\s*#\d+",
                    r"\bnote[s]/", r"\bPNP_A[I]\b", r"\bexp_[a-z0-9]+_[a-z0-9_]+", r"\bINDIC[E]\b",
                    r"\bSTATU[S]\.md\b", r"\bDECISOE[S]"],
    "secret": [r"\bsk-[A-Za-z0-9]{16,}", r"\bgh[pousr]_[A-Za-z0-9]{20,}", r"\bAKI[A][0-9A-Z]{16}\b",
               r"-----BEGIN [A-Z ]*PRIVATE KE[Y]-----", r"\bxox[bpas]-[A-Za-z0-9-]{10,}"],
    "tool_mark": [r"\b[M]ade with\b"],
    "portuguese": ["[\u00e3\u00f5\u00e7\u00c3\u00d5\u00c7\u00e1\u00e9\u00ed\u00f3\u00fa\u00e2\u00ea\u00f4\u00e0]"],
}

# Unambiguous words of the research tree's working language, stored reversed.
_PT_REV = (
    "oan oatne euqrop mebmat adias satrop atrop adartne oviuqra oriehcif otciderev ahnumetset "
    "otsi ossi odnauq adnia iuqa adan ahnil osiva uohlaf atroba asucer odacifirev oriemirp "
    "sezev amu alep olep mes soa ahlaf aicnatsni oacudart"
)
PT_WORDS = sorted(w[::-1] for w in _PT_REV.split())
PT_RE = re.compile(r"\b(?:" + "|".join(PT_WORDS) + r")\b", re.I)
COMPILED = {c: [re.compile(p) for p in ps] for c, ps in REGEX.items()}
TOKEN = re.compile(r"[A-Za-z0-9]+")


def iter_files(root):
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS and not d.endswith(SKIP_SUFFIXES)]
        for fn in fns:
            yield os.path.join(dp, fn)


def scan_text(rel, text):
    out = []
    for i, line in enumerate(text.split("\n"), 1):
        for tok in TOKEN.findall(line):
            hh = _h(tok)
            for cat, hs in HASHED.items():
                if hh in hs and (rel, cat, hh) not in ALLOW:
                    out.append((rel, i, cat, f"blocked token (sha16 {hh})"))
        for cat, pats in COMPILED.items():
            for p in pats:
                m = p.search(line)
                if m:
                    out.append((rel, i, cat, f"pattern {p.pattern!r} matched {m.group(0)!r}"))
        m = PT_RE.search(line)
        if m:
            out.append((rel, i, "portuguese", f"word {m.group(0)!r}"))
    return out


def scan(root):
    findings = []
    for p in iter_files(root):
        rel = os.path.relpath(p, root).replace(os.sep, "/")
        findings += [(rel, 0, c, m) for (_, _, c, m) in scan_text(rel, rel)]   # the path itself
        try:
            with open(p, "rb") as fh:
                raw = fh.read()
            text = raw.decode("utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        findings += scan_text(rel, text)
    return findings


def report(findings, quiet=False):
    if not quiet:
        for rel, i, cat, msg in findings:
            print(f"  {rel}:{i}: [{cat}] {msg}")
    return 1 if findings else 0


def _plants_builtin():
    """(label, text) pairs: one infringing text per regex pattern, per lexicon word, per canary."""
    p = []
    samples = {
        r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])": "ssh to " + ".".join(["203", "0", "113", "7"]) + " now",
        r"\$HOM[E]\b": "export PATH=$" + "HOME/bin",
        r"(?<![\w.])[~]/": "see " + "~" + "/notes",
        r"/User[s]/": "path /" + "Users/someone/x",
        r"/hom[e]/": "path /" + "home/someone/x",
        r"/privat[e]/": "path /" + "private/tmp/x",
        r"\bREV-\d+": "fixed in " + "REV" + "-0113",
        r"\bEXP-[A-Z0-9]": "see " + "EXP" + "-GATE-0001",
        r"\bSRC-\d{3,}": "source " + "SRC" + "-0033",
        r"\b[Cc]laims?\s+0\d{3}\b": "as in " + "claim" + " 0043",
        r"\b7P-P[N]P": "7P-P" + "NP-CLM-0001",
        r"\bitem\s+\d+\b": "see " + "item" + " 33",
        r"\bcall[ -]log\b": "the " + "call" + " log entry",
        r"\bPR\s*#\d+": "merged in " + "PR" + " #141",
        r"\bnote[s]/": "read " + "notes" + "/x.md",
        r"\bPNP_A[I]\b": "under " + "PNP" + "_AI",
        r"\bexp_[a-z0-9]+_[a-z0-9_]+": "dir " + "exp" + "_gate_0001",
        r"\bINDIC[E]\b": "see " + "INDIC" + "E.md",
        r"\bSTATU[S]\.md\b": "see " + "STATUS" + ".md",
        r"\bDECISOE[S]": "see " + "DECISOE" + "S_FECHADAS",
        r"\bsk-[A-Za-z0-9]{16,}": "key " + "sk" + "-" + "A" * 20,
        r"\bgh[pousr]_[A-Za-z0-9]{20,}": "token " + "ghp" + "_" + "B" * 24,
        r"\bAKI[A][0-9A-Z]{16}\b": "id " + "AKIA" + "C" * 16,
        r"-----BEGIN [A-Z ]*PRIVATE KE[Y]-----": "-----BEGIN RSA " + "PRIVATE KEY" + "-----",
        r"\bxox[bpas]-[A-Za-z0-9-]{10,}": "slack " + "xoxb" + "-" + "1" * 12,
        r"\b[M]ade with\b": "Made" + " with SomeTool",
        REGEX["portuguese"][0]: "a palavra " + "s\u00e3o" + " here",
    }
    for cat, pats in REGEX.items():
        for pat in pats:
            p.append((f"{cat}: {pat}", samples[pat]))
    for w in PT_WORDS:
        p.append((f"portuguese word: {w[::-1]} (reversed)", f"text with {w} inside"))
    for cat, tok in CANARY.items():
        p.append((f"{cat}: canary", f"mentions {tok} here"))
    return p


def prove(plants_file=None):
    tmp = tempfile.mkdtemp(prefix="scrub-prove-")
    ok = True
    try:
        control = os.path.join(tmp, "control")
        os.makedirs(control)
        with open(os.path.join(control, "clean.py"), "w") as fh:
            fh.write("# A clean English comment about AND gates and DRAT proofs.\nx = 1\n")
        rc = report(scan(control), quiet=True)
        print(f"  control (clean file)              -> rc {rc} (want 0)")
        ok &= rc == 0

        plants = _plants_builtin()
        if plants_file:
            covered = {c: set() for c in HASHED}
            for line in open(plants_file, encoding="utf-8"):
                line = line.rstrip("\n")
                if not line or line.startswith("#"):
                    continue
                cat, tok = line.split("\t")
                covered[cat].add(_h(tok))
                plants.append((f"{cat}: plaintext token #{len(plants)}", f"some text {tok} more text"))
            for cat, hs in HASHED.items():
                missing = hs - covered[cat] - {_h(CANARY[cat])}
                print(f"  coverage {cat:10s}: {len(hs) - 1 - len(missing)}/{len(hs) - 1} hashes planted")
                ok &= not missing
            # file scoping of the allowlist: an allowed token outside its file is a finding
            for (rel, cat, hh) in sorted(ALLOW):
                tok = next((t for line in open(plants_file, encoding="utf-8") if line.strip()
                            for c, t in [line.rstrip("\n").split("\t")] if _h(t) == hh), None)
                if tok:
                    plants.append((f"{cat}: allowed in {rel} only, planted elsewhere", f"x {tok} y"))
        n_det = 0
        for i, (label, text) in enumerate(plants):
            d = os.path.join(tmp, f"plant{i:03d}")
            os.makedirs(d)
            with open(os.path.join(d, "infringer.txt"), "w", encoding="utf-8") as fh:
                fh.write(text + "\n")
            rc = report(scan(d), quiet=True)
            n_det += rc == 1
            if rc != 1:
                print(f"  NOT DETECTED: {label}")
                ok = False
        print(f"  plants detected: {n_det}/{len(plants)} (each in its own directory, each must give rc 1)")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="Leak scan of the package (rc 0 clean, 1 findings).")
    ap.add_argument("root", nargs="?", default=ROOT)
    ap.add_argument("--prove", action="store_true", help="run the planted-infringer proof instead")
    ap.add_argument("--plants", help="clear-text token list (category<TAB>token) kept OUTSIDE the package")
    a = ap.parse_args()
    if a.prove:
        rc = prove(a.plants)
        print(f"scrub_check --prove: {'PASS' if rc == 0 else 'FAIL'}")
        return rc
    findings = scan(a.root)
    rc = report(findings)
    n = sum(1 for _ in iter_files(a.root))
    print(f"scrub_check: {len(findings)} finding(s) in {n} files under {os.path.basename(os.path.abspath(a.root))}/")
    return rc


if __name__ == "__main__":
    sys.exit(main())
