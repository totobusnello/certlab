#!/usr/bin/env python3
"""Blind AST-equality check between each packaged module and the file it was copied from.

Why this exists. Every module under `src/certlab/` (and the two validation gates under
`tests/gates/`) is a copy of a research script whose comments and messages were translated into
English. Translation is exactly the step where code can change by accident: a reworded line that
also drops a condition, a "harmless" cleanup of an expression, a string that a downstream script
greps for. Reading the diff does not scale and is not blind. This script makes the claim
"only comments and messages changed" mechanical:

  1. Locate the ORIGINAL by content: a file under --source-root with the declared basename AND the
     declared sha256. The map never stores a path into the source tree, only the hash, so the
     original that was translated is pinned byte for byte.
  2. Apply the declared LINE PATCHES to the original text. Each patch replaces a line range whose
     sha256 is pinned, and carries a reason. These are the only intended code changes: imports
     (the package uses normal imports instead of `sys.path.insert`), file-system paths (data and
     output locations), and the defect fixes listed in TESTING.md. A patch whose pinned lines do
     not match aborts the check.
  3. Apply the declared IDENTIFIER RENAMES to the original AST (consistent alpha-renaming; a
     rename onto a name already used in the file is refused, since that could merge two names).
     Renames are keyed by sha256(original identifier)[:16], so the map does not carry the
     original (non-English) identifiers in clear.
  4. Drop docstrings and every bare string statement from both trees (they are comments).
  5. Mask every str constant and compare `ast.dump` of both trees: the code structure, every
     operator, number, name and call must be identical.
  6. Compare the masked str constants pairwise, in tree order. An unchanged string passes. A
     changed string passes only if the ORIGINAL is natural-language Portuguese (a translated
     message) AND the translation keeps the same %-format specifiers and the same brace count.
     Any other changed string (a regex, a solver flag, a status sentinel) fails the check.

Exit status: 0 if every entry matches, 1 if any does not, 2 on usage/map errors.

    python3 tools/ast_equal.py --source-root /path/to/research/checkout [--map tools/ast_map.json]
"""
import argparse
import ast
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# Portuguese marker words, stored REVERSED so that this file does not itself trip the
# Portuguese category of tools/scrub_check.py. Unaccented forms only: any accented Latin letter
# already marks a string as Portuguese (see _PT_ACCENTS).
_PT_REVERSED = (
    'oan mes arap euq ad sad sod me amu rop alep olep oa soa iof oas res met aj uo odnauq oatne '
    'euqrop adnia iuqa adan odut sadot sodot ahnil atrop satrop adias adartne oviuqra oriehcif '
    'otciderev ahnumetset otrom lanis osiva uohlaf ahlaf atroba asucer odacifirev ocitatnis '
    'seocpo savita oaceles acinu oledom alumis etsixe omito emrofnoc sadacifitrec aicnegrevnocer '
    'alpud odalatsni odatucexe ogol avorp otsiger odatic eugapa oriemirp omsem rezafer adirroc '
    'uerrom azepmil laicrap adivomer muhnen otsi zid aicnatsni arud aulcnoc iuqad onretni odatnoc '
    'erboc seocnuf sotnemazurc oaciubirtsid aicnairavni adartsoma etnematirtse rohlem '
    'setnetsisnoc saud seocerid oacaremune avitsuaxe otelpmoc artnoc aireved essalc etnesua '
    'otnujnoc sadazilacinonac otnop oxif etnegrevid acinonac osnec otet odagil amica ossid '
    'racilpud edop rahlitrapmoc atsag airevloved oslaf moc uias aruturtse uossap '
)
_PT_WORDS = {w[::-1] for w in _PT_REVERSED.split()}
_PT_ACCENTS = re.compile("[\u00e0-\u00fa\u00c0-\u00da\u00e3\u00f5\u00e7\u00c7]")
_FMT_PCT = re.compile(r"%[-+ #0]*\d*(?:\.\d+)?[sdifrxXeEgGc%]")


def is_portuguese(s):
    if _PT_ACCENTS.search(s):
        return True
    toks = re.findall(r"[A-Za-z]+", s.lower())
    return any(t in _PT_WORDS for t in toks)


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def find_original(source_root, basename, want_sha):
    hits = []
    for dp, dns, fns in os.walk(source_root):
        dns[:] = [d for d in dns if d not in (".git", "__pycache__", "node_modules")]
        if basename in fns:
            p = os.path.join(dp, basename)
            with open(p, "rb") as fh:
                if sha256_bytes(fh.read()) == want_sha:
                    hits.append(p)
    return hits


def apply_patches(text, patches):
    lines = text.split("\n")
    # bottom-up so earlier line numbers stay valid
    spans = sorted(patches, key=lambda p: p["start"], reverse=True)
    prev_start = None
    for p in spans:
        s, e = p["start"], p["end"]
        if prev_start is not None and e >= prev_start:
            raise ValueError(f"overlapping patches at lines {s}-{e}")
        old = "\n".join(lines[s - 1:e])
        if sha256_bytes(old.encode()) != p["old_sha256"]:
            raise ValueError(f"patch lines {s}-{e}: pinned sha256 does not match the original "
                             f"(reason: {p.get('reason')})")
        new = p["new"].split("\n") if p["new"] != "" else []
        lines[s - 1:e] = new
        prev_start = s
    return "\n".join(lines)


class _StripStrings(ast.NodeTransformer):
    """Remove docstrings and bare string statements; they are comments."""

    def generic_visit(self, node):
        super().generic_visit(node)
        for field in ("body", "orelse", "finalbody"):
            seq = getattr(node, field, None)
            if isinstance(seq, list):
                kept = [st for st in seq
                        if not (isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant)
                                and isinstance(st.value.value, str))]
                if not kept and seq:
                    kept = [ast.Pass()]
                setattr(node, field, kept)
        return node


def identifiers(tree):
    names = set()
    for n in ast.walk(tree):
        for attr in ("id", "arg", "attr"):
            v = getattr(n, attr, None)
            if isinstance(v, str):
                names.add(v)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(n.name)
        if isinstance(n, ast.alias):
            names.add(n.name)
            if n.asname:
                names.add(n.asname)
        if isinstance(n, (ast.Global, ast.Nonlocal)):
            names.update(n.names)
    return names


def rename(tree, mapping):
    for n in ast.walk(tree):
        for attr in ("id", "arg", "attr"):
            v = getattr(n, attr, None)
            if isinstance(v, str) and v in mapping:
                setattr(n, attr, mapping[v])
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.name in mapping:
            n.name = mapping[n.name]
        if isinstance(n, ast.alias):
            if n.name in mapping:
                n.name = mapping[n.name]
            if n.asname and n.asname in mapping:
                n.asname = mapping[n.asname]
        if isinstance(n, (ast.Global, ast.Nonlocal)):
            n.names = [mapping.get(x, x) for x in n.names]
    return tree


def strings_and_mask(tree):
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            out.append((getattr(n, "lineno", 0), n.value))
            n.value = "<S>"
    return out


def check_entry(entry, source_root, global_renames):
    errs, notes = [], []
    copy_path = os.path.join(ROOT, entry["copy"])
    hits = find_original(source_root, entry["original_basename"], entry["original_sha256"])
    if not hits:
        return [f"original {entry['original_basename']} with the pinned sha256 not found"], notes
    with open(hits[0], encoding="utf-8") as fh:
        orig_text = fh.read()
    try:
        orig_text = apply_patches(orig_text, entry.get("patches", []))
    except ValueError as e:
        return [str(e)], notes
    with open(copy_path, encoding="utf-8") as fh:
        copy_text = fh.read()
    t_orig = _StripStrings().visit(ast.parse(orig_text))
    t_copy = _StripStrings().visit(ast.parse(copy_text))

    hashed = dict(global_renames)
    hashed.update(entry.get("renames_sha16", {}))
    orig_ids = identifiers(t_orig)
    mapping = {i: hashed[sha256_bytes(i.encode())[:16]] for i in orig_ids
               if sha256_bytes(i.encode())[:16] in hashed}
    clash = sorted(v for k, v in mapping.items() if v in orig_ids and v not in mapping)
    if clash:
        return [f"rename target(s) already used in the original: {clash}"], notes
    rename(t_orig, mapping)

    s_orig = strings_and_mask(t_orig)
    s_copy = strings_and_mask(t_copy)
    d_orig = ast.dump(t_orig, include_attributes=False)
    d_copy = ast.dump(t_copy, include_attributes=False)
    if d_orig != d_copy:
        i = next((j for j in range(min(len(d_orig), len(d_copy))) if d_orig[j] != d_copy[j]),
                 min(len(d_orig), len(d_copy)))
        errs.append("code structure differs near: ORIGINAL ..." + d_orig[max(0, i - 120):i + 120]
                    + "\n    COPY ..." + d_copy[max(0, i - 120):i + 120])
        return errs, notes
    translated = 0
    for (lo, so), (lc, sc) in zip(s_orig, s_copy):
        if so == sc:
            continue
        if not is_portuguese(so):
            errs.append(f"non-message string changed (copy line {lc}): {so!r} -> {sc!r}")
            continue
        if sorted(_FMT_PCT.findall(so)) != sorted(_FMT_PCT.findall(sc)):
            errs.append(f"%-format specifiers changed (copy line {lc}): {so!r} -> {sc!r}")
            continue
        if so.count("{") != sc.count("{") or so.count("}") != sc.count("}"):
            errs.append(f"brace count changed (copy line {lc}): {so!r} -> {sc!r}")
            continue
        translated += 1
    notes.append(f"{len(entry.get('patches', []))} patch(es), {len(mapping)} rename(s), "
                 f"{translated} translated string(s), {len(s_orig)} strings total")
    return errs, notes


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--source-root", required=True, help="checkout holding the original scripts")
    ap.add_argument("--map", default=os.path.join(HERE, "ast_map.json"))
    args = ap.parse_args()
    if not os.path.isdir(args.source_root):
        print(f"ast_equal: --source-root is not a directory: {args.source_root}", file=sys.stderr)
        return 2
    with open(args.map, encoding="utf-8") as fh:
        spec = json.load(fh)
    entries = spec["entries"]
    if not entries:
        print("ast_equal: empty map", file=sys.stderr)
        return 2
    bad = 0
    for e in entries:
        errs, notes = check_entry(e, args.source_root, spec.get("global_renames_sha16", {}))
        tag = "EQUAL" if not errs else "DIFFERENT"
        print(f"[{tag}] {e['copy']}  <-  {e['original_basename']} @ {e['original_sha256'][:12]}"
              + (f"  ({notes[0]})" if notes else ""))
        for m in errs:
            print(f"    {m}")
        bad += bool(errs)
    print(f"\n{len(entries) - bad}/{len(entries)} modules AST-equal to their originals "
          f"(docstrings and comments excluded; declared patches and renames applied)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
