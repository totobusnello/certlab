"""Atomic, gated CSV writing for result artefacts.

WHY THIS EXISTS. The same defect once produced a bad artefact FOUR times in one day:

  1. A census script saved only inside the compute branch, so a retry run truncated the CSV to 188
     of 222 rows -- cutting a family class -- while its summary printed the complete table from memory.
  2. Running a chain script on a second machine overwrote the CSV harvested from the first one
     (same output path).
  3. A blanket `git add` committed a validation CSV while it was still being written, so a file
     recording spurious FAILs entered the tree and the history.
  4. The same validation run died at 134 of 159 when its shell went away, leaving a silent prefix. The
     completeness gate could not fire: gates run AFTER the loop, and a killed process has no after.

The first fix (write again at the end, `sys.exit(3)` on a short file) addresses only case 1. Cases 2-4
are the same shape from other directions, and the pattern is that **a partial file is indistinguishable
from a finished one**. So make it distinguishable by construction:

    write  ->  <name>.partial      (never a valid artefact name; ignore it in version control)
    gate   ->  row count, and any caller-supplied invariant
    rename ->  <name>              (atomic on POSIX; the final name appears only when valid)

A killed process leaves `<name>.partial`, which no script reads and no result cites. There is no
window in which the real filename holds incomplete content, because `os.replace` is atomic: readers
see either the old file or the new one, never a half-written one.

This also fixes case 2: `write_csv_atomic` refuses to overwrite an existing file when
`overwrite_ok=False` is passed explicitly, so a local smoke test cannot silently clobber a harvested
result.
"""
import csv
import os
import sys


class ArtefactIncomplete(Exception):
    """Raised when the gate rejects a would-be artefact. The .partial file is left on disk for triage."""


def write_csv_atomic(path, fieldnames, rows, expected_rows=None, invariant=None,
                     overwrite_ok=True, quiet=False):
    """Write `rows` to `path` atomically, only if the gate passes.

    path          final artefact path. Content is written to `path + '.partial'` first.
    expected_rows if given, len(rows) must equal it — the completeness gate.
    invariant     optional callable(rows) -> None|str. Return a string to REJECT with that reason.
                  Use for the checks only the caller knows: distinct-class counts, no-timeout-as-verdict,
                  every expected key present.
    overwrite_ok  False refuses to replace an existing file — the guard for case 2, a local run
                  clobbering a harvested artefact.

    Returns the final path. Raises ArtefactIncomplete without touching the final path if the gate fails.
    """
    tmp = path + ".partial"
    with open(tmp, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)
        fh.flush()
        os.fsync(fh.fileno())

    problems = []
    if expected_rows is not None and len(rows) != expected_rows:
        problems.append(f"{len(rows)} rows written, {expected_rows} expected — this is a PREFIX")
    if invariant is not None:
        msg = invariant(rows)
        if msg:
            problems.append(msg)
    if not overwrite_ok and os.path.exists(path):
        problems.append(f"{os.path.basename(path)} already exists and overwrite_ok=False — refusing to "
                        f"clobber a file this run did not produce (it may be a harvested result)")

    if problems:
        raise ArtefactIncomplete(
            f"artefact REJECTED, final file not written. Left at {os.path.basename(tmp)} for triage:\n"
            + "\n".join(f"  - {p}" for p in problems))

    os.replace(tmp, path)   # atomic: readers see the old file or the new one, never a partial
    if not quiet:
        print(f"    artefact written atomically: {os.path.relpath(path)} ({len(rows)} rows)", flush=True)
    return path


def checkpoint_csv(path, fieldnames, rows):
    """Mid-run progress dump for a long job, written ONLY to the .partial name.

    Long runs want their progress on disk in case of a crash, which is what motivated the
    write-after-every-item pattern that caused case 1. Keep the habit, but never let progress land on the
    real filename: that is precisely what made a prefix look like a result. Call this in the loop and
    `write_csv_atomic` once at the end.
    """
    with open(path + ".partial", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def resume_source(path):
    """Where a RESUMABLE producer reads its progress from (added 2026-10-08).

    Progress lives only in `path + '.partial'` (see `checkpoint_csv`), so a run that died mid-way left
    it THERE, not in the final file. Returns the `.partial` if it exists and is non-empty, else the
    final `path` if it does, else None. A `.partial` rejected by the gate of `write_csv_atomic` is
    also a valid source: it holds every row the run produced.
    """
    for p in (path + ".partial", path):
        if os.path.exists(p) and os.path.getsize(p) > 0:
            return p
    return None


def fail(exc):
    """Print an ArtefactIncomplete and exit 3 — the code the harvest tooling already treats as 'do not
    harvest'. Kept here so every producer script reports the same way."""
    print(f"\n  *** {exc} ***\n"
          f"  *** Do not harvest, commit or cite anything from this run. ***", flush=True)
    sys.exit(3)
