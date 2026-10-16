"""tools/scrub_check.py and tools/ast_equal.py, including their failure paths.

The AST check needs the original research scripts; set CERTLAB_SOURCE_ROOT to a checkout that
holds them (the files are located by basename + sha256), otherwise those tests are skipped.
"""
import os
import shutil
import subprocess
import sys

import pytest

from conftest import ROOT

SOURCE_ROOT = os.environ.get("CERTLAB_SOURCE_ROOT")
needs_source = pytest.mark.skipif(not SOURCE_ROOT or not os.path.isdir(SOURCE_ROOT),
                                  reason="CERTLAB_SOURCE_ROOT not set")


def run(*args, cwd=None):
    return subprocess.run([sys.executable] + list(args), capture_output=True, text=True, cwd=cwd)


def test_scrub_package_is_clean():
    p = run(os.path.join(ROOT, "tools", "scrub_check.py"))
    assert p.returncode == 0, p.stdout


def test_scrub_plants_are_detected():
    p = run(os.path.join(ROOT, "tools", "scrub_check.py"), "--prove")
    assert p.returncode == 0 and "PASS" in p.stdout, p.stdout


def test_scrub_flags_an_infringing_file(tmp_path):
    copy = tmp_path / "pkg"
    shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", "*.egg-info"))
    (copy / "src" / "certlab" / "leak.py").write_text("# fixed after REV" + "-0042, see /Us" + "ers/x\n")
    p = run(str(copy / "tools" / "scrub_check.py"))
    assert p.returncode == 1 and "internal_id" in p.stdout and "home_path" in p.stdout, p.stdout


@needs_source
def test_ast_equal_passes():
    p = run(os.path.join(ROOT, "tools", "ast_equal.py"), "--source-root", SOURCE_ROOT)
    assert p.returncode == 0, p.stdout


@needs_source
@pytest.mark.parametrize("old,new,what", [
    ("    if r.returncode != 20:\n", "    if r.returncode != 21:\n", "code structure differs"),
    ('r = subprocess.run(["kissat", "-q", path]', 'r = subprocess.run(["kissat", "-v", path]', "non-message string changed"),
])
def test_ast_equal_rejects_a_code_change(tmp_path, old, new, what):
    copy = tmp_path / "pkg"
    shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", "*.egg-info"))
    f = copy / "src" / "certlab" / "encoders" / "xag.py"
    s = f.read_text()
    assert old in s
    f.write_text(s.replace(old, new, 1))
    p = run(str(copy / "tools" / "ast_equal.py"), "--source-root", SOURCE_ROOT)
    assert p.returncode == 1 and what in p.stdout, p.stdout
