"""tools/scrub_check.py, including its failure paths."""
import os
import shutil
import subprocess
import sys

from conftest import ROOT


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

