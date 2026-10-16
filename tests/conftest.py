import os
import shutil
import stat
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

# certlab.certify.zc_certify and certlab.witness create their output directories at import time;
# keep them out of the working tree during the tests.
_SESSION_TMP = tempfile.mkdtemp(prefix="certlab-tests-")
os.environ.setdefault("CERTLAB_CERTS", os.path.join(_SESSION_TMP, "certs"))
os.environ.setdefault("CERTLAB_OUT", os.path.join(_SESSION_TMP, "generated"))

HAVE_KISSAT = shutil.which("kissat") is not None
HAVE_DRAT_TRIM = shutil.which("drat-trim") is not None

needs_kissat = pytest.mark.skipif(not HAVE_KISSAT, reason="kissat not on PATH")
needs_drat_trim = pytest.mark.skipif(not HAVE_DRAT_TRIM, reason="drat-trim not on PATH")


def make_exe(directory, name, body):
    """Write an executable shell script `name` into `directory`."""
    p = os.path.join(directory, name)
    with open(p, "w") as fh:
        fh.write("#!/bin/sh\n" + body + "\n")
    os.chmod(p, os.stat(p).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return p


def env_with_path_first(directory, extra=None):
    env = dict(os.environ)
    env["PATH"] = directory + os.pathsep + env.get("PATH", "")
    env["PYTHONPATH"] = SRC + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    if extra:
        env.update(extra)
    return env


@pytest.fixture
def fakebin(tmp_path):
    d = tmp_path / "fakebin"
    d.mkdir()
    return str(d)
