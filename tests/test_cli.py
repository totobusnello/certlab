"""Exit codes of every `certlab` subcommand, including the failure paths."""
import json
import os
import subprocess
import sys

from conftest import SRC, env_with_path_first, make_exe, needs_kissat


def run(args, env=None):
    e = dict(env or os.environ)
    e["PYTHONPATH"] = SRC
    p = subprocess.run([sys.executable, "-m", "certlab.cli"] + args, capture_output=True, text=True, env=e)
    return p.returncode, p.stdout, p.stderr


@needs_kissat
def test_synth_found_and_simulate_roundtrip(tmp_path):
    rc, out, _ = run(["synth", "--basis", "xag", "--n", "3", "--tt", "0x96"])
    assert rc == 0
    c = json.loads(out)
    assert c["k"] == 2                      # parity of 3 inputs: 2 XOR gates
    circ = tmp_path / "c.json"
    circ.write_text(out)
    assert run(["simulate", "--basis", "xag", "--n", "3", "--tt", "0x96", "--circuit", str(circ)])[0] == 0
    # adulterated witness: one gate operand changed -> rc 1
    c["gates"][0][0] = "and"
    circ.write_text(json.dumps(c))
    assert run(["simulate", "--basis", "xag", "--n", "3", "--tt", "0x96", "--circuit", str(circ)])[0] == 1
    # unreadable circuit -> rc 2
    circ.write_text("{not json")
    assert run(["simulate", "--basis", "xag", "--n", "3", "--tt", "0x96", "--circuit", str(circ)])[0] == 2


@needs_kissat
def test_synth_none_up_to_kmax():
    assert run(["synth", "--basis", "aig", "--n", "3", "--tt", "0x96", "--kmax", "3"])[0] == 1


def test_synth_solver_failure_and_missing_solver(fakebin):
    make_exe(fakebin, "kissat", "exit 1")
    assert run(["synth", "--basis", "mig", "--n", "2", "--tt", "0x6"], env_with_path_first(fakebin))[0] == 4
    env = env_with_path_first(fakebin)
    env["PATH"] = fakebin + os.pathsep + "/usr/bin:/bin"
    os.remove(os.path.join(fakebin, "kissat"))
    if not os.path.exists("/usr/bin/kissat"):
        assert run(["synth", "--basis", "mig", "--n", "2", "--tt", "0x6"], env)[0] == 3


def test_synth_trivial_and_bad_input():
    rc, out, _ = run(["synth", "--basis", "aig", "--n", "2", "--tt", "0xa"])
    assert rc == 0 and json.loads(out)["k"] == 0
    assert run(["synth", "--basis", "aig", "--n", "2", "--tt", "0x1ff"])[0] == 2
    assert run(["synth", "--basis", "nand", "--n", "2", "--tt", "0x8"])[0] == 2


def test_cnf_matches_manifest_pin(tmp_path):
    out = tmp_path / "k3.cnf"
    rc, stdout, _ = run(["cnf", "--basis", "aig", "--n", "5", "--tt", "0x03de0154", "--k", "3", "-o", str(out)])
    assert rc == 0
    assert "sha16 a4c2ba4cd9869694" in stdout


def test_npn_lookup():
    rc, out, _ = run(["npn", "0x03de"])
    assert rc == 0
    d = json.loads(out)
    assert d["npn_rep"] == "0x03de" and d["opt_aig"] == 6


def test_witness_unknown_tt_refused():
    assert run(["witness", "0x1234"])[0] == 1
