"""NPN canonicalisation (n = 4) against the census CSV."""
import pytest

from certlab import npn


def test_lookup_known_classes():
    census, rows = npn.load_census()
    assert len(census) == 222
    for r in rows[:40]:
        dec = int(r["npn_rep_dec"])
        assert npn.npn_canon(dec) == dec          # (a) on a sample, fast
    assert npn.opt_lookup(census, 0x03de) == (6, 0x03de)
    # an NPN transform of 0x03de lands on the same class
    t = npn._negate_output(npn._negate_input(npn._permute_inputs(0x03de, (2, 0, 3, 1)), 1))
    assert npn.opt_lookup(census, t) == (6, 0x03de)


@pytest.mark.slow
def test_full_validation():
    """(a) all 222 representatives are fixed points; (b) the 65536 functions give exactly them."""
    census = npn.validate()
    assert len(census) == 222
