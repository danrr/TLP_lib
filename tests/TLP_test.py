import pytest

from tlp_lib import TLP
from tlp_lib.wrappers import SeededRSA


@pytest.mark.parametrize(
    "message",
    [
        b"",
        b"t",
        b"test2",
        b"test2test2test2test2test2",
    ],
)
@pytest.mark.parametrize(
    "seed",
    [
        None,
        1234,
    ],
)
def test_tlp(message: bytes, seed: int | None):
    tlp = TLP(seed=seed)

    pk, sk = tlp.setup(1, 1)
    p = tlp.generate(pk, sk.a, message)
    m = tlp.solve(pk, p)
    if seed is not None:
        assert pk[0] == SeededRSA(seed=seed).gen_key()[0]
    assert m == message
