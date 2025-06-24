from typing import Literal

import pytest

from tlp_lib import GCTLP


@pytest.mark.parametrize("keysize", [1024, 2048])
@pytest.mark.parametrize(
    "messages, intervals",
    [
        ([b""], [1]),
        ([b"test1"], [1]),
        ([b"test1", b"test2"], [1, 2]),
        ([b"test1", b"test2", b"test1", b"test2"], [1, 2, 1, 2]),
    ],
)
def test_gctlp(
    keysize: Literal[1024, 2048], messages: list[bytes], intervals: list[int]
):
    gctlp = GCTLP()
    pk, sk = gctlp.setup(intervals, 1, keysize=keysize)
    puzz_list, hash_list = gctlp.generate(messages, pk, sk)
    s = gctlp.solve(pk, puzz_list)
    for i, (m, d) in enumerate(s):
        assert m == messages[i]
        gctlp.verify(m, d, hash_list[i])
