from typing import Literal

import pytest

from .KP_MITLP import KP_MITLP


@pytest.mark.parametrize("keysize", [1024, 2048])
@pytest.mark.parametrize(
    "messages",
    [
        [b""],
        [b"t"],
        [b"test"],
        [b"test1", b"test2"],
        [b"test1", b"test2", b"test2", b"test2", b"test2"],
    ],
)
@pytest.mark.parametrize("hash_messages", [False, True])
def test_kp_mitlp(
    keysize: Literal[1024, 2048], messages: list[bytes], hash_messages: bool
):
    mitlp = KP_MITLP(hash_messages=hash_messages)
    z = len(messages)
    pk, sk = mitlp.setup(z, 1, 1, keysize=keysize)
    _, _, _, r = pk
    puzz_list, hash_list = mitlp.generate(messages, pk, sk)
    s = mitlp.solve(pk, puzz_list)
    for i, m in enumerate(s):
        assert m == messages[i]
        mitlp.verify(m, r[i], hash_list[i])
