# Modified implementation to match
# https://doi.org/10.1016/j.ic.2025.105301

from typing import Unpack

from tlp_lib import TLP
from tlp_lib.protocols import (
    TLP_Digest,
    TLP_Digests,
    TLP_Message,
    TLP_Messages,
    TLP_Puzzles,
    TLP_type,
    TLPKwargs,
)
from tlp_lib.wrappers import Random, SHA512Wrapper
from tlp_lib.wrappers.protocols import HashFunc, RandGen

COMMITMENT_LENGTH = 128  # hard coded for hash commitments


class KP_MITLP:
    def __init__(
        self,
        *,
        tlp: TLP_type = TLP,
        hash_func: HashFunc = SHA512Wrapper,
        random: RandGen | None = None,
        seed: int | None = None,
        **kwargs: Unpack[TLPKwargs],
    ):
        if random is None:
            random = Random(seed=seed)
        self.random = random
        self.tlp = tlp(seed=seed, random=self.random, **kwargs)
        self.hash = hash_func

    def setup(
        self, z: int, interval: int, squaring_per_second: int, keysize: int = 2048
    ):
        if z < 1:
            raise ValueError("z must be greater than 0")

        tlp_pk, tlp_sk = self.tlp.setup(interval, squaring_per_second, keysize)
        N, t, a = tlp_pk
        p, q, _, u = tlp_sk

        len_commitment = COMMITMENT_LENGTH // 8
        r = [self.random.gen_random_bytes(len_commitment) for _ in range(z)]

        return (N, t, a, r), (p, q, u)

    def generate(self, m: TLP_Messages, pk, sk):
        N, t, a, r = pk
        _, _, u = sk
        z = len(m)

        hash_list: TLP_Digests = [self.hash.digest(m[0] + r[0])]
        puzz_list: TLP_Puzzles = [self.tlp.generate((N, t, a), u, m[0])]

        for i in range(1, z):
            pk_i = N, t, int.from_bytes(m[i - 1])
            puzzle = self.tlp.generate(pk_i, u, m[i])

            hash_list.append(self.hash.digest(m[i] + r[i]))

            puzz_list.append(puzzle)

        return puzz_list, hash_list

    def solve(
        self,
        pk,
        puzz: TLP_Puzzles,
    ):
        N, t, a, _ = pk
        z = len(puzz)

        m = self.tlp.solve((N, t, a), puzz[0])

        yield m

        for i in range(1, z):
            m = self.tlp.solve((N, t, int.from_bytes(m)), puzz[i])

            yield m

    def verify(self, m: TLP_Message, d: bytes, h: TLP_Digest) -> None:
        assert h == self.hash.digest(m + d)
