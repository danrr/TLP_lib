# Modified implementation to match
# https://doi.org/10.1016/j.ic.2025.105301
from typing import Unpack

import gmpy2

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
        hash_messages: bool = False,
        **kwargs: Unpack[TLPKwargs],
    ):
        if random is None:
            random = Random(seed=seed)
        self.random = random
        self.tlp = tlp(seed=seed, random=self.random, **kwargs)
        self.hash = hash_func
        self.hash_messages = hash_messages

    def setup(
        self, z: int, interval: int, squaring_per_second: int, keysize: int = 2048
    ):
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

        hash_list: TLP_Digests = []
        puzz_list: TLP_Puzzles = []

        base = a
        for i in range(z):
            pk_i = N, t, base
            puzzle = self.tlp.generate(pk_i, u, m[i])
            puzz_list.append(puzzle)
            hash_list.append(self.hash.digest(m[i] + r[i]))
            base = gmpy2.mpz(
                int.from_bytes(self.hash.digest(m[i]) if self.hash_messages else m[i])
            )

        return puzz_list, hash_list

    def solve(
        self,
        pk,
        puzz: TLP_Puzzles,
    ):
        N, t, a, _ = pk
        z = len(puzz)
        base = a
        for i in range(z):
            m = self.tlp.solve((N, t, base), puzz[i])
            base = gmpy2.mpz(
                int.from_bytes(self.hash.digest(m) if self.hash_messages else m)
            )
            yield m

    def verify(self, m: TLP_Message, d: bytes, h: TLP_Digest) -> None:
        assert h == self.hash.digest(m + d)
