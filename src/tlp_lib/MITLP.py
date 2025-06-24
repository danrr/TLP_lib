from collections.abc import Generator
from typing import Unpack

import gmpy2

from tlp_lib import TLP
from tlp_lib.protocols import (
    MITLP_Auxiliary_Info,
    MITLP_Public,
    MITLP_Public_Input,
    MITLP_Secret,
    MITLP_Secret_Input,
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


class MITLP:
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
    ) -> tuple[MITLP_Public, MITLP_Secret]:
        if z < 1:
            raise ValueError("z must be greater than 0")

        tlp_pk, tlp_sk = self.tlp.setup(interval, squaring_per_second, keysize)
        n, t, r_0 = tlp_pk
        _, _, _, a = tlp_sk

        r = [r_0] + [self.random.gen_random_generator_mod_n(n) for _ in range(z - 1)]
        len_r = keysize // 8
        r_bin = [ri.to_bytes(length=len_r) for ri in r]
        len_commitment = COMMITMENT_LENGTH // 8
        d = [self.random.gen_random_bytes(len_commitment) for _ in range(z)]

        aux = MITLP_Auxiliary_Info(self.hash.name, len_commitment, len_r)

        return MITLP_Public(aux, n, t, r_0), MITLP_Secret(a, r_bin, d)

    def generate(
        self, m: TLP_Messages, pk: MITLP_Public_Input, sk: MITLP_Secret_Input
    ) -> tuple[TLP_Puzzles, TLP_Digests]:
        # todo: generator function?
        _, n, t, _ = pk
        a, r, d = sk
        z = len(m)
        if len(r) != z or len(d) != z:
            raise ValueError("length of m, r, and d must be equal")

        hash_list: TLP_Digests = []
        puzz_list: TLP_Puzzles = []
        for i in range(z):
            pk_i = n, t, gmpy2.mpz.from_bytes(r[i])

            message = m[i] + d[i]
            hash_list.append(self.hash.digest(message))

            if i != z - 1:
                message += r[i + 1]
            puzzle = self.tlp.generate(pk_i, a, message)
            puzz_list.append(puzzle)

        return puzz_list, hash_list

    def solve(
        self,
        pk: MITLP_Public_Input,
        puzz: TLP_Puzzles,
    ) -> Generator[tuple[TLP_Message, TLP_Digest], None, None]:
        aux, n, t, r_i = pk
        _, len_d, len_r = aux
        z = len(puzz)

        for i in range(z):
            s_i = self.tlp.solve((n, t, r_i), puzz[i])

            if i < z - 1:
                r_i = s_i[-len_r:]
                r_i = gmpy2.mpz.from_bytes(r_i)
                message = s_i[:-len_r]
            else:
                message = s_i

            m_i = message[:-len_d]
            d_i = message[-len_d:]

            yield m_i, d_i

    def verify(self, m: TLP_Message, d: bytes, h: TLP_Digest) -> None:
        assert h == self.hash.digest(m + d)
