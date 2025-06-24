from collections.abc import Generator, Sequence
from typing import Unpack

import gmpy2

from tlp_lib import TLP
from tlp_lib.protocols import (
    GCTLP_Public,
    GCTLP_Public_Input,
    GCTLP_Secret,
    GCTLP_Secret_Input,
    MITLP_Auxiliary_Info,
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


class GCTLP:
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
        self, intervals: Sequence[int], squaring_per_second: int, keysize: int = 2048
    ) -> tuple[GCTLP_Public, GCTLP_Secret]:
        tlp_pk, tlp_sk = self.tlp.setup(1, 1, keysize)
        n, _, r_0 = tlp_pk
        _, _, phi_n, _ = tlp_sk

        t = [gmpy2.mpz(interval * squaring_per_second) for interval in intervals]
        # todo: can I make this more efficient? fixed base
        a = [gmpy2.powmod(2, t_i, phi_n) for t_i in t]

        r = [r_0] + [self.random.gen_random_generator_mod_n(n) for _ in intervals]
        len_r = keysize // 8
        r_bin = [ri.to_bytes(length=len_r) for ri in r]

        len_bytes = COMMITMENT_LENGTH // 8
        d = [self.random.gen_random_bytes(len_bytes) for _ in intervals]

        aux = MITLP_Auxiliary_Info(self.hash.name, len_bytes, len_r)

        return GCTLP_Public(aux, n, t, r_0), GCTLP_Secret(a, r_bin, d)

    def generate(
        self, m: TLP_Messages, pk: GCTLP_Public_Input, sk: GCTLP_Secret_Input
    ) -> tuple[TLP_Puzzles, TLP_Digests]:
        _, n, t, _ = pk
        a, r, d = sk
        z = len(m)
        if len(d) != z:
            raise ValueError("length of m and d must be equal")
        if len(r) != z + 1:
            raise ValueError("length of r must be one more than m")

        hash_list: TLP_Digests = []
        puzz_list: TLP_Puzzles = []
        for i in range(z):
            pk_i = (n, t[i], gmpy2.mpz.from_bytes(r[i]))

            message = m[i] + d[i]
            hash_list.append(self.hash.digest(message))

            message += r[i + 1]
            puzzle = self.tlp.generate(pk_i, a[i], message)
            puzz_list.append(puzzle)

        return puzz_list, hash_list

    def solve(
        self,
        pk: GCTLP_Public_Input,
        puzz: TLP_Puzzles,
    ) -> Generator[tuple[TLP_Message, TLP_Digest], None, None]:
        aux, n, t, r_i = pk
        _, len_d, len_r = aux
        z = len(puzz)

        for i in range(z):
            s_i = self.tlp.solve((n, t[i], r_i), puzz[i])

            r_i = gmpy2.mpz.from_bytes(s_i[-len_r:])
            message = s_i[:-len_r]

            m_i = message[:-len_d]
            d_i = message[-len_d:]

            yield m_i, d_i

    def verify(self, m: TLP_Message, d: bytes, h: TLP_Digest) -> None:
        assert h == self.hash.digest(m + d)
