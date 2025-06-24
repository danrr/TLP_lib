import random
import secrets

import gmpy2


class Random:
    def __init__(self, *, seed: int | None = None):
        if seed is not None:
            self.random_state = gmpy2.random_state(seed)
            self.rand = random.Random(seed)
        else:
            self.random_state = gmpy2.random_state()
            self.rand = secrets.SystemRandom()

    def gen_random_generator_mod_n(self, n: int) -> int:
        while True:
            r = gmpy2.mpz_random(self.random_state, n)
            if gmpy2.gcd(n, r) == 1:
                break
        return r

    def gen_random_prime(self, bits: int) -> int:
        p = gmpy2.mpz_urandomb(self.random_state, bits)
        p |= 1 << (bits // 2 - 1)
        p = gmpy2.next_prime(p)
        return p

    def gen_random_bytes(self, length: int) -> bytes:
        return self.rand.randbytes(length)
