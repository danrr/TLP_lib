from tlp_lib.wrappers.Random import Random


class SeededRSA:
    def __init__(self, *, seed: int | None = None):
        self.rand = Random(seed=seed)

    def gen_key(self, *, keysize: int = 2048) -> tuple[int, int, int, int]:
        p = self.rand.gen_random_prime(keysize // 2)
        q = self.rand.gen_random_prime(keysize // 2)
        n = p * q
        phi_n = (p - 1) * (q - 1)
        return n, p, q, phi_n
