import gmpy2

from tlp_lib.protocols import (
    TLP_Key,
    TLP_Message,
    TLP_Public,
    TLP_Public_Input,
    TLP_Puzzle,
    TLP_Secret,
)
from tlp_lib.wrappers import FernetWrapper, Random, SeededRSA, rsa_gen_key
from tlp_lib.wrappers.protocols import RandGenModN, RSAKeyGen, SymEnc


class TLP:
    def __init__(
        self,
        *,
        sym_enc: SymEnc | None = None,
        gen_modulus: RSAKeyGen | None = None,
        seed: int | None = None,
        random: RandGenModN | None = None,
    ):
        if sym_enc is None:
            sym_enc = FernetWrapper()
        self.sym_enc = sym_enc
        if gen_modulus is None:
            if seed is not None:
                gen_modulus = SeededRSA(seed=seed).gen_key
            else:
                gen_modulus = rsa_gen_key
        self.gen_modulus = gen_modulus
        if random is None:
            random = Random(seed=seed)
        self.gen_random_generator = random.gen_random_generator_mod_n

    def setup(
        self,
        interval: int,
        squarings_per_second: int,
        keysize: int = 2048,
    ) -> TLP_Key:
        n, p, q, phi_n = self.gen_modulus(keysize=keysize)
        r = self.gen_random_generator(n)
        t = gmpy2.mpz(interval) * squarings_per_second
        a = gmpy2.powmod(2, t, phi_n)
        return TLP_Public(n, t, r), TLP_Secret(p, q, phi_n, a)

    def generate(
        self,
        pk: TLP_Public_Input,
        a: int,
        message: TLP_Message,
    ) -> TLP_Puzzle:
        n, _, r = pk

        k = self.sym_enc.generate_key()
        b = gmpy2.powmod(r, a, n)
        encrypted_message = self.sym_enc.encrypt(k, message)
        encrypted_key = int((k + b) % n)
        return TLP_Puzzle(encrypted_key, encrypted_message)

    def solve(self, pk: TLP_Public_Input, puzzle: TLP_Puzzle) -> TLP_Message:
        encrypted_key, encrypted_message = puzzle
        n, t, r = pk

        for _ in range(t):
            r = r**2 % n
        key_int = int((encrypted_key - r) % n)
        message = self.sym_enc.decrypt(key_int, encrypted_message)
        return message
