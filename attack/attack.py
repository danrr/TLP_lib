import functools

import gmpy2
import time

from benchmarks.consts import SQUARINGS_PER_SEC
from KP_MITLP import KP_MITLP
from multiprocessing import Pool

from tlp_lib.wrappers import FernetWrapper, SHA512Wrapper

messages = [
    int.to_bytes(1),
    int.to_bytes(0),
    int.to_bytes(0),
    int.to_bytes(1),
    int.to_bytes(0),
    int.to_bytes(1),
]
z = len(messages)


def verify_attack():
    """Shows you need hidden randomness in the commitment to prevent guessing"""
    mitlp = KP_MITLP(hash_messages=True)
    pk, sk = mitlp.setup(z, 60, SQUARINGS_PER_SEC[2048])
    _, _, _, r = pk
    puzz_list, hash_list = mitlp.generate(messages, pk, sk)
    for i, puzz in enumerate(puzz_list[1:]):
        try:
            solution = 0
            mitlp.verify(int.to_bytes(solution), r[i + 1], hash_list[i + 1])
        except AssertionError:
            solution = 1
            mitlp.verify(int.to_bytes(solution), r[i + 1], hash_list[i + 1])
        print(solution)

def no_hash_attack():
    """Shows that {0,1} which are common messages (true/false) break the exponentiation"""
    mitlp = KP_MITLP(hash_messages=False)
    pk, sk = mitlp.setup(z, 10, SQUARINGS_PER_SEC[2048])
    N, t, _, r = pk
    puzz_list, hash_list = mitlp.generate(messages, pk, sk)

    t0 = time.time()
    solutions = list(mitlp.solve(pk, puzz_list))
    t1 = time.time()
    print("time for chained solve:", t1 - t0)
    print(solutions)


def __exponentiate_hashed_message(n, t, message: bytes):
    base = gmpy2.mpz(int.from_bytes(SHA512Wrapper.digest(message)))
    for _ in range(t):
        base = base**2 % n
    return int(base)


def hash_attack():
    """Shows that even when hashed, a small, known message space allows an attacker to precompute values and break the TLP"""
    mitlp = KP_MITLP(hash_messages=True)
    pk, sk = mitlp.setup(z, 10, SQUARINGS_PER_SEC[2048])
    N, t, _, r = pk
    puzz_list, hash_list = mitlp.generate(messages, pk, sk)

    t0 = time.time()
    solutions = list(mitlp.solve(pk, puzz_list))
    t1 = time.time()
    print("time for chained solve:", t1 - t0)
    t2 = time.time()
    with Pool(2) as pool:
        sols = pool.map_async(
            functools.partial(__exponentiate_hashed_message, N, t),
            [
                int.to_bytes(0),
                int.to_bytes(1),
            ],
        )
        bypass_solutions = list(mitlp.solve(pk, puzz_list[:1]))
        sols = sols.get()
    for i, puzz in enumerate(puzz_list[1:]):
        enc_key, enc_mess = puzz
        sym_enc = FernetWrapper()
        try:
            solution = sym_enc.decrypt(int((enc_key - sols[0]) % N), enc_mess)
        except (ValueError, OverflowError):
            solution = sym_enc.decrypt(int((enc_key - sols[1]) % N), enc_mess)
        bypass_solutions.append(solution)

    t3 = time.time()
    print("time for attack:", t3 - t2)
    assert solutions == bypass_solutions


if __name__ == "__main__":
    # verify_attack()
    # no_hash_attack()
    hash_attack()
