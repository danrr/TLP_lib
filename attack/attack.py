import ctypes

from benchmarks.consts import SQUARINGS_PER_SEC
from KP_MITLP import KP_MITLP
from multiprocessing import Pool

from tlp_lib.wrappers import FernetWrapper

if __name__ == "__main__":
    messages = [
        int.to_bytes(1),
        int.to_bytes(0),
        int.to_bytes(0),
        int.to_bytes(1),
        int.to_bytes(0),
        int.to_bytes(1),
    ]

    mitlp = KP_MITLP()
    z = len(messages)
    pk, sk = mitlp.setup(z, 60, SQUARINGS_PER_SEC[2048])
    _, _, _, r = pk
    puzz_list, hash_list = mitlp.generate(messages, pk, sk)
    for puzz in puzz_list[1:]:
        enc_key, enc_mess = puzz
        sym_enc = FernetWrapper()
        try:
            print(sym_enc.decrypt(enc_key, enc_mess))
        except ValueError:
            print(sym_enc.decrypt(enc_key - 1, enc_mess))
