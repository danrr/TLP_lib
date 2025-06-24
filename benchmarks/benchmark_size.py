import sys
from typing import Any

from consts import KEYSIZE, SEED, SQUARINGS_PER_SEC

from benchmarks.utils import try_make_process_rude
from tlp_lib import GCTLP, MITLP
from tlp_lib.protocols import GCTLP_Public, GCTLP_Secret, MITLP_Public, MITLP_Secret

INSTANCES = [10**i for i in range(0, 6)]
FIXED_INTERVALS = [10**i for i in range(0, 9)]


def get_size(x: Any) -> int:
    size = sys.getsizeof(x)
    if hasattr(x, "__iter__") and not isinstance(x, str | bytes | bytearray):
        for y in x:
            size += get_size(y)
    return size


def get_size_of_output(
    output: tuple[MITLP_Public, MITLP_Secret] | tuple[GCTLP_Public, GCTLP_Secret],
) -> tuple[int, int, int, int, int, int, int, int, int]:
    (aux, n, t, r_0), (a, r, d) = output
    size_aux = get_size(aux)
    size_n = get_size(n)
    size_t = get_size(t)
    size_pk = size_n + size_t + get_size(r_0) + size_aux
    size_r = get_size(r)
    size_a = get_size(a)
    size_d = get_size(d)
    size_sk = size_r + size_a + size_d
    total_size = size_sk + size_pk
    return (
        size_aux,
        size_n,
        size_t,
        size_r,
        size_a,
        size_d,
        size_pk,
        size_sk,
        total_size,
    )


def benchmark_size(instances: int, fixed_interval: int):
    headings = (
        "Size of aux",
        "Size of n",
        "Size of t",
        "Size of r",
        "Size of a",
        "Size of d",
        "Size of public key",
        "Size of secret key",
        "Total size",
    )

    mitlp = MITLP(seed=SEED)
    gctlp = GCTLP(seed=SEED)

    distinct_intervals = [fixed_interval for _ in range(instances)]
    mitlp_size = get_size_of_output(
        mitlp.setup(
            instances, fixed_interval, SQUARINGS_PER_SEC[KEYSIZE], keysize=KEYSIZE
        )
    )
    gctlp_size = get_size_of_output(
        gctlp.setup(distinct_intervals, SQUARINGS_PER_SEC[KEYSIZE], keysize=KEYSIZE)
    )
    print(f"For {instances} instances of {fixed_interval} seconds each")
    print(f"{'TLP':20} {'MITLP': >20} {'GCTLP': >20} {'Difference': >20}")
    for heading, val1, val2 in zip(headings, mitlp_size, gctlp_size, strict=False):
        print(f"{heading:20} {val1: >20} {val2: >20} {val2 - val1: >20}")


def benchmark():
    fixed_interval = 1
    instances = 1000

    for instances in INSTANCES:
        benchmark_size(instances, fixed_interval)
        print()

    for fixed_interval in FIXED_INTERVALS:
        benchmark_size(instances, fixed_interval)
        print()


if __name__ == "__main__":
    try_make_process_rude()

    print("keysize:", KEYSIZE)
    benchmark()
