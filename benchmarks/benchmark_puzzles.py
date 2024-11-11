import csv
from datetime import datetime
from multiprocessing import Pool
from operator import itemgetter
from pathlib import Path
from typing import Optional

from consts import KEYSIZE, MESSAGE, SEED, SQUARINGS_PER_SEC
from utils import timer, timer_with_output, try_make_process_rude

from tlp_lib import EDTLP, GCTLP, MITLP, TLP
from tlp_lib.protocols import (
    GCTLP_Encrypted_Message,
    Server_Info,
    TLP_Digest,
    TLP_Message,
    TLP_Public,
    TLP_Puzzle,
    TLP_Secret,
)
from tlp_lib.smartcontracts import EthereumSC, MockSC
from tlp_lib.smartcontracts.protocols import SCInterface
from tlp_lib.wrappers.Keccak256Wrapper import Keccak256Wrapper

SOLVE = True

# todo: store in some format that can be output to csv
# todo: pyplot


def benchmark_time_tlp(instances: int):
    try_make_process_rude()
    output = {
        "name": "TLP",
        "extra": None,
        "instances": instances,
    }

    messages = [MESSAGE] * instances
    distinct_intervals = [FIXED_INTERVAL] * instances
    tlp = TLP(seed=SEED)

    keys: list[tuple[TLP_Public, TLP_Secret]] = []

    def tlp_setup():
        keys.clear()
        seconds = 0
        for i, m in enumerate(messages):
            seconds += distinct_intervals[i]
            keys.append(tlp.setup(seconds, SQUARINGS_PER_SEC[KEYSIZE], KEYSIZE))

    time_setup = timer(tlp_setup)
    output["setup"] = time_setup

    puzzles: list[tuple[TLP_Public, TLP_Puzzle]] = []

    def tlp_generate():
        puzzles.clear()
        for (pk, sk), m in zip(keys, messages):
            puzzles.append((pk, tlp.generate(pk, sk.a, m)))

    time_generate = timer(tlp_generate)
    output["generate"] = time_generate

    # (n, _, _), (p, q, phi_n, _) = tlp.setup(1, SQUARINGS_PER_SEC[KEYSIZE], KEYSIZE)

    # def gen_modulus(*, keysize: int):
    #     # keysize isn't used, as KEYSIZE constant affects instantiation above
    #     return n, p, q, phi_n
    #
    # def tlp_setup_and_generate_fixed_n():
    #     tlp = TLP(seed=SEED, gen_modulus=gen_modulus)
    #     seconds = 0
    #     for i, m in enumerate(messages):
    #         seconds += distinct_intervals[i]
    #         pk, sk = tlp.setup(seconds, SQUARINGS_PER_SEC[KEYSIZE], KEYSIZE)
    #         tlp.generate(pk, sk.a, m)
    #
    # time_fixed_n = timer(tlp_setup_and_generate_fixed_n)
    # output["setup and generate fixed n"] = time_fixed_n

    if not SOLVE or instances >= 100:
        output["total"] = sum((time_setup, time_generate))
        return output

    def tlp_solve_sequentially():
        for pk, puzzle in puzzles:
            tlp.solve(pk, puzzle)

    time_solve = timer(tlp_solve_sequentially)

    output["solve"] = time_solve
    output["total"] = sum((time_setup, time_generate, time_solve))
    return output


def benchmark_time_mitlp(instances: int):
    try_make_process_rude()
    output = {
        "name": "MITLP",
        "extra": None,
        "instances": instances,
    }

    messages = [MESSAGE] * instances
    mitlp = MITLP(seed=SEED)

    time_setup, (pk, sk) = timer_with_output(
        mitlp.setup, instances, FIXED_INTERVAL, SQUARINGS_PER_SEC[KEYSIZE], KEYSIZE
    )
    output["setup"] = time_setup

    time_generate, (puzz_list, hash_list) = timer_with_output(mitlp.generate, messages, pk, sk)
    output["generate"] = time_generate

    if not SOLVE:
        output["total"] = sum((time_setup, time_generate))
        return output

    sol: list[tuple[TLP_Message, TLP_Digest]] = []

    def mitlp_solve():
        sol.clear()
        for x in mitlp.solve(pk, puzz_list):
            sol.append(x)

    time_solve = timer(mitlp_solve)
    output["solve"] = time_solve

    def mitlp_verify():
        for i, (m, d) in enumerate(sol):
            assert m == messages[i]
            mitlp.verify(m, d, hash_list[i])

    time_verify = timer(mitlp_verify)
    output["verify"] = time_verify

    output["total"] = sum((time_setup, time_generate, time_solve, time_verify))
    return output


def benchmark_time_gctlp(instances: int):
    try_make_process_rude()
    output = {
        "name": "GCTLP",
        "extra": None,
        "instances": instances,
    }

    messages = [MESSAGE] * instances
    distinct_intervals = [FIXED_INTERVAL] * instances
    gctlp = GCTLP(seed=SEED)

    time_setup, (pk, sk) = timer_with_output(gctlp.setup, distinct_intervals, SQUARINGS_PER_SEC[KEYSIZE], KEYSIZE)
    output["setup"] = time_setup

    time_generate, (puzz_list, hash_list) = timer_with_output(gctlp.generate, messages, pk, sk)
    output["generate"] = time_generate

    if not SOLVE:
        output["total"] = sum((time_setup, time_generate))
        return output

    sol: list[tuple[TLP_Message, TLP_Digest]] = []

    def gctlp_solve():
        sol.clear()
        for x in gctlp.solve(pk, puzz_list):
            sol.append(x)

    time_solve = timer(gctlp_solve)
    output["solve"] = time_solve

    def gctlp_verify():
        for i, (m, d) in enumerate(sol):
            assert m == messages[i]
            gctlp.verify(m, d, hash_list[i])

    time_verify = timer(gctlp_verify)
    output["verify"] = time_verify

    output["total"] = sum((time_setup, time_generate, time_solve, time_verify))
    return output


def benchmark_time_edtlp(instances: int, sc: Optional[SCInterface] = None):
    if sc is None:
        sc = MockSC()
        extra = ""
    else:
        extra = "eth"

    try_make_process_rude()
    output = {
        "name": "EDTLP",
        "extra": extra,
        "instances": instances,
    }

    client_helper_id = 1
    server_id = 0
    server_helper_id = 2

    messages = [MESSAGE] * instances
    distinct_intervals = [FIXED_INTERVAL] * instances
    edtlp = EDTLP(seed=SEED, smart_contract=sc, hash_func=Keccak256Wrapper)

    time_client_setup, csk = timer_with_output(edtlp.client_setup)
    output["setup"] = time_client_setup

    time_client_delegation, (encrypted_messages, start_time) = timer_with_output(edtlp.client_delegation, messages, csk)
    output["client delegation"] = time_client_delegation

    coins = [1] * len(distinct_intervals)
    if isinstance(sc, EthereumSC):
        # Generate an address for the client helper and save it
        sc.switch_to_account(client_helper_id)
        helper_id = sc.account
    else:
        helper_id = client_helper_id
    sc.switch_to_account(server_id)
    server_info = Server_Info(1)
    time_server_delegation, (_, sc) = timer_with_output(
        edtlp.server_delegation, distinct_intervals, server_info, coins, start_time, helper_id, None, KEYSIZE
    )
    output["server delegation"] = time_server_delegation

    sc.switch_to_account(client_helper_id)
    time_helper_setup, (pk, sk) = timer_with_output(
        edtlp.helper_setup, distinct_intervals, SQUARINGS_PER_SEC[KEYSIZE], KEYSIZE
    )
    output["helper setup"] = time_helper_setup

    time_helper_generate, puzz_list = timer_with_output(
        edtlp.helper_generate, encrypted_messages, pk, sk, start_time, sc
    )
    output["helper generate"] = time_helper_generate

    if not SOLVE:
        output["total"] = sum((
            time_client_setup,
            time_client_delegation,
            time_server_delegation,
            time_helper_setup,
            time_helper_generate,
        ))
        return output

    coins_acceptable = 1

    sol: list[tuple[GCTLP_Encrypted_Message, TLP_Digest]] = []

    def edtlp_solve():
        sol.clear()
        for x in edtlp.solve(sc, server_info, pk, puzz_list, coins_acceptable):
            sol.append(x)

    sc.switch_to_account(server_helper_id)
    time_solve = timer(edtlp_solve)
    output["helper solve"] = time_solve

    when_solved = []

    def edtlp_register():
        for m_, d in sol:
            when_solved.append(int(datetime.now().timestamp()))
            edtlp.register(sc, m_, d)

    time_register = timer(edtlp_register)
    output["helper register"] = time_register

    def edtlp_verify():
        for i, ((m_, d), time) in enumerate(zip(sol, when_solved)):
            edtlp.verify(sc, i, m_, d, 0)

    sc.switch_to_account(server_id)
    time_verify = timer(edtlp_verify)
    output["verify"] = time_verify

    def edtlp_retrieve():
        for i, _ in enumerate(messages):
            edtlp.retrieve(sc, csk, i)

    time_retrieve = timer(edtlp_retrieve)
    output["retrieve"] = time_retrieve

    output["total"] = sum((
        time_client_setup,
        time_client_delegation,
        time_server_delegation,
        time_helper_setup,
        time_helper_generate,
        time_solve,
        time_register,
        time_verify,
        time_retrieve,
    ))

    return output


INSTANCES = [10**i for i in range(0, 5)]
FIXED_INTERVAL = 1


def runner(args):
    f, instances = args
    return f(instances)


def benchmark():
    rows = []

    for instances in INSTANCES:
        print(f"{instances} instances of {FIXED_INTERVAL} seconds each")
        runnables = [
            (benchmark_time_mitlp, instances),
            (benchmark_time_gctlp, instances),
            (benchmark_time_edtlp, instances),
        ]
        if instances != INSTANCES[0]:
            runnables.append((benchmark_time_tlp, instances // 10))

        with Pool(4) as p:
            outputs = p.map_async(
                runner,
                runnables,
            )

            rows.append(benchmark_time_edtlp(instances, EthereumSC()))

            for output in outputs.get():
                rows.append(output)
    rows.append(benchmark_time_tlp(INSTANCES[-1]))

    with open(Path(__file__).parent / f"out/benchmark{datetime.now()}.csv", "w", newline="") as csvfile:
        fieldnames = [
            "name",
            "extra",
            "instances",
            "setup",
            "helper setup",
            "client delegation",
            "server delegation",
            "generate",
            "helper generate",
            "solve",
            "helper solve",
            "helper register",
            "verify",
            "retrieve",
            "total",
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(sorted(rows, key=itemgetter("name", "instances", "extra")))


if __name__ == "__main__":
    try_make_process_rude()

    print("keysize:", KEYSIZE)
    benchmark()
