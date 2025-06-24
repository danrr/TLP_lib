from collections.abc import Callable, Generator
from itertools import accumulate
from operator import add
from typing import Unpack

from eth_typing import ChecksumAddress

from tlp_lib import GCTLP
from tlp_lib.consts import SQUARINGS_PER_SEC_UPPER_BOUND
from tlp_lib.protocols import (
    GCTLP_Client_Key,
    GCTLP_Encrypted_Message,
    GCTLP_Encrypted_Messages,
    GCTLP_Intervals,
    GCTLP_Public_Input,
    GCTLP_Secret_Input,
    GCTLP_type,
    GCTLPKwargs,
    Server_Info,
    TLP_Digest,
    TLP_Message,
    TLP_Messages,
    TLP_Puzzles,
)
from tlp_lib.smartcontracts import MockSC
from tlp_lib.smartcontracts.protocols import SC_Coins, SC_ExtraTime, SCInterface
from tlp_lib.wrappers import FernetWrapper, Random
from tlp_lib.wrappers.protocols import RandGen, SymEnc


class CoinException(ValueError):
    message = "Not enough coins"


class UpperBoundException(ValueError):
    message = "Server time exceeds maximum time"


# Set fixed TOC = repeated squaring in Z_(p*q)
def custom_extra_delay(
    squarings_upper_bound: int,
    seconds: int,
    aux: Server_Info,
) -> float:
    squarings = aux.squarings
    assert squarings <= squarings_upper_bound
    return seconds * (squarings_upper_bound / squarings - 1)


class EDTLP:
    def __init__(
        self,
        *,
        gctlp: GCTLP_type = GCTLP,
        sym_enc: SymEnc | None = None,
        random: RandGen | None = None,
        seed: int | None = None,
        smart_contract: SCInterface | None = None,
        **kwargs: Unpack[GCTLPKwargs],
    ):
        if random is None:
            random = Random(seed=seed)
        self.random = random
        if sym_enc is None:
            sym_enc = FernetWrapper()
        self.sym_enc = sym_enc
        self.gctlp = gctlp(
            seed=seed,
            random=self.random,
            sym_enc=self.sym_enc,
            **kwargs,
        )
        if smart_contract is None:
            smart_contract = MockSC()
        self.smart_contract = smart_contract

    def client_setup(self) -> GCTLP_Client_Key:
        return self.sym_enc.generate_key()

    def client_delegation(
        self,
        messages: TLP_Messages,
        csk: GCTLP_Client_Key,
    ) -> tuple[GCTLP_Encrypted_Messages, int]:
        start_time = 0  # todo: allow for delays
        return [self.sym_enc.encrypt(csk, message) for message in messages], start_time
        # todo: send encrypted messages to TPH and start_time to TPH and S

    def server_delegation(
        self,
        intervals: GCTLP_Intervals,
        server_info: Server_Info,
        coins: SC_Coins,
        start_time: int,
        helper_id: int | ChecksumAddress,
        squarings_upper_bound: int | None = None,
        keysize: int = 2048,
        cdeg: Callable[[int, int, Server_Info], float] = custom_extra_delay,
    ) -> tuple[SC_ExtraTime, SCInterface]:
        if squarings_upper_bound is None:
            squarings_upper_bound = SQUARINGS_PER_SEC_UPPER_BOUND[keysize]

        extra_time = [
            cdeg(squarings_upper_bound, interval, server_info) for interval in intervals
        ]
        upper_bounds = list(
            accumulate([start_time, *list(map(add, intervals, extra_time))])
        )[1:]
        sc = self.smart_contract.initiate(
            coins=coins,
            start_time=start_time,
            extra_time=extra_time,
            upper_bounds=upper_bounds,
            helper_id=helper_id,
        )

        return extra_time, sc

    def helper_setup(
        self,
        intervals: GCTLP_Intervals,
        squaring_per_second: int,
        keysize: int = 2048,
    ):
        return self.gctlp.setup(intervals, squaring_per_second, keysize=keysize)

    def helper_generate(
        self,
        messages: GCTLP_Encrypted_Messages,
        pk: GCTLP_Public_Input,
        sk: GCTLP_Secret_Input,
        start_time: int,
        sc: SCInterface,
    ):
        puzz_list, hash_list = self.gctlp.generate(messages, pk, sk)
        sc.commitments = hash_list
        return puzz_list
        # todo: use start_time to send puzz_list to TPH

    def solve(
        self,
        sc: SCInterface,
        server_info: Server_Info,
        pk: GCTLP_Public_Input,
        puzz: TLP_Puzzles,
        coins_acceptable: int,
    ) -> Generator[tuple[GCTLP_Encrypted_Message, TLP_Digest], None, None]:
        coins = sc.coins
        for coin in coins:
            if coin < coins_acceptable:
                raise CoinException

        _, _, t, _ = pk
        upper_bounds = sc.upper_bounds
        squarings_per_sec = server_info.squarings

        prev_bound = sc.start_time
        for i, upper_bound in enumerate(upper_bounds):
            server_time = t[i] / squarings_per_sec
            maximum_time = upper_bound - prev_bound

            if server_time > maximum_time:
                raise UpperBoundException
            prev_bound = upper_bound

        yield from self.gctlp.solve(pk, puzz)

    def register(
        self,
        sc: SCInterface,
        solution: GCTLP_Encrypted_Message,
        commitment: TLP_Digest,
    ) -> None:
        sc.add_solution(solution, commitment)

    def verify(self, sc: SCInterface, i: int) -> None:
        solution, witness, time_solved = sc.get_solution_at(i)
        commitment = sc.get_commitment_at(i)
        time_to_solve = time_solved - sc.initial_timestamp
        upper_bound = sc.get_upper_bound_at(i)
        assert time_to_solve < upper_bound
        self.gctlp.verify(solution, witness, commitment)

    def pay(self, sc: SCInterface, i: int) -> None:
        try:
            self.verify(sc, i)
        except AssertionError:
            sc.pay_back(i)
        else:
            sc.pay(i)

    def retrieve(self, sc: SCInterface, csk: GCTLP_Client_Key, i: int) -> TLP_Message:
        encrypted_message = sc.get_message_at(i)
        return self.sym_enc.decrypt(csk, encrypted_message)
