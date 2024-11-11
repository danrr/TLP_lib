from typing import Protocol, Self

from eth_typing import ChecksumAddress

from tlp_lib.protocols import GCTLP_Encrypted_Message, GCTLP_Encrypted_Messages, GCTLPInterface, TLP_Digest, TLP_Digests

SC_Coins = list[int]
SC_UpperBounds = list[int]
SC_ExtraTime = list[float]


class SCInterface(Protocol):

    def initiate(
        self,
        coins: SC_Coins,
        upper_bounds: SC_UpperBounds,
        gctlp: GCTLPInterface,
        helper_id: int | ChecksumAddress,
    ) -> Self: ...

    def add_solution(self, solution: GCTLP_Encrypted_Message, witness: TLP_Digest) -> None: ...

    def switch_to_account(self, account: int, /) -> None: ...

    def get_commitment_at(self, i: int, /) -> TLP_Digest: ...

    def get_solution_at(self, i: int, /) -> GCTLP_Encrypted_Message: ...

    def get_upper_bound_at(self, i: int, /) -> int: ...

    def verify_solution(self, i: int, solution: GCTLP_Encrypted_Message, witness: TLP_Digest, time: int, /) -> bool: ...

    @property
    def upper_bounds(self) -> SC_UpperBounds: ...

    @property
    def coins(self) -> SC_Coins: ...

    @property
    def start_time(self) -> int: ...

    @property
    def commitments(self) -> TLP_Digests: ...

    @commitments.setter
    def commitments(self, commitments: TLP_Digests, /): ...

    @property
    def solutions(self) -> GCTLP_Encrypted_Messages: ...
