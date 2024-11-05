from datetime import datetime
from typing import Any, Self

from tlp_lib.protocols import GCTLP_Encrypted_Message, GCTLP_Encrypted_Messages, GCTLPInterface, TLP_Digest, TLP_Digests
from tlp_lib.smartcontracts.protocols import SC_Coins, SC_UpperBounds


class MockSC:
    commitments: TLP_Digests
    start_time: int
    upper_bounds: SC_UpperBounds
    coins: SC_Coins
    solutions: GCTLP_Encrypted_Messages = []
    gctlp: GCTLPInterface
    helper_id: Any

    def initiate(
        self,
        coins: SC_Coins,
        upper_bounds: SC_UpperBounds,
        gctlp: GCTLPInterface,
        helper_id: Any,
    ) -> Self:
        self.coins = coins
        self.start_time = int(datetime.now().timestamp())
        self.upper_bounds = upper_bounds
        self.gctlp = gctlp
        self.helper_id = helper_id
        self.commitments = []
        self.solutions = []
        return self

    def add_solution(self, solution: GCTLP_Encrypted_Message, witness: TLP_Digest):
        next_solution_index = len(self.solutions)
        time = int(datetime.now().timestamp())
        assert time < self.start_time + self.upper_bounds[next_solution_index]

        self.gctlp.verify(solution, witness, self.get_commitment_at(next_solution_index))
        self.solutions.append(solution)

    def verify_solution(self, i: int, /) -> bool:
        solution = self.get_solution_at(i)
        return len(solution) != 0

    def check_solution(self, commitment: TLP_Digest, solution: GCTLP_Encrypted_Message, witness: TLP_Digest) -> bool:


    def switch_to_account(self, account: int):
        pass

    def pay_back(self, i: int, /):
        assert i < len(self.coins) and self.coins[i] >= 0
        time = int(datetime.now().timestamp())
        assert time > self.start_time + self.upper_bounds[i]
        print(f"paying back {self.coins[i]}")
        self.coins[i] = -1

    def get_commitment_at(self, i: int, /) -> TLP_Digest:
        return self.commitments[i]

    def get_solution_at(self, i: int, /) -> GCTLP_Encrypted_Message:
        return self.solutions[i]

    def get_upper_bound_at(self, i: int, /) -> int:
        return self.upper_bounds[i]
