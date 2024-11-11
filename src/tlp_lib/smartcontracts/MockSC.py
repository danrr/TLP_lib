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
    next_unsolved_puzzle_part: int = 0

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
        time = int(datetime.now().timestamp())
        self.solutions.append(solution)

        if self.verify_solution(self.next_unsolved_puzzle_part, solution, witness, time):
            self.pay()
        else:
            self.pay_back()

    def verify_solution(self, i: int, solution: GCTLP_Encrypted_Message, witness: TLP_Digest, time: int, /) -> bool:

        on_time = time < self.start_time + self.upper_bounds[i]

        correct = False
        try:
            self.gctlp.verify(solution, witness, self.get_commitment_at(i))
            correct = True
        except Exception:
            pass

        return on_time and correct

    def switch_to_account(self, account: int):
        pass

    def pay(self, /):
        print(f"paying TPH {self.coins[self.next_unsolved_puzzle_part]}")
        self.coins[self.next_unsolved_puzzle_part] = 0

    def pay_back(self, /):
        print(f"paying back {self.coins[self.next_unsolved_puzzle_part]}")
        self.coins[self.next_unsolved_puzzle_part] = 0

    def get_commitment_at(self, i: int, /) -> TLP_Digest:
        return self.commitments[i]

    def get_solution_at(self, i: int, /) -> GCTLP_Encrypted_Message:
        return self.solutions[i]

    def get_upper_bound_at(self, i: int, /) -> int:
        return self.upper_bounds[i]
