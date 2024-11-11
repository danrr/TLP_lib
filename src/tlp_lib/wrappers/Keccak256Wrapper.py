from typing import ClassVar

from eth_utils.crypto import keccak


class Keccak256Wrapper:
    name: ClassVar[str] = "KECCAK256"

    @staticmethod
    def digest(message: bytes) -> bytes:
        return keccak(message)
