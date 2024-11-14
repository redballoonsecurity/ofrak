from abc import ABC, abstractmethod


__all__ = ["EccError", "EccAlgorithm"]


class EccError(Exception):
    pass


class EccAlgorithm(ABC):
    @abstractmethod
    def encode(self, payload: bytes) -> bytes:
        raise NotImplementedError()

    @abstractmethod
    def decode(self, payload: bytes) -> bytes:
        raise NotImplementedError()
