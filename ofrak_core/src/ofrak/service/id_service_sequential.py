import struct
from collections import defaultdict

from ofrak.service.id_service_i import IDServiceInterface


class SequentialIDService(IDServiceInterface):
    """
    An ID service implementation that generates sequencial ids to aid debugging.

    This ID service is intended to be used for debugging purposes only, since it relies on its
    internal state to generate ids.
    """

    def __init__(self):
        self._ids = defaultdict(lambda: 0)
        self._scope = "default"

    def generate_id(self) -> bytes:
        _id = self._ids[self._scope]
        self._ids[self._scope] += 1
        return struct.pack(">I", _id)

    @staticmethod
    def generate_id_from_base(base_id: bytes, key: str) -> bytes:
        return b"-".join((base_id, bytes(key, "utf-8")))
