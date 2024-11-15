from enum import Enum


__all__ = ["Endianness"]


class Endianness(Enum):
    """
    The order in which bytes are stored.
    """

    BIG_ENDIAN = "big"
    LITTLE_ENDIAN = "little"

    def get_struct_flag(self) -> str:
        if self is Endianness.BIG_ENDIAN:
            return ">"
        else:
            return "<"
