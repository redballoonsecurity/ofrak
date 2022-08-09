from enum import Enum


class BitWidth(Enum):
    """
    The number of bits which can be used to represent a number.
    """

    BIT_8 = 8
    BIT_16 = 16
    BIT_32 = 32
    BIT_64 = 64

    def get_word_size(self):  # type: () -> int
        return int(self.value / 8)
