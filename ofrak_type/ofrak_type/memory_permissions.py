from enum import Enum


class MemoryPermissions(Enum):
    """
    Representation of memory access permissions - all combinations of Read, Write, and eXecute
    are represented, with the exception of Write + eXecute (not a sane combination).
    """

    R = 1
    W = 2
    X = 4
    RW = R + W
    RX = R + X
    RWX = R + W + X

    def as_str(self) -> str:
        string = ""
        if self.value & MemoryPermissions.R.value:
            string += "r"
        if self.value & MemoryPermissions.W.value:
            string += "w"
        if self.value & MemoryPermissions.X.value:
            string += "x"
        return string

    def __add__(self, other: "MemoryPermissions") -> "MemoryPermissions":
        if not isinstance(other, MemoryPermissions):
            raise TypeError(f"Operation between MemoryPermissions and {type(other)} not supported")
        elif other.value & self.value != 0:
            raise ValueError(f"Cannot add {self} and {other} because they overlap!")
        else:
            return MemoryPermissions(self.value + other.value)

    def __and__(self, other: "MemoryPermissions") -> "MemoryPermissions":
        if not isinstance(other, MemoryPermissions):
            raise TypeError(f"Operation between MemoryPermissions and {type(other)} not supported")
        else:
            return MemoryPermissions(self.value & other.value)

    def __sub__(self, other: "MemoryPermissions") -> "MemoryPermissions":
        if not isinstance(other, MemoryPermissions):
            raise TypeError(f"Operation between MemoryPermissions and {type(other)} not supported")
        elif other.value & self.value == 0:
            raise ValueError(f"Cannot subtract {other} from {self} because they have no overlap!")
        else:
            return MemoryPermissions(self.value & (~other.value & 0x7))
