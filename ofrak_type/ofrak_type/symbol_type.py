from enum import Enum


class LinkableSymbolType(Enum):
    FUNC = 0
    RW_DATA = 1
    RO_DATA = 2
    UNDEF = -1
