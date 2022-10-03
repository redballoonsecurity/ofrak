from dataclasses import dataclass
from enum import IntEnum
from typing import Optional, List

from ofrak_type.range import Range


class DataRangePosition(IntEnum):
    UNDEFINED = -3
    UNMAPPED = -2
    OVERLAP = -1
    BEFORE = 0
    WITHIN = 1
    AFTER = 2


@dataclass
class DataPatchRef:
    range: Range
    data_id: bytes


@dataclass
class DataPatch:
    range: Range
    data_id: bytes
    data: bytes
    after_data_id: Optional[bytes] = None
    before_data_id: Optional[bytes] = None

    def __repr__(self):
        return f"DataPatch({self.data_id.hex()}, {self.range}, {len(self.data)})"


@dataclass
class DataPatchResult:
    range: Range


@dataclass
class DataPatchesResult:
    data_id: bytes
    patches: List[DataPatchResult]


@dataclass(unsafe_hash=True)
class DataModel:
    id: bytes
    range: Range
    root_id: Optional[bytes] = None

    def is_mapped(self):
        return self.root_id is not None
