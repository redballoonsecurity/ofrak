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
class DataMove:
    range: Range
    data_id: bytes
    after_data_id: Optional[bytes] = None
    before_data_id: Optional[bytes] = None


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
    size_change: int
    child_index: int
    child_relative_position: DataRangePosition


@dataclass
class DataPatchesResult:
    data_id: bytes
    patches: List[DataPatchResult]

    def get_size_change(self):
        return sum(r.size_change for r in self.patches)


@dataclass
class DataModel:
    id: bytes
    range: Range
    alignment: int = 1
    parent_id: Optional[bytes] = None

    def is_mapped(self):
        return self.parent_id is not None
