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


@dataclass
class DataModel:
    """
    Representation of a chunk of binary data stored in a `DataServiceInterface` implementation.

    :ivar id: Unique ID for this data model.
    :ivar range: The slice of some underlying binary blob which belongs to this data model. For
    root models, this range starts from 0 and ends at the total length of the blob.
    :ivar root_id: If this model represents a part of a root model's data, this is the ID of that
    root data model.
    """

    id: bytes
    range: Range
    root_id: bytes

    def is_mapped(self):
        return self.root_id != self.id
