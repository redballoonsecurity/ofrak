from dataclasses import dataclass
from typing import List

from ofrak_type.range import Range


@dataclass
class DataPatch:
    """
    Representation of a binary patch to part of a resource's data.

    :ivar range: The slice of the binary blob to replace with new data (zero-length is allowed)
    :ivar data_id: ID of the binary blob to apply this path to
    :ivar data: The bytes to replace old data with (zero-length is allowed)
    """

    range: Range
    data_id: bytes
    data: bytes

    def __repr__(self):
        return f"DataPatch({self.data_id.hex()}, {self.range}, {len(self.data)})"


@dataclass
class DataPatchesResult:
    """
    Summary of changes to a binary blob resulting from the application of a ``DataPatch``.

    :ivar data_id: ID of the patched blob
    :ivar patches: Range in the original blob which have been altered by applying patches
    """

    data_id: bytes
    patches: List[Range]


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
