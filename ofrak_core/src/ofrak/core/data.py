import struct
from collections import defaultdict
from dataclasses import dataclass
from typing import Tuple, Dict

from ofrak.core.memory_region import MemoryRegion
from ofrak.model.resource_model import ResourceAttributes
from ofrak_type.range import Range


@dataclass
class DataWord(MemoryRegion):
    """
    Addressable data word. Size depends on target system, and is extracted by analysis backend.

    :ivar virtual_address: virtual address of the memory region containing the data word
    :ivar size: size of the memory region containing the data word
    :ivar format_string: `struct.unpack` format string for unpacking the data word into a value
    :ivar xrefs_to: cross references to the data word
    """

    format_string: str
    xrefs_to: Tuple[int, ...]

    async def get_value_unsigned(self) -> int:
        data = await self.resource.get_data()
        return struct.unpack(self.format_string.upper(), data)[0]

    async def get_value_signed(self) -> int:
        data = await self.resource.get_data()
        return struct.unpack(self.format_string.lower(), data)[0]


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class ReferencedStringsAttributes(ResourceAttributes):
    """
    Strings referenced by functions, represented as
    [ResourceAttributes][ofrak.model.resource_model.ResourceAttributes].

    :ivar referencing_functions: All functions which reference strings in the program
    :ivar referenced_strings: All strings which are referenced in the program
    :ivar references: Edges from referencing funcs to referenced strings
    """

    referencing_functions: Tuple[int, ...]
    referenced_strings: Tuple[Range, ...]
    references: Tuple[Tuple[int, int], ...]


@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class ReferencedDataAttributes(ResourceAttributes):
    """
    Data cross-references in a program. That is, all addresses which are known to reference data
    and all data addresses which are known to be referenced.

    :ivar referencing_addresses: Addresses of all items which reference data in the program
    :ivar referenced_data: All data which are referenced in the program
    :ivar references: Pairs of indexes in `referencing_addresses` and `referenced_strings`
    representing edges from referencing funcs to referenced data
    """

    referencing_addresses: Tuple[int, ...]
    referenced_data: Tuple[int, ...]
    references: Tuple[Tuple[int, int], ...]

    def get_xrefs_to(self) -> Dict[int, Tuple[int, ...]]:
        """
        Create a dictionary version of the data ref information. The keys are data addresses, and
        the value for each of those is a tuple of all the addresses which reference that data
        address.

        :return: Dictionary mapping each data address to the addresses that reference it
        """
        data_vaddrs_to_referrees = defaultdict(list)
        for ref_from_idx, ref_to_idx in self.references:
            data_vaddrs_to_referrees[self.referenced_data[ref_to_idx]].append(
                self.referencing_addresses[ref_from_idx]
            )
        return {
            data_vaddr: tuple(addresses_refering_to_data_vaddr)
            for data_vaddr, addresses_refering_to_data_vaddr in data_vaddrs_to_referrees.items()
        }

    def get_xrefs_from(self):
        """
        Create a dictionary version of the data ref information. The keys are addresses, and
        the value for each of those is a tuple of all the data addresses are referenced from that
        address.

        :return: Dictionary mapping each address to the addresses of the data that it references
        """
        addresses_to_referenced_data = defaultdict(list)
        for ref_from_idx, ref_to_idx in self.references:
            addresses_to_referenced_data[self.referencing_addresses[ref_from_idx]].append(
                self.referenced_data[ref_to_idx]
            )
        return {
            vaddr: tuple(referenced_data_vaddrs)
            for vaddr, referenced_data_vaddrs in addresses_to_referenced_data.items()
        }
