import logging
from dataclasses import dataclass
from typing import Iterable

from ofrak.core.addressable import Addressable
from ofrak.model.resource_model import index, ResourceAttributes
from ofrak.resource import Resource
from ofrak.service.data_service import OverlapError
from ofrak_type.error import NotFoundError
from ofrak_type.range import Range

LOGGER = logging.getLogger(__file__)


class MemoryOverlapError(RuntimeError):
    """
    Error raised when a memory region overlaps with an existing child memory region.
    """

    def __init__(self, new_region: "MemoryRegion", existing_region: "MemoryRegion"):
        message = f"New MemoryRegion {new_region} overlaps with an existing child {existing_region}"
        super().__init__(message)
        self.new_region = new_region
        self.existing_region = existing_region


@dataclass
class MemoryRegion(Addressable):
    """
    Binary bytes that are addressable.

    :ivar virtual_address: the virtual address of the start of the memory region
    :ivar size: the size of the memory region
    """

    size: int

    @index
    def Size(self) -> int:
        return self.size

    @index(nested_indexes=(Addressable.VirtualAddress,))
    def EndVaddr(self) -> int:
        return self.size + self.VirtualAddress

    def end_vaddr(self) -> int:
        """
        Get the virtual address of the end of the memory region.

        :returns: the virtual address directly after the memory region
        """
        return self.virtual_address + self.size

    def vaddr_range(self) -> Range:
        return Range.from_size(self.virtual_address, self.size)

    @classmethod
    def caption(cls, all_attributes) -> str:
        try:
            mem_region_attributes = all_attributes[MemoryRegion.attributes_type]
            addressable_attributes = all_attributes[Addressable.attributes_type]
        except KeyError:
            return super().caption(all_attributes)
        return (
            f"{str(cls.__name__)}: "
            f"{hex(addressable_attributes.virtual_address)}-"
            f"{hex(addressable_attributes.virtual_address + mem_region_attributes.size)}"
        )

    def contains(self, vaddr: int) -> bool:
        """
        Does the memory region contain the given virtual address?

        :param vaddr: a virtual address

        :return: True if the memory region contains the given virtual address
        """
        return self.virtual_address <= vaddr < self.end_vaddr()

    def get_offset_in_self(self, vaddr: int) -> int:
        """
        Get the physical offset within the memory region that corresponds to the given virtual
        address.

        :param vaddr: a virtual address

        :return: an offset within the memory region
        """
        if not self.contains(vaddr):
            raise ValueError(
                f"Memory region {hex(self.virtual_address)}-{hex(self.end_vaddr())} "
                f"does not contain vaddr {hex(vaddr)}"
            )
        return vaddr - self.virtual_address

    async def create_child_region(
        self,
        child_mr: "MemoryRegion",
        additional_attributes: Iterable[ResourceAttributes] = (),
    ) -> Resource:
        """
        Create a child memory region that is mapped into this memory region.

        :param child_mr: the child memory region
        :param additional_attributes: additional attributes passed to the child memory region

        :raises OverlapError: if the child to be created overlaps with an existing child node
        :raises ValueError: if the child's end offset is larger than the memory region's size
        :return: the created child resource
        """
        start_offset = self.get_offset_in_self(child_mr.virtual_address)
        end_offset = start_offset + child_mr.size
        if start_offset < 0:
            raise ValueError(
                f"New child has vaddr {hex(child_mr.virtual_address)} which is before"
                f" the proposed parent's vaddr {hex(self.virtual_address)}"
            )
        if end_offset > self.size:
            raise ValueError(
                f"New child at {hex(child_mr.virtual_address)} is too large to fit in the proposed "
                f"parent - end vaddr {hex(child_mr.end_vaddr())} goes past the parent's end vaddr "
                f"{hex(self.end_vaddr())}."
            )

        try:
            return await self.resource.create_child_from_view(
                child_mr,
                data_range=Range(start_offset, end_offset),
                additional_attributes=additional_attributes,
            )
        except OverlapError as e:
            existing_child_vaddr = e.existing_child_node.model.range.start + self.virtual_address
            existing_child_size = e.existing_child_node.model.range.length()
            raise MemoryOverlapError(
                child_mr, MemoryRegion(existing_child_vaddr, existing_child_size)
            ) from e

    @staticmethod
    def get_mem_region_with_vaddr_from_sorted(vaddr: int, sorted_regions: Iterable["MemoryRegion"]):
        """
        Return the first [memory region][ofrak.core.memory_region.MemoryRegion] in the input
        iterable that contains vaddr.

        :param vaddr: Virtual address
        :param sorted_regions: Sorted iterable of memory regions to check in order for vaddr

        :raises NotFoundError: If vaddr is not in any element of the iterable

        :return: The first memory region in the sorted iterable containing vaddr
        """
        for mem_view in sorted_regions:
            # the first region we find should be the largest
            mem_region_vaddr_range = Range(
                mem_view.virtual_address,
                mem_view.virtual_address + mem_view.size,
            )
            if vaddr in mem_region_vaddr_range:
                return mem_view

        raise NotFoundError(f"Cannot find memory region matching {hex(vaddr)}")

    def __str__(self):
        if type(self) is MemoryRegion:
            return f"MemoryRegion({hex(self.virtual_address)}-{hex(self.end_vaddr())})"
        else:
            return super().__str__()

    def __hash__(self):
        """
        Return the hash of the virtual address and size.

        !!! warning

            Two memory regions may have the same hash, even if they refer to different data! As
            long as the address and size are the same, two regions will have the same hash,
            since the resource is not part of the data that is hashed. Be careful about comparing
            memory regions that refer to different data!
        """
        return hash((self.virtual_address, self.size))
