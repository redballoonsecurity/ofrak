from abc import ABC, abstractmethod
from typing import Optional, Tuple, Iterable

from ofrak.resource import Resource

from ofrak.component.analyzer import Analyzer
from ofrak.core.code_region import CodeRegion
from ofrak.core.complex_block import ComplexBlock
from ofrak.core.data import ReferencedStringsAttributes, ReferencedDataAttributes
from ofrak.core.memory_region import MemoryRegion
from ofrak.service.resource_service_i import (
    ResourceFilter,
    ResourceAttributeValueFilter,
    ResourceSort,
    ResourceSortDirection,
)
from ofrak.core.patch_maker.linkable_binary import LinkableBinary
from ofrak_type.error import NotFoundError
from ofrak_type.range import Range


class Program(LinkableBinary):
    """
    Generic representation for a binary program with functions, code and
    [memory regions][ofrak.core.memory_region.MemoryRegion], and
    [ProgramAttributes][ofrak.core.architecture.ProgramAttributes].
    """

    async def get_function_complex_block(self, func_name: str) -> ComplexBlock:
        return await self.resource.get_only_descendant_as_view(
            ComplexBlock,
            r_filter=ResourceFilter(
                tags=(ComplexBlock,),
                attribute_filters=(ResourceAttributeValueFilter(ComplexBlock.Symbol, func_name),),
            ),
        )

    async def get_code_regions(self) -> Iterable[CodeRegion]:
        """
        Return code regions associated with the resource

        :return: Iterable of CodeRegions
        """
        return await self.resource.get_children_as_view(
            CodeRegion, r_filter=ResourceFilter.with_tags(CodeRegion)
        )

    async def get_code_region_for_vaddr(self, vaddr: int) -> Optional[CodeRegion]:
        """
        Return the code region in this program containing vaddr.

        :param vaddr: Virtual address

        :raises NotFoundError: If vaddr is not in any code region

        :return: Code region containing the input vaddr
        """

        code_regions = await self.get_code_regions()

        for cr_view in code_regions:
            code_region_vaddr_range = Range(
                cr_view.virtual_address,
                cr_view.virtual_address + cr_view.size,
            )
            if vaddr in code_region_vaddr_range:
                return cr_view

        raise NotFoundError

    async def get_memory_region_for_vaddr(self, vaddr: int) -> Optional[MemoryRegion]:
        """
        Return the largest [memory region][ofrak.core.memory_region.MemoryRegion] containing vaddr.

        :param vaddr: Virtual address

        :raises NotFoundError: If vaddr is not in any memory region

        :return: The most general (largest) region of memory containing the input vaddr,
        if such a memory region exists
        """
        # we're looking for the largest (most general) memory region containing this vaddr
        mem_regions = await self.resource.get_descendants_as_view(
            MemoryRegion,
            r_filter=ResourceFilter.with_tags(MemoryRegion),
            r_sort=ResourceSort(
                attribute=MemoryRegion.Size,
                direction=ResourceSortDirection.DESCENDANT,
            ),
        )

        return MemoryRegion.get_mem_region_with_vaddr_from_sorted(vaddr, mem_regions)


class ReferencedStringsAnalyzer(Analyzer[None, Tuple[ReferencedStringsAttributes]], ABC):
    targets = (Program,)
    outputs = (ReferencedStringsAttributes,)

    @abstractmethod
    async def analyze(self, resource: Resource, config=None) -> Tuple[ReferencedStringsAttributes]:
        raise NotImplementedError()


class ReferencedDataAnalyzer(Analyzer[None, Tuple[ReferencedDataAttributes]], ABC):
    targets = (Program,)
    outputs = (ReferencedDataAttributes,)

    @abstractmethod
    async def analyze(self, resource: Resource, config=None) -> Tuple[ReferencedDataAttributes]:
        raise NotImplementedError()
