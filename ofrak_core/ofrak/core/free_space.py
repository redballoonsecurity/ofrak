from collections import defaultdict
from dataclasses import dataclass
from itertools import chain
from typing import List, Tuple, Dict, Optional, Iterable

from ofrak.service.id_service_i import IDServiceInterface

from ofrak.component.analyzer import Analyzer
from ofrak.component.modifier import Modifier
from ofrak.core.architecture import ProgramAttributes
from ofrak.core.basic_block import BasicBlock
from ofrak.core.complex_block import ComplexBlock
from ofrak.core.instruction import Instruction
from ofrak.core.memory_region import MemoryRegion
from ofrak.core.program import Program
from ofrak.model.component_model import ComponentConfig
from ofrak.model.resource_model import index
from ofrak.resource import Resource, ResourceFactory
from ofrak.resource_view import ResourceView
from ofrak.service.assembler.assembler_service_i import AssemblerServiceInterface
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.resource_service_i import (
    ResourceServiceInterface,
    ResourceFilter,
    ResourceAttributeRangeFilter,
    ResourceAttributeValueFilter,
    ResourceSort,
)
from ofrak_type.architecture import InstructionSet, InstructionSetMode
from ofrak_type.memory_permissions import MemoryPermissions
from ofrak_type.range import Range, remove_subranges

NOPS: Dict[Tuple[ProgramAttributes, InstructionSetMode], bytes] = dict()


class FreeSpaceAllocationError(RuntimeError):
    pass


@dataclass
class FreeSpace(MemoryRegion):
    permissions: MemoryPermissions

    @index
    def Permissions(self) -> int:
        return self.permissions.value


@dataclass
class FreeSpaceAllocation(ComponentConfig):
    permissions: MemoryPermissions
    allocations: List[Range]


@dataclass
class Allocatable(ResourceView):
    """
    Identifies a resource that may have some free space available within it to allocate (for
    arbitrary purposes). Once tagged as an Allocatable, a resource may be analyzed to find all of
    the available free space within it and its descendants. These ranges are stored as
    minimal lists of contiguous ranges of free space (ranges which overlap or touch are combined),
    sorted first by size then vaddr (lowest to highest). Each list of free space ranges contains
    only free space with one type of memory access permissions of the ranges, i.e. all read-only
    free space is stored in one list, all read-execute free-space is stored in another list, etc.
    """

    free_space_ranges: Dict[MemoryPermissions, List[Range]]

    async def allocate(
        self,
        permissions: MemoryPermissions,
        requested_size: int,
        alignment: int = 4,
        min_fragment_size: Optional[int] = None,
        within_range: Optional[Range] = None,
    ) -> List[Range]:
        """
        Request some range(s) of free space which satisfies the given constraints as parameters.
        If such ranges are found, the resources they belong to (which are descendants of this
        `Allocatable`) are modified to reflect that part or all of them are no longer valid free
        space using
        [RemoveFreeSpaceModifier][ofrak.core.free_space.RemoveFreeSpaceModifier].

        Allows either a fragmented allocation (X space is allocated across N individual ranges),
        or a non-fragmented allocation (one range of size X). To force the allocation to be
        non-fragmented, set the `min_fragment_size` param equal to the `requested_size`.

        :param permissions: Required memory permissions of the free space (exact match)
        :param requested_size: Total size of allocated ranges
        :param alignment: That start of the allocated ranges will be aligned to `alignment` bytes
        :param min_fragment_size: The minimum size of each allocated range
        :param within_range: All returned ranges must be within this virtual address range

        :return: A list of one or more [Range][ofrak_type.range.Range], which each contain a
         start and end vaddr of an allocated range of free space

        :raises FreeSpaceAllocationError: if there is not enough free space to allocate which
        matches the given constraints
        """
        allocated_ranges = await self._allocate(
            permissions,
            requested_size,
            alignment,
            min_fragment_size,
            within_range,
        )

        # Having acquired a satisfactory allocation, make sure subsequent calls won't allocate
        # from this same block
        await self.resource.run(
            RemoveFreeSpaceModifier,
            FreeSpaceAllocation(
                permissions,
                allocated_ranges,
            ),
        )
        self.remove_allocation_from_cached_free_ranges(allocated_ranges, permissions)

        return allocated_ranges

    async def _allocate(
        self,
        permissions: MemoryPermissions,
        requested_size: int,
        alignment: int = 4,
        min_fragment_size: Optional[int] = None,
        within_range: Optional[Range] = None,
    ) -> List[Range]:
        free_ranges = self.free_space_ranges.get(permissions)
        if not free_ranges:
            raise FreeSpaceAllocationError(f"No free space with permissions {permissions}.")

        if min_fragment_size is None:
            _min_fragment_size = requested_size
        elif min_fragment_size <= 0:
            raise ValueError(f"Minimum fragment size must be >0 or None! Got {min_fragment_size}.")
        else:
            _min_fragment_size = min_fragment_size

        unallocated_size = requested_size
        allocation: List = list()

        for free_range in free_ranges:
            assert unallocated_size >= 0
            if unallocated_size == 0:
                break

            # 1. Transform free range to only ranges within vaddr range constraint
            try:
                if within_range:
                    free_range = free_range.intersect(within_range)
            except ValueError:
                # There is no overlap with the `within_range` constraint
                continue
            # 2. Transform free range to satisfy alignment
            try:
                free_range = self._align_range(free_range, alignment)
            except ValueError:
                # Free range is too small to satisfy alignment
                continue
            # 3. Transform free range to only the range we actually require for allocation
            new_length = min(free_range.length(), unallocated_size)
            free_range = Range.from_size(free_range.start, new_length)
            # If transformed range is not not big enough, continue
            if free_range.length() < _min_fragment_size:
                continue

            allocation.append(free_range)
            unallocated_size -= free_range.length()

        assert unallocated_size >= 0
        if unallocated_size > 0:
            raise FreeSpaceAllocationError(
                f"Not enough valid free space to allocate {requested_size} "
                f"units with constraints alignment={alignment}, "
                f"permissions={permissions}, "
                f"min_fragment_size={min_fragment_size}, "
                f"within_range={within_range}."
            )

        return allocation

    @staticmethod
    def _align_range(unaligned_range: Range, alignment: int) -> Range:
        offset_to_align_start = (alignment - (unaligned_range.start % alignment)) % alignment
        # Currently we don't expect the end of each allocated range to be aligned
        # If we end up wanting to align both start and end, `offset_to_align_end` should be updated
        offset_to_align_end = 0
        aligned_range = Range(
            unaligned_range.start + offset_to_align_start,
            unaligned_range.end + offset_to_align_end,
        )
        assert aligned_range.start >= unaligned_range.start
        assert aligned_range.end <= unaligned_range.end

        return aligned_range

    @staticmethod
    def sort_free_ranges(ranges: Iterable[Range]) -> List[Range]:
        return list(sorted(ranges, key=lambda r: (r.length(), r.start)))

    def remove_allocation_from_cached_free_ranges(
        self, allocation: List[Range], permissions: MemoryPermissions
    ):
        if len(allocation) == 0:
            return
        new_free_ranges = remove_subranges(
            self.free_space_ranges[permissions],
            allocation,
        )

        self.free_space_ranges[permissions] = Allocatable.sort_free_ranges(new_free_ranges)


class FreeSpaceAnalyzer(Analyzer[None, Allocatable]):
    """
    Analyze an `Allocatable` resource to find the ranges of free space it contains by searching for
    descendants tagged as `FreeSpace`. The ranges of each individual `FreeSpace` resource will be
    globbed into as few non-overlapping ranges as possible. The ranges of different types of free
    space - such as RW permissions vs RX permissions - will be calculated and stored separately.
    """

    targets = (Allocatable,)
    outputs = (Allocatable,)

    async def analyze(self, resource: Resource, config: None) -> Allocatable:
        ranges_by_permissions = defaultdict(list)
        for free_space_r in await resource.get_descendants_as_view(
            FreeSpace,
            r_filter=ResourceFilter.with_tags(FreeSpace),
            r_sort=ResourceSort(FreeSpace.VirtualAddress),
        ):
            ranges_by_permissions[free_space_r.permissions].append(free_space_r.vaddr_range())

        merged_ranges_by_permissions = dict()
        for perms, ranges in ranges_by_permissions.items():
            merged_ranges_by_permissions[perms] = Allocatable.sort_free_ranges(
                Range.merge_ranges(ranges)
            )

        return Allocatable(merged_ranges_by_permissions)


class RemoveFreeSpaceModifier(Modifier[FreeSpaceAllocation]):
    """
    After allocating some space from an `Allocatable`, fix up its descendants to make sure the
    allocated space will not be allocated again. Remove FreeSpace tags from resources which
    overlap with an allocated range. If part of one of these resources is not within an
    allocated range, create a child tagged as FreeSpace to reflect that part of it is still
    available as free space.
    """

    targets = (Allocatable,)

    async def modify(self, resource: Resource, config: FreeSpaceAllocation) -> None:

        wholly_allocated_resources = list()
        partially_allocated_resources: Dict[bytes, Tuple[FreeSpace, List[Range]]] = dict()
        allocatable = await resource.view_as(Allocatable)

        for alloc in config.allocations:
            for res_wholly_in_alloc in await resource.get_descendants_as_view(
                FreeSpace,
                r_filter=ResourceFilter(
                    tags=(FreeSpace,),
                    attribute_filters=(
                        ResourceAttributeValueFilter(
                            FreeSpace.Permissions, config.permissions.value
                        ),
                        ResourceAttributeRangeFilter(
                            FreeSpace.VirtualAddress,
                            min=alloc.start,
                            max=alloc.end - 1,
                        ),
                        ResourceAttributeRangeFilter(
                            FreeSpace.EndVaddr, min=alloc.start + 1, max=alloc.end
                        ),
                    ),
                ),
            ):
                wholly_allocated_resources.append(res_wholly_in_alloc)

            for res_partially_in_alloc in await self._get_partially_overlapping_resources(
                resource,
                config.permissions,
                alloc,
            ):
                free_space_range = res_partially_in_alloc.vaddr_range()
                overlap = alloc.intersect(free_space_range)
                assert overlap.length() > 0
                free_space_res_id = res_partially_in_alloc.resource.get_id()
                if free_space_res_id in partially_allocated_resources:
                    _, allocated_ranges_of_res = partially_allocated_resources[free_space_res_id]
                    allocated_ranges_of_res.append(overlap)
                else:
                    partially_allocated_resources[free_space_res_id] = (
                        res_partially_in_alloc,
                        [overlap],
                    )

        for fs in wholly_allocated_resources:
            fs.resource.remove_tag(FreeSpace)

        for fs, allocated_ranges in partially_allocated_resources.values():
            remaining_free_space_ranges = remove_subranges([fs.vaddr_range()], allocated_ranges)
            for remaining_range in remaining_free_space_ranges:
                remaining_data_range = Range.from_size(
                    fs.get_offset_in_self(remaining_range.start), remaining_range.length()
                )
                await fs.resource.create_child_from_view(
                    FreeSpace(
                        remaining_range.start,
                        remaining_range.length(),
                        fs.permissions,
                    ),
                    data_range=remaining_data_range,
                )
            fs.resource.remove_tag(FreeSpace)

        # Update Allocatable attributes, reflecting removed ranges
        allocatable.remove_allocation_from_cached_free_ranges(
            config.allocations, config.permissions
        )
        resource.add_view(allocatable)

    @staticmethod
    async def _get_partially_overlapping_resources(
        resource: Resource,
        permissions: MemoryPermissions,
        alloc: Range,
    ) -> Iterable[FreeSpace]:
        filter_overlapping_free_range_end = (
            ResourceAttributeValueFilter(FreeSpace.Permissions, permissions.value),
            ResourceAttributeRangeFilter(FreeSpace.VirtualAddress, max=alloc.end),
            ResourceAttributeRangeFilter(
                FreeSpace.EndVaddr,
                min=alloc.end + 1,
            ),
        )
        filter_overlapping_free_range_start = (
            ResourceAttributeValueFilter(FreeSpace.Permissions, permissions.value),
            ResourceAttributeRangeFilter(
                FreeSpace.VirtualAddress,
                max=alloc.start - 1,
            ),
            ResourceAttributeRangeFilter(
                FreeSpace.EndVaddr,
                min=alloc.start + 1,
            ),
        )

        resources_overlapping_free_range_end = await resource.get_descendants_as_view(
            FreeSpace,
            r_filter=ResourceFilter(
                tags=(FreeSpace,),
                attribute_filters=filter_overlapping_free_range_end,
            ),
        )
        resources_overlapping_free_range_start = await resource.get_descendants_as_view(
            FreeSpace,
            r_filter=ResourceFilter(
                tags=(FreeSpace,),
                attribute_filters=filter_overlapping_free_range_start,
            ),
        )

        return chain(
            resources_overlapping_free_range_end,
            resources_overlapping_free_range_start,
        )


@dataclass
class FreeSpaceModifierConfig(ComponentConfig):
    """
    Configuration for modifier which marks some free space.

    :var permissions: memory permissions to give the created free space.
    """

    permissions: MemoryPermissions


class FreeSpaceModifier(Modifier[FreeSpaceModifierConfig]):
    """
    Turn a [MemoryRegion][ofrak.core.memory_region.MemoryRegion] resource into allocatable free
    space by replacing its data with NOP instructions and tagging it as
    [FreeSpace][ofrak.core.free_space.FreeSpace].
    """

    targets = (MemoryRegion,)

    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
        assembler_service: AssemblerServiceInterface,
    ):
        self._assembler_service = assembler_service
        super().__init__(resource_factory, data_service, resource_service)

    async def modify(self, resource: Resource, config: FreeSpaceModifierConfig):
        mem_region_view = await resource.view_as(MemoryRegion)

        freed_range = Range(
            mem_region_view.virtual_address,
            mem_region_view.virtual_address + mem_region_view.size,
        )

        parent_mr_view = await resource.get_parent_as_view(MemoryRegion)
        patch_offset = parent_mr_view.get_offset_in_self(freed_range.start)
        patch_range = freed_range.translate(patch_offset - freed_range.start)
        program_ancestor_r = await resource.get_only_ancestor(
            r_filter=ResourceFilter.with_tags(Program)
        )
        program_attrs = await program_ancestor_r.analyze(ProgramAttributes)

        if resource.has_tag(BasicBlock):
            block = await resource.view_as(BasicBlock)
            mode = block.mode
        elif resource.has_tag(ComplexBlock):
            complex_block = await resource.view_as(ComplexBlock)
            mode = await complex_block.get_mode()
        elif resource.has_tag(Instruction):
            instruction = await resource.view_as(Instruction)
            mode = instruction.mode
        else:
            if program_attrs.isa is InstructionSet.ARM:
                # default to thumb mode on ARM
                mode = InstructionSetMode.THUMB
            else:
                mode = InstructionSetMode.NONE
        if (program_attrs, mode) not in NOPS:
            assembled_nop = await self._assembler_service.assemble(
                "nop",
                freed_range.start,
                program_attrs,
                mode,
            )
            NOPS[(program_attrs, mode)] = assembled_nop
        single_nop_bytes = NOPS[(program_attrs, mode)]
        nop_instr_size = len(single_nop_bytes)
        if freed_range.length() % nop_instr_size:
            raise ValueError(
                "Right now, we expect the length of the range to be freed to be a "
                "multiple of sizeof(NOP instruction)."
            )

        n_nop_instructions = int(freed_range.length() / nop_instr_size)
        patch_bytes = single_nop_bytes * n_nop_instructions

        await resource.delete()
        await resource.save()

        await parent_mr_view.resource.create_child_from_view(
            FreeSpace(
                mem_region_view.virtual_address,
                mem_region_view.size,
                config.permissions,
            ),
            data_range=patch_range,
            data=patch_bytes,
        )


@dataclass
class PartialFreeSpaceModifierConfig(FreeSpaceModifierConfig):
    """
    Dataclass required to free space with `PartialFreeSpaceModifier`. The configuration describes
    the range to remove, and the instruction mode (`InstructionSetMode`). Mode is required to
    accurately assemble `NOP` instructions to replace existing instructions in `range_to_remove`.

    :var range_to_remove: the ranges to consider as free space (remove)
    :var mode: the [InstructionSetMode][ofrak_type.architecture.InstructionSetMode]
    """

    range_to_remove: Range
    mode: InstructionSetMode = InstructionSetMode.NONE


class PartialFreeSpaceModifier(Modifier[PartialFreeSpaceModifierConfig]):
    """
    Turn part of a [MemoryRegion][ofrak.core.memory_region.MemoryRegion] resource into allocatable
    free space by replacing a range of its data with NOP instructions and creating a
    [FreeSpace][ofrak.core.free_space.FreeSpace] child resource at that range.
    """

    targets = (MemoryRegion,)

    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
        assembler_service: AssemblerServiceInterface,
        id_service: IDServiceInterface,
    ):
        self._assembler_service = assembler_service
        self.id_service = id_service
        super().__init__(resource_factory, data_service, resource_service)

    async def modify(self, resource: Resource, config: PartialFreeSpaceModifierConfig):
        mem_region_view = await resource.view_as(MemoryRegion)

        freed_range = config.range_to_remove
        virtual_patch_range = Range.intersect(
            Range(mem_region_view.virtual_address, mem_region_view.end_vaddr()), freed_range
        )

        overlapping_children = set()
        for possible_overlapping_child in await resource.get_children_as_view(
            MemoryRegion,
            r_filter=ResourceFilter(
                tags=(MemoryRegion,),
                attribute_filters=(
                    ResourceAttributeRangeFilter(MemoryRegion.VirtualAddress, max=freed_range.end),
                ),
            ),
        ):
            if (
                possible_overlapping_child.virtual_address > freed_range.start
                or possible_overlapping_child.end_vaddr() > freed_range.start
            ):
                overlapping_children.add(possible_overlapping_child.resource)

        for overlapping_child in overlapping_children:
            await overlapping_child.delete()

        program_ancestor_r = await resource.get_only_ancestor(
            r_filter=ResourceFilter.with_tags(Program)
        )
        program_attrs = await program_ancestor_r.analyze(ProgramAttributes)

        if (program_attrs, config.mode) not in NOPS:
            assembled_nop = await self._assembler_service.assemble(
                "nop",
                virtual_patch_range.start,
                program_attrs,
                config.mode,
            )
            NOPS[(program_attrs, config.mode)] = assembled_nop
        single_nop_bytes = NOPS[(program_attrs, config.mode)]
        nop_instr_size = len(single_nop_bytes)

        assert 0 == (virtual_patch_range.length() % nop_instr_size)
        n_nop_instructions = int(virtual_patch_range.length() / nop_instr_size)
        nop_bytes = single_nop_bytes * n_nop_instructions

        patch_offset = mem_region_view.get_offset_in_self(virtual_patch_range.start)
        patch_range = Range.from_size(patch_offset, virtual_patch_range.length())
        assert len(nop_bytes) == patch_range.length()

        await mem_region_view.resource.create_child_from_view(
            FreeSpace(
                virtual_patch_range.start,
                virtual_patch_range.length(),
                config.permissions,
            ),
            data_range=patch_range,
            data=nop_bytes,
        )
