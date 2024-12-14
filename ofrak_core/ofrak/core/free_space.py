from collections import defaultdict
from dataclasses import dataclass
from itertools import chain
from typing import List, Tuple, Dict, Optional, Iterable, Mapping

from immutabledict import immutabledict

from ofrak.core.binary import BinaryPatchModifier, BinaryPatchConfig

from ofrak.component.analyzer import Analyzer
from ofrak.component.modifier import Modifier, ModifierError
from ofrak.core.memory_region import MemoryRegion
from ofrak.model.component_model import ComponentConfig
from ofrak.model.resource_model import index
from ofrak.resource import Resource
from ofrak.resource_view import ResourceView
from ofrak.service.resource_service_i import (
    ResourceFilter,
    ResourceAttributeRangeFilter,
    ResourceAttributeValueFilter,
    ResourceSort,
)
from ofrak_patch_maker.model import AssembledObject, PatchRegionConfig, BOM
from ofrak_patch_maker.toolchain.model import Segment
from ofrak_type.memory_permissions import MemoryPermissions
from ofrak_type.range import Range, remove_subranges


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

    def allocate(
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
        allocated_ranges = self._allocate(
            permissions,
            requested_size,
            alignment,
            min_fragment_size,
            within_range,
        )

        # Having acquired a satisfactory allocation, make sure subsequent calls won't allocate
        # from this same block
        self.resource.run(
            RemoveFreeSpaceModifier,
            FreeSpaceAllocation(
                permissions,
                allocated_ranges,
            ),
        )
        self.remove_allocation_from_cached_free_ranges(allocated_ranges, permissions)

        return allocated_ranges

    def allocate_bom(
        self,
        bom: BOM,
        permission_map: Optional[Mapping[MemoryPermissions, Iterable[MemoryPermissions]]] = None,
    ) -> PatchRegionConfig:
        """
        Responsible for allocating the patches if free memory is required and
        providing details about where space was made.

        :param bom:
        :param permission_map: a map that assigns patch segment-local permissions to possible
        destination permissions. available memory pool is evaluated in order!
        Ex: a developer wants to enable allocation of RO strings from .rodata in an RX .text section.

        :return: information required to generate the linker directive script
        """
        segments_to_allocate: List[Tuple[AssembledObject, Segment]] = []
        for obj in bom.object_map.values():
            for segment in obj.segment_map.values():
                segments_to_allocate.append((obj, segment))

        # Allocate largest segments first
        segments_to_allocate.sort(key=lambda o_s: o_s[1].length, reverse=True)
        segments_by_object: Dict[str, List[Segment]] = defaultdict(list)
        for obj, segment in segments_to_allocate:
            vaddr, final_size = 0, 0
            if segment.length == 0:
                continue
            if permission_map is not None:
                possible_perms = permission_map[segment.access_perms]
            else:
                possible_perms = (segment.access_perms,)
            for candidate_permissions in possible_perms:
                try:
                    allocs = self.allocate(
                        candidate_permissions,
                        segment.length,
                        min_fragment_size=segment.length,
                        alignment=bom.segment_alignment,
                    )
                    allocation = next(iter(allocs))
                    vaddr = allocation.start
                    final_size = allocation.length()
                    break
                except FreeSpaceAllocationError:
                    continue
            if vaddr == 0 or final_size == 0:
                raise FreeSpaceAllocationError(
                    f"Could not find enough free space for access perms {possible_perms} and "
                    f"length {segment.length}"
                )
            segments_by_object[obj.path].append(
                Segment(
                    segment_name=segment.segment_name,
                    vm_address=vaddr,
                    offset=segment.offset,
                    is_entry=segment.is_entry,
                    length=final_size,
                    access_perms=segment.access_perms,
                )
            )

        all_segments: Dict[str, Tuple[Segment, ...]] = {
            object_path: tuple(segments) for object_path, segments in segments_by_object.items()
        }

        return PatchRegionConfig(bom.name + "_patch", immutabledict(all_segments))

    def _allocate(
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

    def analyze(self, resource: Resource, config: ComponentConfig = None) -> Allocatable:
        ranges_by_permissions = defaultdict(list)
        for free_space_r in resource.get_descendants_as_view(
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

    def modify(self, resource: Resource, config: FreeSpaceAllocation) -> None:
        wholly_allocated_resources = list()
        partially_allocated_resources: Dict[bytes, Tuple[FreeSpace, List[Range]]] = dict()
        allocatable = resource.view_as(Allocatable)

        for alloc in config.allocations:
            for res_wholly_in_alloc in resource.get_descendants_as_view(
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

            for res_partially_in_alloc in self._get_partially_overlapping_resources(
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
                fs.resource.create_child_from_view(
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
    def _get_partially_overlapping_resources(
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

        resources_overlapping_free_range_end = resource.get_descendants_as_view(
            FreeSpace,
            r_filter=ResourceFilter(
                tags=(FreeSpace,),
                attribute_filters=filter_overlapping_free_range_end,
            ),
        )
        resources_overlapping_free_range_start = resource.get_descendants_as_view(
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


def _find_and_delete_overlapping_children(resource: Resource, freed_range: Range):
    # Note this filter calculation has the potential to be very expensive if, for instance,
    # the resource is an entire program segment...
    overlap_resources = list(
        resource.get_children_as_view(
            MemoryRegion,
            r_filter=ResourceFilter(
                tags=(MemoryRegion,),
                attribute_filters=(
                    ResourceAttributeRangeFilter(MemoryRegion.VirtualAddress, max=freed_range.end),
                    ResourceAttributeRangeFilter(MemoryRegion.EndVaddr, min=freed_range.start + 1),
                ),
            ),
        )
    )
    for overlapping_child in overlap_resources:
        overlapping_child.resource.delete()
        overlapping_child.resource.save()


def _get_patch(freed_range: Range, stub: bytes, fill: bytes) -> bytes:
    total_fill_length = freed_range.length() - len(stub)
    remainder = total_fill_length % len(fill)
    final = b"".join([stub, fill * (total_fill_length // len(fill)), fill[:remainder]])
    assert len(final) == freed_range.length()
    return final


@dataclass
class FreeSpaceModifierConfig(ComponentConfig):
    """
    Configuration for modifier which marks some free space.

    :var permissions: Memory permissions to give the created free space.
    :var stub: Bytes for a stub to be injected before the free space. The stub will not be marked as
      [FreeSpace][ofrak.core.free_space.FreeSpace].
    :var fill: Pattern of bytes to fill the free space with.
    """

    permissions: MemoryPermissions
    stub: bytes = b""
    fill: bytes = b"\x00"

    def __post_init__(self):
        if len(self.fill) == 0:
            raise ValueError(f"The minimum size for fill is 1 byte, got 0: {self}")


class FreeSpaceModifier(Modifier[FreeSpaceModifierConfig]):
    """
    Turn a [MemoryRegion][ofrak.core.memory_region.MemoryRegion] resource into allocatable free
    space by replacing its data with b'\x00' or optionally specified bytes.

    The modifier allows for an optional "stub", bytes to be injected at the beginning of the target resource. The stub
    bytes are not marked as [FreeSpace][ofrak.core.free_space.FreeSpace].
    """

    targets = (MemoryRegion,)

    def modify(self, resource: Resource, config: FreeSpaceModifierConfig):
        mem_region_view = resource.view_as(MemoryRegion)

        freed_range = Range(
            mem_region_view.virtual_address,
            mem_region_view.virtual_address + mem_region_view.size,
        )
        patch_data = _get_patch(freed_range, config.stub, config.fill)
        parent = resource.get_parent()
        patch_offset = (resource.get_data_range_within_parent()).start
        patch_range = freed_range.translate(patch_offset - freed_range.start)

        # Grab tags, so they can be saved to the stub.
        # At some point, it might be nice to save the attributes as well.
        current_tags = resource.get_tags()
        # One interesting side effect here is the Resource used to call this modifier no longer exists
        # when this modifier returns. This can be confusing. Would an update work better in this case?
        resource.delete()
        resource.save()

        # Patch in the patch_data
        parent.run(BinaryPatchModifier, BinaryPatchConfig(patch_offset, patch_data))

        free_offset = len(config.stub)

        if len(config.stub) > 0:
            # Create the stub
            parent.create_child_from_view(
                MemoryRegion(mem_region_view.virtual_address, len(config.stub)),
                data_range=Range.from_size(patch_range.start, len(config.stub)),
                additional_tags=current_tags,
            )

        # Create the FreeSpace child
        parent.create_child_from_view(
            FreeSpace(
                mem_region_view.virtual_address + free_offset,
                mem_region_view.size - free_offset,
                config.permissions,
            ),
            data_range=Range(patch_range.start + free_offset, patch_range.end),
        )


@dataclass
class PartialFreeSpaceModifierConfig(ComponentConfig):
    """
    :var permissions: memory permissions to give the created free space.
    :var range_to_remove: The ranges to consider as free space (remove).
    :var stub: Bytes for a stub to be injected before the free space. If a stub is specified, then the FreeSpace created
      will decrease in size. For example, with a stub of b"HA" and range_to_remove=Range(4,10), the final FreeSpace will
      end up corresponding to Range(6,10).
    :var fill: Pattern of bytes to fill the free space with.
    """

    permissions: MemoryPermissions
    range_to_remove: Range
    stub: bytes = b""
    fill: bytes = b"\x00"

    def __post_init__(self):
        if len(self.fill) == 0:
            raise ValueError(f"The minimum size for fill is 1 byte, got 0: {self}")


class PartialFreeSpaceModifier(Modifier[PartialFreeSpaceModifierConfig]):
    """
    Turn part of a [MemoryRegion][ofrak.core.memory_region.MemoryRegion] resource into allocatable
    free space by replacing a range of its data with fill bytes (b'\x00' by default).

    The modifier supports optionally injecting a "stub", bytes at the beginning of the targeted range that will not be
    marked as [FreeSpace][ofrak.core.free_space.FreeSpace].
    """

    targets = (MemoryRegion,)

    def modify(self, resource: Resource, config: PartialFreeSpaceModifierConfig):
        freed_range = config.range_to_remove
        mem_region_view = resource.view_as(MemoryRegion)
        if not freed_range.within(mem_region_view.vaddr_range()):
            raise ModifierError(
                f"Free space range, {freed_range}, must lie within target memory"
                f"region range, {mem_region_view.vaddr_range()}"
            )

        _find_and_delete_overlapping_children(resource, freed_range)

        patch_offset = mem_region_view.get_offset_in_self(freed_range.start)
        patch_range = Range.from_size(patch_offset, freed_range.length())
        patch_data = _get_patch(freed_range, config.stub, config.fill)
        mem_region_view.resource.run(
            BinaryPatchModifier, BinaryPatchConfig(patch_offset, patch_data)
        )

        free_offset = len(config.stub)
        mem_region_view.resource.create_child_from_view(
            FreeSpace(
                freed_range.start + free_offset,
                freed_range.length() - free_offset,
                config.permissions,
            ),
            data_range=Range(patch_range.start + free_offset, patch_range.end),
        )
