from collections import defaultdict
from dataclasses import dataclass, field, replace
from itertools import chain
from typing import List, Tuple, Dict, Optional, Iterable, Mapping, Type
from warnings import warn

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
class AnyFreeSpace(MemoryRegion):
    permissions: MemoryPermissions

    @index
    def Permissions(self) -> int:
        return self.permissions.value


@dataclass
class FreeSpace(AnyFreeSpace):
    ...


@dataclass
class RuntimeFreeSpace(AnyFreeSpace):
    ...


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
    dataless_free_space_ranges: Dict[MemoryPermissions, List[Range]] = field(default_factory=dict)

    async def allocate(
        self,
        permissions: MemoryPermissions,
        requested_size: int,
        alignment: int = 4,
        min_fragment_size: Optional[int] = None,
        within_range: Optional[Range] = None,
        with_data: bool = True,
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
        :param with_data: Whether the free space range(s) need to be mapped to some modifiable
        data or not. Ranges without data are suitable for uninitialized memory e.g. `.bss`.

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
            with_data,
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

    async def allocate_bom(
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

        # Allocate non-bss and largest segments first
        segments_to_allocate.sort(key=lambda o_s: (not o_s[1].is_bss, o_s[1].length), reverse=True)
        segments_by_object: Dict[str, List[Segment]] = defaultdict(list)
        for obj, segment in segments_to_allocate:
            vaddr, final_size = 0, 0
            if segment.length == 0:
                continue
            if permission_map is not None:
                possible_perms = permission_map[segment.access_perms]
            else:
                possible_perms = (segment.access_perms,)
            alignment = max(bom.segment_alignment, segment.alignment)
            for candidate_permissions in possible_perms:
                try:
                    allocs = await self.allocate(
                        candidate_permissions,
                        segment.length,
                        min_fragment_size=segment.length,
                        alignment=alignment,
                        with_data=not segment.is_bss,
                    )
                    allocation = next(iter(allocs))
                    vaddr = allocation.start
                    final_size = allocation.length()
                    break
                except FreeSpaceAllocationError:
                    continue

            if final_size == 0:
                if segment.is_bss:
                    # fall back to legacy .bss allocation
                    warn(
                        f"Could not find enough free space for unloaded segment with access perms "
                        "{possible_perms} and length {segment.length}. Assuming segment will be "
                        "placed with deprecated unsafe_bss_segment by ofrak_patch_maker.",
                        category=DeprecationWarning,
                    )
                    vaddr = Segment.BSS_LEGACY_VADDR
                    final_size = segment.length
                else:
                    raise FreeSpaceAllocationError(
                        f"Could not find enough free space for access perms {possible_perms} and "
                        f"length {segment.length}"
                    )

            segments_by_object[obj.path].append(
                replace(
                    segment,
                    vm_address=vaddr,
                    length=final_size,
                    alignment=alignment,
                )
            )

        all_segments: Dict[str, Tuple[Segment, ...]] = {
            object_path: tuple(segments) for object_path, segments in segments_by_object.items()
        }

        return PatchRegionConfig(bom.name + "_patch", immutabledict(all_segments))

    async def _allocate(
        self,
        permissions: MemoryPermissions,
        requested_size: int,
        alignment: int = 4,
        min_fragment_size: Optional[int] = None,
        within_range: Optional[Range] = None,
        with_data: bool = True,
    ) -> List[Range]:
        if with_data:
            free_ranges = self.free_space_ranges.get(permissions, [])
            if len(free_ranges) == 0:
                raise FreeSpaceAllocationError(
                    f"No free space with mapped data and permissions {permissions}."
                )
        else:
            free_ranges = self.dataless_free_space_ranges.get(
                permissions, []
            ) + self.free_space_ranges.get(permissions, [])
            if len(free_ranges) == 0:
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
                free_range = align_range_start(free_range, alignment)
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
                f"within_range={within_range}, "
                f"with_data={with_data}."
            )

        return allocation

    @staticmethod
    def sort_free_ranges(ranges: Iterable[Range]) -> List[Range]:
        return list(sorted(ranges, key=lambda r: (r.length(), r.start)))

    def remove_allocation_from_cached_free_ranges(
        self, allocation: List[Range], permissions: MemoryPermissions
    ):
        if len(allocation) == 0:
            return

        for cache in self.free_space_ranges, self.dataless_free_space_ranges:
            if permissions not in cache:
                continue

            new_ranges = remove_subranges(
                cache[permissions],
                allocation,
            )
            cache[permissions] = Allocatable.sort_free_ranges(new_ranges)


class FreeSpaceAnalyzer(Analyzer[None, Allocatable]):
    """
    Analyze an `Allocatable` resource to find the ranges of free space it contains by searching for
    descendants tagged as `FreeSpace`. The ranges of each individual `FreeSpace` resource will be
    globbed into as few non-overlapping ranges as possible. The ranges of different types of free
    space - such as RW permissions vs RX permissions - will be calculated and stored separately.
    """

    targets = (Allocatable,)
    outputs = (Allocatable,)

    @staticmethod
    def _merge_ranges_by_permissions(free_spaces: Iterable[AnyFreeSpace]):
        ranges_by_permissions = defaultdict(list)
        for free_space_r in free_spaces:
            ranges_by_permissions[free_space_r.permissions].append(free_space_r.vaddr_range())

        merged_ranges_by_permissions: Dict[MemoryPermissions, List[Range]] = {}
        for perms, ranges in ranges_by_permissions.items():
            merged_ranges_by_permissions[perms] = Allocatable.sort_free_ranges(
                Range.merge_ranges(ranges)
            )

        return merged_ranges_by_permissions

    async def analyze(self, resource: Resource, config: ComponentConfig = None) -> Allocatable:
        free_spaces_with_data = []
        free_spaces_without_data = []

        for free_space_r in await resource.get_descendants_as_view(
            AnyFreeSpace,
            r_filter=ResourceFilter.with_tags(AnyFreeSpace),
            r_sort=ResourceSort(AnyFreeSpace.VirtualAddress),
        ):
            if free_space_r.resource.has_tag(RuntimeFreeSpace):
                if free_space_r.resource.get_data_id() is not None:
                    raise ValueError(
                        f"Found RuntimeFreeSpace with mapped data, should be FreeSpace instead"
                    )
                free_spaces_without_data.append(free_space_r)
            elif free_space_r.resource.has_tag(FreeSpace):
                if free_space_r.resource.get_data_id() is None:
                    raise ValueError(
                        f"Found FreeSpace without mapped data, should be RuntimeFreeSpace instead"
                    )
                free_spaces_with_data.append(free_space_r)
            else:
                raise TypeError("Got AnyFreeSpace without FreeSpace or RuntimeFreeSpace tags")

        return Allocatable(
            free_space_ranges=self._merge_ranges_by_permissions(free_spaces_with_data),
            dataless_free_space_ranges=self._merge_ranges_by_permissions(free_spaces_without_data),
        )


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
        wholly_allocated_resources: List[AnyFreeSpace] = []
        partially_allocated_resources: Dict[bytes, Tuple[AnyFreeSpace, List[Range]]] = dict()
        allocatable = await resource.view_as(Allocatable)

        for alloc in config.allocations:
            for res_wholly_in_alloc in await resource.get_descendants_as_view(
                AnyFreeSpace,
                r_filter=ResourceFilter(
                    tags=(AnyFreeSpace,),
                    attribute_filters=(
                        ResourceAttributeValueFilter(
                            AnyFreeSpace.Permissions, config.permissions.value
                        ),
                        ResourceAttributeRangeFilter(
                            AnyFreeSpace.VirtualAddress,
                            min=alloc.start,
                            max=alloc.end - 1,
                        ),
                        ResourceAttributeRangeFilter(
                            AnyFreeSpace.EndVaddr, min=alloc.start + 1, max=alloc.end
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
            fs.resource.remove_tag(RuntimeFreeSpace)
            fs.resource.remove_tag(AnyFreeSpace)

        for fs, allocated_ranges in partially_allocated_resources.values():
            remaining_free_space_ranges = remove_subranges([fs.vaddr_range()], allocated_ranges)
            if fs.resource.has_tag(FreeSpace):
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
            elif fs.resource.has_tag(RuntimeFreeSpace):
                for remaining_range in remaining_free_space_ranges:
                    await fs.resource.create_child_from_view(
                        RuntimeFreeSpace(
                            remaining_range.start,
                            remaining_range.length(),
                            fs.permissions,
                        ),
                        data_range=None,
                    )
                fs.resource.remove_tag(RuntimeFreeSpace)
            else:
                raise TypeError(f"Got AnyFreeSpace {fs} without FreeSpace or RuntimeFreeSpace tags")

            fs.resource.remove_tag(AnyFreeSpace)

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
    ) -> Iterable[AnyFreeSpace]:
        filter_overlapping_free_range_end = (
            ResourceAttributeValueFilter(AnyFreeSpace.Permissions, permissions.value),
            ResourceAttributeRangeFilter(AnyFreeSpace.VirtualAddress, max=alloc.end),
            ResourceAttributeRangeFilter(
                AnyFreeSpace.EndVaddr,
                min=alloc.end + 1,
            ),
        )
        filter_overlapping_free_range_start = (
            ResourceAttributeValueFilter(AnyFreeSpace.Permissions, permissions.value),
            ResourceAttributeRangeFilter(
                AnyFreeSpace.VirtualAddress,
                max=alloc.start - 1,
            ),
            ResourceAttributeRangeFilter(
                AnyFreeSpace.EndVaddr,
                min=alloc.start + 1,
            ),
        )

        resources_overlapping_free_range_end = await resource.get_descendants_as_view(
            AnyFreeSpace,
            r_filter=ResourceFilter(
                tags=(AnyFreeSpace,),
                attribute_filters=filter_overlapping_free_range_end,
            ),
        )
        resources_overlapping_free_range_start = await resource.get_descendants_as_view(
            AnyFreeSpace,
            r_filter=ResourceFilter(
                tags=(AnyFreeSpace,),
                attribute_filters=filter_overlapping_free_range_start,
            ),
        )

        return chain(
            resources_overlapping_free_range_end,
            resources_overlapping_free_range_start,
        )


async def _find_and_delete_overlapping_children(resource: Resource, freed_range: Range):
    # Note this filter calculation has the potential to be very expensive if, for instance,
    # the resource is an entire program segment...
    overlap_resources = list(
        await resource.get_children_as_view(
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
        await overlapping_child.resource.delete()
        await overlapping_child.resource.save()


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

    async def modify(self, resource: Resource, config: FreeSpaceModifierConfig):
        mem_region_view = await resource.view_as(MemoryRegion)

        freed_range = Range(
            mem_region_view.virtual_address,
            mem_region_view.virtual_address + mem_region_view.size,
        )
        parent = await resource.get_parent()

        FreeSpaceTag: Type[AnyFreeSpace]
        # no data within parent indicates we're marking a memory mapped region outside of the
        # flash for .bss (RW) space. In theory, an ELF object could have a read only region
        # of all zeros optimized out into a SHT_NOBITS section, although in practice this never
        # happens and it goes into .rodata instead, so we treat a readonly config with no
        # data as a user error. If you ever encounter a readonly, SHT_NOBITS section, file an issue
        # to remove this check.
        if resource.get_data_id() is None:
            if config.permissions & MemoryPermissions.RW != MemoryPermissions.RW:
                raise ValueError(
                    "FreeSpaceModifier on a resource with no data should only be used for RW(X) regions"
                )

            if len(config.stub) != 0:
                raise ValueError("FreeSpaceModifier on a resource with no data cannot have a stub")

            freed_data_range = None
            FreeSpaceTag = RuntimeFreeSpace
        else:
            patch_data = _get_patch(freed_range, config.stub, config.fill)
            patch_offset = (await resource.get_data_range_within_parent()).start
            patch_range = freed_range.translate(patch_offset - freed_range.start)

            # Patch in the patch_data
            await parent.run(BinaryPatchModifier, BinaryPatchConfig(patch_offset, patch_data))

            if len(config.stub) > 0:
                # Grab tags, so they can be saved to the stub.
                # At some point, it might be nice to save the attributes as well.
                current_tags = resource.get_tags()

                await parent.create_child_from_view(
                    MemoryRegion(mem_region_view.virtual_address, len(config.stub)),
                    data_range=Range.from_size(patch_range.start, len(config.stub)),
                    additional_tags=current_tags,
                )

            freed_data_range = Range(patch_range.start + len(config.stub), patch_range.end)
            FreeSpaceTag = FreeSpace

        # One interesting side effect here is the Resource used to call this modifier no longer exists
        # when this modifier returns. This can be confusing. Would an update work better in this case?
        await resource.delete()
        await resource.save()

        free_offset = len(config.stub)

        # Create the FreeSpace child
        await parent.create_child_from_view(
            FreeSpaceTag(
                mem_region_view.virtual_address + free_offset,
                mem_region_view.size - free_offset,
                config.permissions,
            ),
            data_range=freed_data_range,
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

    async def modify(self, resource: Resource, config: PartialFreeSpaceModifierConfig):
        freed_range = config.range_to_remove
        mem_region_view = await resource.view_as(MemoryRegion)
        if not freed_range.within(mem_region_view.vaddr_range()):
            raise ModifierError(
                f"Free space range, {freed_range}, must lie within target memory"
                f"region range, {mem_region_view.vaddr_range()}"
            )

        await _find_and_delete_overlapping_children(resource, freed_range)

        patch_offset = mem_region_view.get_offset_in_self(freed_range.start)
        patch_range = Range.from_size(patch_offset, freed_range.length())
        patch_data = _get_patch(freed_range, config.stub, config.fill)
        await mem_region_view.resource.run(
            BinaryPatchModifier, BinaryPatchConfig(patch_offset, patch_data)
        )

        free_offset = len(config.stub)
        await mem_region_view.resource.create_child_from_view(
            FreeSpace(
                freed_range.start + free_offset,
                freed_range.length() - free_offset,
                config.permissions,
            ),
            data_range=Range(patch_range.start + free_offset, patch_range.end),
        )


def align_range_start(unaligned_range: Range, alignment: int) -> Range:
    """
    Increase the range start address so it is a multiple of the `alignment` size.
    This function does not update the end address of the Range.

    :param unaligned_range: the range to align
    :param alignment: the new start address will be a multiple of this value

    :raises ValueError: if alignment is greater than length of the unaligned range

    :return: a new Range whose start address has the specified alignment
    """
    offset_to_align_start = (alignment - (unaligned_range.start % alignment)) % alignment

    try:
        aligned_range = Range(
            unaligned_range.start + offset_to_align_start,
            unaligned_range.end,
        )
    except ValueError as e:
        raise e

    assert aligned_range.within(unaligned_range)

    return aligned_range
