from dataclasses import dataclass

import pytest

from ofrak import OFRAKContext
from ofrak.core.memory_region import MemoryRegion
from ofrak.service.resource_service_i import ResourceSort
from ofrak.core.free_space import (
    AnyFreeSpace,
    FreeSpaceAllocation,
    RemoveFreeSpaceModifier,
    FreeSpace,
    RuntimeFreeSpace,
)
from .mock_tree_struct import (
    FreeSpaceTreeType,
    inflate_tree,
)
from ofrak_type.memory_permissions import MemoryPermissions
from ofrak_type.range import Range


@dataclass
class FreeSpaceAllocationModifierTestCase:
    label: str
    initial_tree_structure: FreeSpaceTreeType
    allocated_range: FreeSpaceAllocation
    resulting_tree_structure: FreeSpaceTreeType


async def validate_tree(actual_mem_region: MemoryRegion, expected_node: FreeSpaceTreeType):
    expected_mem_region, expected_children = expected_node

    if isinstance(expected_mem_region, AnyFreeSpace):
        expected_free_space = await actual_mem_region.resource.view_as(AnyFreeSpace)
        actual_free_space = await actual_mem_region.resource.view_as(AnyFreeSpace)
        assert (
            actual_free_space == expected_free_space
        ), f"Got {actual_free_space} expected {expected_free_space}"
    else:
        assert actual_mem_region == expected_mem_region

    if expected_children:
        actual_children_iter = iter(
            await actual_mem_region.resource.get_children_as_view(
                MemoryRegion, r_sort=ResourceSort(MemoryRegion.VirtualAddress)
            )
        )
        expected_chilren_iter = iter(expected_children)
        for actual_child_mem_region, expected_child_node in zip(
            actual_children_iter, expected_chilren_iter
        ):
            await validate_tree(actual_child_mem_region, expected_child_node)

        # Actual and expected children must be same size, so both iterators should be done
        with pytest.raises(StopIteration):
            # More actual children than expected!
            next(actual_children_iter)
        with pytest.raises(StopIteration):
            # Fewer actual children than expected!
            next(expected_chilren_iter)
    else:
        with pytest.raises(StopIteration):
            next(iter(await actual_mem_region.resource.get_children()))


FREE_SPACE_ALLOCATION_MODIFIER_TEST_CASES = [
    FreeSpaceAllocationModifierTestCase(
        "allocation removes tag from an entire resource",
        (
            MemoryRegion(0x0, 0x100),
            [
                (MemoryRegion(0x0, 0x40), None),
                (MemoryRegion(0x40, 0x40), None),
                (FreeSpace(0x80, 0x40, MemoryPermissions.RX), None),
                (MemoryRegion(0xC0, 0x40), None),
            ],
        ),
        FreeSpaceAllocation(MemoryPermissions.RX, [Range(0x80, 0xC0)]),
        (
            MemoryRegion(0x0, 0x100),
            [
                (MemoryRegion(0x0, 0x40), None),
                (MemoryRegion(0x40, 0x40), None),
                (MemoryRegion(0x80, 0x40), None),
                (MemoryRegion(0xC0, 0x40), None),
            ],
        ),
    ),
    FreeSpaceAllocationModifierTestCase(
        "allocation removes tag from multiple entire resources",
        (
            MemoryRegion(0x0, 0x100),
            [
                (MemoryRegion(0x0, 0x40), None),
                (FreeSpace(0x40, 0x40, MemoryPermissions.RX), None),
                (FreeSpace(0x80, 0x40, MemoryPermissions.RX), None),
                (FreeSpace(0xC0, 0x40, MemoryPermissions.RX), None),
                (RuntimeFreeSpace(0xD00, 0x40, MemoryPermissions.RX), None),
            ],
        ),
        FreeSpaceAllocation(MemoryPermissions.RX, [Range(0x40, 0x100), Range(0xD00, 0xD40)]),
        (
            MemoryRegion(0x0, 0x100),
            [
                (MemoryRegion(0x0, 0x40), None),
                (MemoryRegion(0x40, 0x40), None),
                (MemoryRegion(0x80, 0x40), None),
                (MemoryRegion(0xC0, 0x40), None),
                (MemoryRegion(0xD00, 0x40), None),
            ],
        ),
    ),
    FreeSpaceAllocationModifierTestCase(
        "allocation removes tag from resource, creates FreeSpace resource child on right side",
        (
            MemoryRegion(0x0, 0x100),
            [
                (MemoryRegion(0x0, 0x40), None),
                (MemoryRegion(0x40, 0x40), None),
                (FreeSpace(0x80, 0x40, MemoryPermissions.RX), None),
                (MemoryRegion(0xC0, 0x40), None),
            ],
        ),
        FreeSpaceAllocation(MemoryPermissions.RX, [Range(0x80, 0xA0)]),
        (
            MemoryRegion(0x0, 0x100),
            [
                (MemoryRegion(0x0, 0x40), None),
                (MemoryRegion(0x40, 0x40), None),
                (
                    MemoryRegion(0x80, 0x40),
                    [(FreeSpace(0xA0, 0x20, MemoryPermissions.RX), None)],
                ),
                (MemoryRegion(0xC0, 0x40), None),
            ],
        ),
    ),
    FreeSpaceAllocationModifierTestCase(
        "allocation removes tag from resource, creates FreeSpace resource child on left side",
        (
            MemoryRegion(0x0, 0x100),
            [
                (MemoryRegion(0x0, 0x40), None),
                (MemoryRegion(0x40, 0x40), None),
                (FreeSpace(0x80, 0x40, MemoryPermissions.RX), None),
                (MemoryRegion(0xC0, 0x40), None),
            ],
        ),
        FreeSpaceAllocation(MemoryPermissions.RX, [Range(0xA0, 0xC0)]),
        (
            MemoryRegion(0x0, 0x100),
            [
                (MemoryRegion(0x0, 0x40), None),
                (MemoryRegion(0x40, 0x40), None),
                (
                    MemoryRegion(0x80, 0x40),
                    [(FreeSpace(0x80, 0x20, MemoryPermissions.RX), None)],
                ),
                (MemoryRegion(0xC0, 0x40), None),
            ],
        ),
    ),
    FreeSpaceAllocationModifierTestCase(
        "allocation removes tag from resource, creates FreeSpace resource child on left and right",
        (
            MemoryRegion(0x0, 0x100),
            [
                (MemoryRegion(0x0, 0x40), None),
                (MemoryRegion(0x40, 0x40), None),
                (FreeSpace(0x80, 0x40, MemoryPermissions.RX), None),
                (MemoryRegion(0xC0, 0x40), None),
            ],
        ),
        FreeSpaceAllocation(MemoryPermissions.RX, [Range(0x90, 0xB0)]),
        (
            MemoryRegion(0x0, 0x100),
            [
                (MemoryRegion(0x0, 0x40), None),
                (MemoryRegion(0x40, 0x40), None),
                (
                    MemoryRegion(0x80, 0x40),
                    [
                        (FreeSpace(0x80, 0x10, MemoryPermissions.RX), None),
                        (FreeSpace(0xB0, 0x10, MemoryPermissions.RX), None),
                    ],
                ),
                (MemoryRegion(0xC0, 0x40), None),
            ],
        ),
    ),
    FreeSpaceAllocationModifierTestCase(
        "allocation removes tag from resource, creates FreeSpace resource child in middle",
        (
            MemoryRegion(0x0, 0x100),
            [
                (MemoryRegion(0x0, 0x40), None),
                (MemoryRegion(0x40, 0x40), None),
                (FreeSpace(0x80, 0x40, MemoryPermissions.RX), None),
                (MemoryRegion(0xC0, 0x40), None),
            ],
        ),
        FreeSpaceAllocation(
            MemoryPermissions.RX,
            [Range(0x80, 0x90), Range(0xB0, 0xC0)],
        ),
        (
            MemoryRegion(0x0, 0x100),
            [
                (MemoryRegion(0x0, 0x40), None),
                (MemoryRegion(0x40, 0x40), None),
                (
                    MemoryRegion(0x80, 0x40),
                    [
                        (FreeSpace(0x90, 0x20, MemoryPermissions.RX), None),
                    ],
                ),
                (MemoryRegion(0xC0, 0x40), None),
            ],
        ),
    ),
]


@pytest.mark.parametrize(
    "test_case", FREE_SPACE_ALLOCATION_MODIFIER_TEST_CASES, ids=lambda tc: tc.label
)
async def test_free_space_analyzer(
    ofrak_context: OFRAKContext, test_case: FreeSpaceAllocationModifierTestCase
):
    allocatable_r = await inflate_tree(test_case.initial_tree_structure, ofrak_context)
    await allocatable_r.run(RemoveFreeSpaceModifier, test_case.allocated_range)

    await validate_tree(
        await allocatable_r.view_as(MemoryRegion),
        test_case.resulting_tree_structure,
    )
