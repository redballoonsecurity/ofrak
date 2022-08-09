import sys
from dataclasses import dataclass
from typing import Optional, List

import pytest

from ofrak import OFRAKContext
from ofrak.component.modifier import Modifier
from ofrak.resource import Resource
from ofrak.core.free_space import (
    FreeSpaceAllocation,
    Allocatable,
    RemoveFreeSpaceModifier,
    FreeSpaceAllocationError,
)
from ofrak_type.memory_permissions import MemoryPermissions
from ofrak_type.range import Range


class NullRemoveFreeSpaceModifier(Modifier[FreeSpaceAllocation]):
    """
    Mock version of the actual RemoveFreeSpaceModifier. Modify method does nothing,
    so that `allocate` can be tested without needed an actual resource structure.
    """

    id = RemoveFreeSpaceModifier.get_id()
    targets = (Allocatable,)

    async def modify(self, resource: Resource, config: FreeSpaceAllocation) -> None:
        return


@pytest.fixture
def ofrak(ofrak):
    ofrak.discover(sys.modules[__name__])
    return ofrak


@pytest.fixture
def mock_allocatable():
    return Allocatable(
        {
            MemoryPermissions.RX: [
                Range(0x100, 0x110),
                Range(0x80, 0xA0),
                Range(0xC0, 0xE0),
                Range(0x0, 0x40),
                Range(0x120, 0x200),
            ]
        }
    )


@dataclass
class AllocateTestCase:
    label: str
    requested_size: int
    expected_allocation: Optional[List[Range]]
    min_fragment_size: Optional[int] = None
    alignment: Optional[int] = 4
    within_range: Optional[Range] = None
    mem_permissions: MemoryPermissions = MemoryPermissions.RX


ALLOCATE_TEST_CASES = [
    AllocateTestCase(
        "successful non-fragmented 4-aligned allocation",
        0xC0,
        [Range(0x120, 0x1E0)],
        min_fragment_size=0xC0,
    ),
    AllocateTestCase(
        "unsuccessful non-fragmented 4-aligned allocation",
        0x100,
        None,
        min_fragment_size=0x100,
    ),
    AllocateTestCase(
        "successful fragmented 4-aligned allocation",
        0x100,
        [
            Range(0x80, 0xA0),
            Range(0xC0, 0xE0),
            Range(0x0, 0x40),
            Range(0x120, 0x1A0),
        ],
        min_fragment_size=0x20,
    ),
    AllocateTestCase(
        "unsuccessful fragmented 4-aligned allocation",
        0x170,
        None,
        min_fragment_size=0x20,
    ),
    AllocateTestCase(
        "successful non-fragmented 128-aligned allocation",
        0x80,
        [Range(0x180, 0x200)],
        min_fragment_size=0x80,
        alignment=0x80,
    ),
    AllocateTestCase(
        "unsuccessful non-fragmented 128-aligned allocation",
        0xC0,
        None,
        min_fragment_size=0x60,
        alignment=0x80,
    ),
    AllocateTestCase(
        "successful fragmented 128-aligned allocation",
        0x80,
        [
            Range(0x80, 0xA0),
            Range(0x0, 0x40),
            Range(0x180, 0x1A0),
        ],
        min_fragment_size=0x20,
        alignment=0x80,
    ),
    AllocateTestCase(
        "unsuccessful fragmented 128-aligned allocation",
        0x100,
        None,
        min_fragment_size=0x20,
        alignment=0x80,
    ),
    AllocateTestCase(
        "allocate with memory permissions not present",
        0x100,
        None,
        mem_permissions=MemoryPermissions.W,
    ),
]


@pytest.mark.parametrize("test_case", ALLOCATE_TEST_CASES, ids=lambda tc: tc.label)
async def test_allocate(ofrak_context: OFRAKContext, test_case: AllocateTestCase, mock_allocatable):
    resource = await ofrak_context.create_root_resource(test_case.label, b"\x00")
    resource.add_view(mock_allocatable)
    await resource.save()
    allocatable = await resource.view_as(Allocatable)

    if test_case.expected_allocation:
        alloc = await allocatable.allocate(
            test_case.mem_permissions,
            test_case.requested_size,
            test_case.alignment,
            test_case.min_fragment_size,
            test_case.within_range,
        )
        assert all([r in test_case.expected_allocation for r in alloc])
    else:
        with pytest.raises(FreeSpaceAllocationError):
            _ = await allocatable.allocate(
                test_case.mem_permissions,
                test_case.requested_size,
                test_case.alignment,
                test_case.min_fragment_size,
                test_case.within_range,
            )
