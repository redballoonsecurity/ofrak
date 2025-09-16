from dataclasses import dataclass
from typing import List, Dict

import pytest

from ofrak import OFRAKContext
from ofrak.core.memory_region import MemoryRegion
from ofrak.resource import Resource
from ofrak.core.free_space import Allocatable, FreeSpace, RuntimeFreeSpace
from .mock_tree_struct import (
    FreeSpaceTreeType,
    inflate_tree,
)
from ofrak_type.memory_permissions import MemoryPermissions
from ofrak_type.range import Range


@dataclass
class FreeSpaceAnalyzerTestCase:
    label: str
    tree_structure: FreeSpaceTreeType
    expected_free_space_ranges: Dict[MemoryPermissions, List[Range]]
    expected_dataless_free_space_ranges: Dict[MemoryPermissions, List[Range]]

    async def inflate(self, ofrak_context: OFRAKContext) -> Resource:
        return await inflate_tree(self.tree_structure, ofrak_context)


FREE_SPACE_ANALYZER_TEST_CASES = [
    FreeSpaceAnalyzerTestCase(
        "one block of free space in one resource",
        (
            MemoryRegion(0x0, 0x100),
            [
                (
                    MemoryRegion(0x0, 0x80),
                    [
                        (MemoryRegion(0x0, 0x20), None),
                        (FreeSpace(0x20, 0x30, MemoryPermissions.RX), None),
                        (MemoryRegion(0x50, 0x30), None),
                    ],
                ),
                (MemoryRegion(0x80, 0x10), None),
            ],
        ),
        {MemoryPermissions.RX: [Range(0x20, 0x50)]},
        {},
    ),
    FreeSpaceAnalyzerTestCase(
        "no free space",
        (
            MemoryRegion(0x0, 0x100),
            [
                (
                    MemoryRegion(0x0, 0x80),
                    [
                        (MemoryRegion(0x0, 0x20), None),
                        (MemoryRegion(0x20, 0x30), None),
                        (MemoryRegion(0x50, 0x30), None),
                    ],
                ),
                (MemoryRegion(0x80, 0x10), None),
            ],
        ),
        {},
        {},
    ),
    FreeSpaceAnalyzerTestCase(
        "one block of free space in multiple sibling resources",
        (
            MemoryRegion(0x0, 0x100),
            [
                (
                    MemoryRegion(0x0, 0x80),
                    [
                        (FreeSpace(0x0, 0x20, MemoryPermissions.RX), None),
                        (FreeSpace(0x20, 0x30, MemoryPermissions.RX), None),
                        (FreeSpace(0x50, 0x10, MemoryPermissions.RX), None),
                        (MemoryRegion(0x60, 0x20), None),
                    ],
                ),
                (MemoryRegion(0x80, 0x10), None),
            ],
        ),
        {MemoryPermissions.RX: [Range(0x0, 0x60)]},
        {},
    ),
    FreeSpaceAnalyzerTestCase(
        "one block of free space in multiple resources with weird relationships",
        (
            MemoryRegion(0x0, 0x100),
            [
                (
                    MemoryRegion(0x0, 0x80),
                    [
                        (MemoryRegion(0x0, 0x20), None),
                        (MemoryRegion(0x20, 0x30), None),
                        (FreeSpace(0x50, 0x30, MemoryPermissions.RX), None),
                    ],
                ),
                (
                    MemoryRegion(0x80, 0x10),
                    [
                        (
                            MemoryRegion(0x80, 0x10),
                            [
                                (
                                    MemoryRegion(0x80, 0x10),
                                    [
                                        (
                                            MemoryRegion(0x80, 0x10),
                                            [
                                                (
                                                    FreeSpace(0x80, 0x10, MemoryPermissions.RX),
                                                    None,
                                                ),
                                            ],
                                        )
                                    ],
                                )
                            ],
                        )
                    ],
                ),
                (FreeSpace(0x90, 0x20, MemoryPermissions.RX), None),
                (
                    MemoryRegion(0xB0, 0x48),
                    [
                        (FreeSpace(0xB0, 0x18, MemoryPermissions.RX), None),
                        (MemoryRegion(0xC8, 0x18), None),
                    ],
                ),
            ],
        ),
        {MemoryPermissions.RX: [Range(0x50, 0xC8)]},
        {},
    ),
    FreeSpaceAnalyzerTestCase(
        "free space ranges that would merge, but resource have different permissions",
        (
            MemoryRegion(0x0, 0x100),
            [
                (
                    MemoryRegion(0x0, 0x80),
                    [
                        (FreeSpace(0x0, 0x20, MemoryPermissions.R), None),
                        (FreeSpace(0x20, 0x30, MemoryPermissions.W), None),
                        (FreeSpace(0x50, 0x30, MemoryPermissions.X), None),
                    ],
                ),
                (MemoryRegion(0x80, 0x10), None),
            ],
        ),
        {
            MemoryPermissions.R: [Range(0x0, 0x20)],
            MemoryPermissions.W: [Range(0x20, 0x50)],
            MemoryPermissions.X: [Range(0x50, 0x80)],
        },
        {},
    ),
    FreeSpaceAnalyzerTestCase(
        "runtime free space goes into dataless_free_space_ranges",
        (MemoryRegion(0x0, 0x100), [(RuntimeFreeSpace(0x120, 0x30, MemoryPermissions.RX), None)]),
        {},
        {MemoryPermissions.RX: [Range(0x120, 0x150)]},
    ),
    FreeSpaceAnalyzerTestCase(
        "free space ranges that would merge, but one is free space and the other is runtime free space",
        (
            MemoryRegion(0x0, 0x100),
            [
                (FreeSpace(0x0, 0x100, MemoryPermissions.RW), None),
                (RuntimeFreeSpace(0x100, 0x30, MemoryPermissions.RW), None),
            ],
        ),
        {
            MemoryPermissions.RW: [Range(0x0, 0x100)],
        },
        {
            MemoryPermissions.RW: [Range(0x100, 0x130)],
        },
    ),
]


@pytest.mark.parametrize("test_case", FREE_SPACE_ANALYZER_TEST_CASES, ids=lambda tc: tc.label)
async def test_free_space_analyzer(
    ofrak_context: OFRAKContext, test_case: FreeSpaceAnalyzerTestCase
):
    allocatable_r = await test_case.inflate(ofrak_context)
    allocatable = await allocatable_r.view_as(Allocatable)

    expected_fs_types = set(test_case.expected_free_space_ranges.keys())
    actual_fs_types = set(allocatable.free_space_ranges.keys())
    assert actual_fs_types == expected_fs_types
    for fs_type in expected_fs_types:
        expected_free_ranges = test_case.expected_free_space_ranges[fs_type]
        actual_free_ranges = allocatable.free_space_ranges[fs_type]
        assert actual_free_ranges == expected_free_ranges

    expected_dataless_fs_types = set(test_case.expected_dataless_free_space_ranges.keys())
    actual_dataless_fs_types = set(allocatable.dataless_free_space_ranges.keys())
    assert expected_dataless_fs_types == actual_dataless_fs_types
    for fs_type in expected_dataless_fs_types:
        expected_dataless_free_ranges = test_case.expected_dataless_free_space_ranges[fs_type]
        actual_dataless_free_ranges = allocatable.dataless_free_space_ranges[fs_type]
        assert actual_dataless_free_ranges == expected_dataless_free_ranges


async def test_free_space_analysis_of_non_memory_region(
    ofrak_context: OFRAKContext,
):
    # root resource is not a MemoryRegion, but it has MemoryRegion and FreeSpace descendants
    root_r = await ofrak_context.create_root_resource(
        "test_r",
        b"\x00" * 0x1000,
    )
    root_r.add_tag(Allocatable)
    await root_r.save()
    assert not root_r.has_tag(MemoryRegion)

    child_1 = await root_r.create_child_from_view(
        MemoryRegion(0x100, 0x100), data_range=Range(0x800, 0x900)
    )
    # child 2 is contiguous with child 1 in memory layout, but not data layout
    child_2 = await root_r.create_child_from_view(
        FreeSpace(0x200, 0x80, MemoryPermissions.RW), data_range=Range(0x0, 0x80)
    )

    # child 3 is RuntimeFreeSpace with no data range
    child_3 = await root_r.create_child_from_view(
        RuntimeFreeSpace(0x400, 0x40, MemoryPermissions.RW), data_range=None
    )

    fs_grandchild = await child_1.create_child_from_view(
        FreeSpace(0x1A0, 0x60, MemoryPermissions.RW), data_range=Range(0xA0, 0x100)
    )

    allocatable = await root_r.view_as(Allocatable)
    assert 1 == len(allocatable.free_space_ranges.keys())
    assert [Range(0x1A0, 0x280)] == allocatable.free_space_ranges[MemoryPermissions.RW]
    assert 1 == len(allocatable.dataless_free_space_ranges.keys())
    assert [Range(0x400, 0x440)] == allocatable.dataless_free_space_ranges[MemoryPermissions.RW]


async def test_free_space_without_data_fail(
    ofrak_context: OFRAKContext,
):
    # root resource is not a MemoryRegion, but it has MemoryRegion and FreeSpace descendants
    root_r = await ofrak_context.create_root_resource(
        "test_r",
        b"\x00" * 0x1000,
    )
    root_r.add_tag(Allocatable)
    await root_r.save()
    assert not root_r.has_tag(MemoryRegion)

    await root_r.create_child_from_view(
        FreeSpace(0x100, 0x100, MemoryPermissions.RW), data_range=None
    )

    with pytest.raises(ValueError, match=r"Found FreeSpace without mapped data.*"):
        await root_r.view_as(Allocatable)


async def test_runtime_free_space_with_data_fail(
    ofrak_context: OFRAKContext,
):
    # root resource is not a MemoryRegion, but it has MemoryRegion and FreeSpace descendants
    root_r = await ofrak_context.create_root_resource(
        "test_r",
        b"\x00" * 0x1000,
    )
    root_r.add_tag(Allocatable)
    await root_r.save()
    assert not root_r.has_tag(MemoryRegion)

    await root_r.create_child_from_view(
        RuntimeFreeSpace(0x100, 0x100, MemoryPermissions.RW), data_range=Range(0x800, 0x900)
    )

    with pytest.raises(ValueError, match=r"Found RuntimeFreeSpace with mapped data.*"):
        await root_r.view_as(Allocatable)
