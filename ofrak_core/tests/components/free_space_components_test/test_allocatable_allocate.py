import inspect
import logging
import os
import sys
from dataclasses import dataclass
from typing import Optional, List

from ofrak_patch_maker.toolchain.llvm_12 import LLVM_12_0_1_Toolchain

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
from ofrak_patch_maker.patch_maker import PatchMaker
from ofrak_patch_maker.toolchain.model import (
    Segment,
    ToolchainConfig,
    BinFileType,
    CompilerOptimizationLevel,
)
from ofrak_type import (
    ArchInfo,
    InstructionSet,
    SubInstructionSet,
    BitWidth,
    Endianness,
    ProcessorType,
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
        free_space_ranges={
            MemoryPermissions.RX: [
                Range(0x100, 0x110),
                Range(0x80, 0xA0),
                Range(0xC0, 0xE0),
                Range(0x0, 0x40),
                Range(0x120, 0x200),
            ],
            MemoryPermissions.RW: [
                Range(0x400, 0x410),
            ],
        },
        dataless_free_space_ranges={
            MemoryPermissions.RW: [
                Range(0xD000, 0xD020),
                Range(0xD130, 0xD200),
            ]
        },
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
    with_data: bool = True


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
        mem_permissions=MemoryPermissions.RWX,
    ),
    AllocateTestCase(
        "successful non-fragmented with_data=False allocation prefers dataless range",
        0x20,
        [
            Range(0xD000, 0xD020),
        ],
        mem_permissions=MemoryPermissions.RW,
        with_data=False,
    ),
    AllocateTestCase(
        "successful fragmented with_data=False allocation falls back to data mapped range",
        0x100,
        [
            Range(0x400, 0x410),
            Range(0xD000, 0xD020),
            Range(0xD130, 0xD200),
        ],
        mem_permissions=MemoryPermissions.RW,
        min_fragment_size=0x10,
        with_data=False,
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
            test_case.with_data,
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
                test_case.with_data,
            )


async def test_allocate_bom(ofrak_context: OFRAKContext, tmpdir):
    source_path = os.path.join(tmpdir, "test_source.c")
    with open(source_path, "w") as f:
        f.write(
            inspect.cleandoc(
                """
            static int global_arr[64] __attribute__((section(".bss.new"))) = {0};
            static int global_arr_legacy[256] __attribute__((section(".bss.legacy"))) = {0};
            
            int main_supplement(int a, int b)
            {
                if (a*b > 49) {
                    global_arr[3] = 1;
                }
                return a*b;
            }
            
            int foo(int* arr) {
                return arr[48];
            }
            
            #ifdef __GNUC__
            __attribute__((section(".text")))
            #endif // __GNUC__
            int main(void) {
               int a = 49;
               int b = 29;
               int c = -38;
               int d = main_supplement(a, b) * c;
               (void) d;
               return foo(global_arr_legacy);
            }

            """
            )
        )

    proc = ArchInfo(
        InstructionSet.ARM,
        SubInstructionSet.ARMv8A,
        BitWidth.BIT_32,
        Endianness.LITTLE_ENDIAN,
        ProcessorType.GENERIC_A9_V7_THUMB,
    )
    tc_config = ToolchainConfig(
        file_format=BinFileType.ELF,
        force_inlines=True,
        relocatable=False,
        no_std_lib=True,
        no_jump_tables=True,
        no_bss_section=False,
        create_map_files=True,
        compiler_optimization_level=CompilerOptimizationLevel.NONE,
        debug_info=True,
    )

    logger = logging.getLogger("ToolchainTest")
    logger.setLevel("INFO")
    toolchain = LLVM_12_0_1_Toolchain(proc, tc_config)
    patch_maker = PatchMaker(
        toolchain=toolchain,
        logger=logger,
        build_dir=tmpdir,
    )

    bom = patch_maker.make_bom(
        name="example_3",
        source_list=[source_path],
        object_list=[],
        header_dirs=[],
    )

    resource = await ofrak_context.create_root_resource("test_allocate_bom", b"\x00")
    resource.add_view(
        Allocatable(
            free_space_ranges={
                MemoryPermissions.RX: [
                    Range(0x100, 0x110),
                    Range(0x80, 0xA0),
                    Range(0xC0, 0xE0),
                    Range(0x0, 0x40),
                    Range(0x120, 0x200),
                ]
            },
            dataless_free_space_ranges={MemoryPermissions.RW: [Range(0xD000, 0xD100)]},
        )
    )
    await resource.save()

    allocatable = await resource.view_as(Allocatable)

    with pytest.warns(DeprecationWarning):
        patch_config = await allocatable.allocate_bom(bom)

    assert len(patch_config.segments) == 1
    (segments,) = patch_config.segments.values()
    segments_by_name = {seg.segment_name: seg for seg in segments}

    assert segments_by_name[".text"].vm_address == 0x120
    assert segments_by_name[".bss.new"].vm_address == 0xD000
    assert segments_by_name[".bss.legacy"].vm_address == Segment.BSS_LEGACY_VADDR
