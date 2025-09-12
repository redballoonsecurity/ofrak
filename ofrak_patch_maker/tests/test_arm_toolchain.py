import os
import tempfile

import pytest
from ofrak_patch_maker.toolchain.llvm_12 import LLVM_12_0_1_Toolchain

from ofrak_type import ArchInfo
from ofrak_patch_maker.model import PatchRegionConfig
from ofrak_patch_maker.patch_maker import PatchMaker
from ofrak_patch_maker.toolchain.gnu_arm import GNU_ARM_NONE_EABI_10_2_1_Toolchain
from ofrak_patch_maker.toolchain.model import (
    CompilerOptimizationLevel,
    BinFileType,
    ToolchainConfig,
    Segment,
)
from ofrak_patch_maker.toolchain.utils import get_file_format
from ofrak_patch_maker_test import ToolchainUnderTest, CURRENT_DIRECTORY
from ofrak_patch_maker_test.toolchain_asm import (
    run_challenge_3_reloc_toy_example_test,
    run_monkey_patch_test,
)
from ofrak_patch_maker_test.toolchain_c import (
    run_hello_world_test,
    run_bounds_check_test,
    run_relocatable_test,
)
from ofrak_type.architecture import (
    InstructionSet,
    SubInstructionSet,
    ProcessorType,
)
from ofrak_type.bit_width import BitWidth
from ofrak_type.endianness import Endianness
from ofrak_type.memory_permissions import MemoryPermissions

ARM_EXTENSION = ".arm"


@pytest.fixture(
    params=[
        ToolchainUnderTest(
            GNU_ARM_NONE_EABI_10_2_1_Toolchain,
            ArchInfo(
                InstructionSet.ARM,
                SubInstructionSet.ARMv8A,
                BitWidth.BIT_32,
                Endianness.LITTLE_ENDIAN,
                ProcessorType.GENERIC_A9_V7_THUMB,
            ),
            ARM_EXTENSION,
        ),
        ToolchainUnderTest(
            GNU_ARM_NONE_EABI_10_2_1_Toolchain,
            ArchInfo(
                InstructionSet.ARM,
                SubInstructionSet.ARMv8A,
                BitWidth.BIT_32,
                Endianness.BIG_ENDIAN,
                ProcessorType.GENERIC_A9_V7_THUMB,
            ),
            ARM_EXTENSION,
        ),
        ToolchainUnderTest(
            GNU_ARM_NONE_EABI_10_2_1_Toolchain,
            ArchInfo(
                InstructionSet.ARM,
                SubInstructionSet.ARMv8A,
                BitWidth.BIT_32,
                Endianness.BIG_ENDIAN,
                ProcessorType.GENERIC_ARM_BE8,
            ),
            ARM_EXTENSION,
        ),
        ToolchainUnderTest(
            LLVM_12_0_1_Toolchain,
            ArchInfo(
                InstructionSet.ARM,
                SubInstructionSet.ARMv8A,
                BitWidth.BIT_32,
                Endianness.LITTLE_ENDIAN,
                ProcessorType.GENERIC_A9_V7_THUMB,
            ),
            ARM_EXTENSION,
        ),
        # Exercise userspace_dynamic_linker logic
        ToolchainUnderTest(
            LLVM_12_0_1_Toolchain,
            ArchInfo(
                InstructionSet.ARM,
                SubInstructionSet.ARMv8A,
                BitWidth.BIT_32,
                Endianness.LITTLE_ENDIAN,
                ProcessorType.GENERIC_A9_V7_THUMB,
            ),
            ARM_EXTENSION,
            "/opt/rbs/toolchain/gcc-arm-none-eabi-10-2020-q4-major/bin/arm-none-eabi-ld",
        ),
    ]
)
def toolchain_under_test(request) -> ToolchainUnderTest:
    return request.param


# ASM Tests
def test_challenge_3_reloc_toy_example(toolchain_under_test: ToolchainUnderTest):
    run_challenge_3_reloc_toy_example_test(toolchain_under_test)


def test_monkey_patch(toolchain_under_test: ToolchainUnderTest):
    run_monkey_patch_test(toolchain_under_test)


# C Tests
def test_bounds_check(toolchain_under_test: ToolchainUnderTest):
    run_bounds_check_test(toolchain_under_test)


def test_hello_world(toolchain_under_test: ToolchainUnderTest):
    run_hello_world_test(toolchain_under_test)


def test_relocatable(toolchain_under_test: ToolchainUnderTest, tmp_path):
    if toolchain_under_test.toolchain == LLVM_12_0_1_Toolchain:
        if toolchain_under_test.userspace_dynamic_linker is not None:
            pytest.skip("LLVM userspace mode can't supply external symbols")
        else:
            pytest.skip("LLVM test can't link .got")
    run_relocatable_test(toolchain_under_test, tmp_path)


def test_arm_alignment(toolchain_under_test: ToolchainUnderTest):
    tc_config = ToolchainConfig(
        file_format=BinFileType.ELF,
        force_inlines=True,
        relocatable=False,
        no_std_lib=True,
        no_jump_tables=True,
        no_bss_section=True,
        create_map_files=True,
        compiler_optimization_level=CompilerOptimizationLevel.NONE,
        debug_info=True,
        check_overlap=False,
        hard_float=True,
    )

    build_dir = tempfile.mkdtemp()

    patch_maker = PatchMaker(
        toolchain=toolchain_under_test.toolchain(toolchain_under_test.proc, tc_config),
        build_dir=build_dir,
    )
    patch_source = os.path.join(CURRENT_DIRECTORY, "test_alignment/patch_arm.as")
    patch_bom = patch_maker.make_bom("patch", [patch_source], [], [])

    # Grab the resulting object paths and re-map them to the segments we chose for each source file.
    patch_object = patch_bom.object_map[patch_source]
    text_segment_patch = Segment(
        segment_name=".text",
        vm_address=0x51A,
        offset=0,
        is_entry=False,
        length=2,
        access_perms=MemoryPermissions.RX,
    )
    # LLVM requires memory regions be defined for 0-length sections.
    # It'd be nice to find a compiler flag that doesn't generate empty sections in the object files.
    data_segment_placeholder = Segment(
        segment_name=".data",
        vm_address=0xFACE,
        offset=0,
        is_entry=False,
        length=0,
        access_perms=MemoryPermissions.RW,
    )
    bss_segment_placeholder = Segment(
        segment_name=".bss",
        vm_address=0xFEED,
        offset=0,
        is_entry=False,
        length=0,
        access_perms=MemoryPermissions.RW,
        is_bss=True,
    )
    segment_dict = {
        patch_object.path: (text_segment_patch, data_segment_placeholder, bss_segment_placeholder),
    }

    exec_path = os.path.join(build_dir, "patch_exec")
    # Generate a PatchRegionConfig from your segment Dict.
    # This data structure informs ld script generation which regions to create for every segment.
    p = PatchRegionConfig(patch_bom.name + "_patch", segment_dict)
    fem = patch_maker.make_fem([(patch_bom, p)], exec_path)
    assert os.path.exists(exec_path)
    assert get_file_format(exec_path) == tc_config.file_format
    code_segments = [s for s in fem.executable.segments if s.access_perms == MemoryPermissions.RX]
    assert len(code_segments) == 1
    assert code_segments[0].vm_address == 0x51A
    assert code_segments[0].length == 2
    with open(exec_path, "rb") as f:
        dat = f.read()
        code_offset = code_segments[0].offset
        if (
            toolchain_under_test.proc.endianness == Endianness.LITTLE_ENDIAN
            or toolchain_under_test.proc.processor == ProcessorType.GENERIC_ARM_BE8
        ):
            # little-endian code instructions
            expected_bytes = b"\x05\xe0"
        else:
            expected_bytes = b"\xe0\x05"
        assert dat[code_offset : code_offset + 2] == expected_bytes
