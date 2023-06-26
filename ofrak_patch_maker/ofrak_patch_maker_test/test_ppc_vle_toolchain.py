import os
import tempfile

import pytest

from ofrak_patch_maker.model import PatchRegionConfig
from ofrak_patch_maker.patch_maker import PatchMaker
from ofrak_patch_maker.toolchain.model import (
    ToolchainConfig,
    BinFileType,
    CompilerOptimizationLevel,
    Segment,
)
from ofrak_patch_maker.toolchain.utils import get_file_format
from ofrak_patch_maker_test import ToolchainUnderTest, CURRENT_DIRECTORY

from ofrak_patch_maker.toolchain.gnu_ppc import GNU_PPCVLE_4_Toolchain
from ofrak_type import (
    ArchInfo,
    InstructionSet,
    BitWidth,
    Endianness,
    SubInstructionSet,
    MemoryPermissions,
)

from ofrak_patch_maker_test.toolchain_asm import (
    run_monkey_patch_test,
)

from ofrak_patch_maker_test.toolchain_c import (
    run_bounds_check_test,
    run_hello_world_test,
)

PPC_EXTENSION = ".vle"


@pytest.fixture(
    params=[
        ToolchainUnderTest(
            GNU_PPCVLE_4_Toolchain,
            ArchInfo(
                InstructionSet.PPC,
                SubInstructionSet.PPCVLE,
                BitWidth.BIT_32,
                Endianness.BIG_ENDIAN,
                None,
            ),
            PPC_EXTENSION,
        ),
    ]
)
def toolchain_under_test(request) -> ToolchainUnderTest:
    return request.param


# ASM Tests
# def test_challenge_3_reloc_toy_example(toolchain_under_test: ToolchainUnderTest):
#     # TODO
#     pass


def test_monkey_patch(toolchain_under_test: ToolchainUnderTest):
    run_monkey_patch_test(toolchain_under_test)


# C Tests
def test_bounds_check(toolchain_under_test: ToolchainUnderTest):
    run_bounds_check_test(toolchain_under_test)


def test_hello_world(toolchain_under_test: ToolchainUnderTest):
    run_hello_world_test(toolchain_under_test)


def test_vle_alignment(toolchain_under_test: ToolchainUnderTest):
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
    patch_source = os.path.join(CURRENT_DIRECTORY, "test_alignment/patch_vle.as")
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
    segment_dict = {
        patch_object.path: (text_segment_patch,),
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
        assert dat[code_offset : code_offset + 2] == b"\x00\x80"
