import os

import pytest

from ofrak import ResourceFilter
from ofrak.core import CodeRegion
from ofrak_patch_maker.model import PatchRegionConfig
from ofrak_patch_maker.toolchain.model import Segment
from ofrak_patch_maker.toolchain.utils import get_file_format
from ofrak_patch_maker_test import ToolchainUnderTest
from ofrak_patch_maker_test.test_toolchain_asm import (
    run_challenge_3_reloc_toy_example_test,
    run_monkey_patch_test,
)
from ofrak_patch_maker_test.test_toolchain_c import run_hello_world_test, run_bounds_check_test
from ofrak_type.endianness import Endianness
from ofrak_type.bit_width import BitWidth
from ofrak_type.architecture import (
    InstructionSet,
    SubInstructionSet,
    ProcessorType,
)
from ofrak.core.architecture import ProgramAttributes
from ofrak_patch_maker.toolchain.version import ToolchainVersion
from ofrak_type.memory_permissions import MemoryPermissions

ARM_EXTENSION = ".arm"


@pytest.fixture(
    params=[
        ToolchainUnderTest(
            ToolchainVersion.GNU_ARM_NONE_EABI_10_2_1,
            ProgramAttributes(
                InstructionSet.ARM,
                SubInstructionSet.ARMv8A,
                BitWidth.BIT_32,
                Endianness.LITTLE_ENDIAN,
                ProcessorType.GENERIC_A9_V7_THUMB,
            ),
            ARM_EXTENSION,
        ),
        ToolchainUnderTest(
            ToolchainVersion.LLVM_12_0_1,
            ProgramAttributes(
                InstructionSet.ARM,
                SubInstructionSet.ARMv8A,
                BitWidth.BIT_32,
                Endianness.LITTLE_ENDIAN,
                ProcessorType.GENERIC_A9_V7_THUMB,
            ),
            ARM_EXTENSION,
        ),
    ]
)
def toolchain_under_test(request) -> ToolchainUnderTest:
    return request.param


# ASM Tests
def test_challenge_3_reloc_toy_example(toolchain_under_test: ToolchainUnderTest):
    run_challenge_3_reloc_toy_example_test(
        toolchain_under_test.toolchain_version,
        toolchain_under_test.proc,
        toolchain_under_test.extension,
    )


def test_monkey_patch(toolchain_under_test: ToolchainUnderTest):
    run_monkey_patch_test(
        toolchain_under_test.toolchain_version,
        toolchain_under_test.proc,
        toolchain_under_test.extension,
    )


# C Tests
def test_bounds_check(toolchain_under_test: ToolchainUnderTest):
    run_bounds_check_test(toolchain_under_test.toolchain_version, toolchain_under_test.proc)


def test_hello_world(toolchain_under_test: ToolchainUnderTest):
    run_hello_world_test(
        toolchain_under_test.toolchain_version,
        toolchain_under_test.proc,
    )


CURRENT_DIRECTORY = os.path.abspath(os.path.dirname(__file__))


async def arm_alignment(ofrak_context: OFRAKContext):
    program_attributes = ProgramAttributes(
        InstructionSet.ARM,
        SubInstructionSet.ARMv7A,
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
        no_bss_section=True,
        create_map_files=True,
        compiler_optimization_level=CompilerOptimizationLevel.NONE,
        debug_info=True,
        check_overlap=False,
        hard_float=True,
    )

    build_dir = tempfile.mkdtemp()

    patch_maker = PatchMaker(
        program_attributes=program_attributes,
        toolchain_config=tc_config,
        toolchain_version=ToolchainVersion.GNU_ARM_NONE_EABI_10_2_1,
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

    root_resource = await ofrak_context.create_root_resource_from_file(exec_path)
    await root_resource.unpack_recursively()

    code_regions = list(
        await root_resource.get_descendants_as_view(
            CodeRegion,
            r_filter=ResourceFilter.with_tags(CodeRegion),
        )
    )
    assert len(code_regions) == 1
    assert await code_regions[0].resource.get_data() == b"\x05\xe0"
    assert code_regions[0].virtual_address == 0x51A
    assert code_regions[0].size == 2


def test_alignment_arm():
    ofrak = OFRAK(logging.INFO)
    ofrak.run(arm_alignment)
