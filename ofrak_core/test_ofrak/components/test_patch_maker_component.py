from dataclasses import dataclass
from pathlib import Path
from typing import List, Type

import pytest
import re
import subprocess
import filelock

from ofrak.core import MemoryRegion
from ofrak.model.resource_model import EphemeralResourceContextFactory, ClientResourceContextFactory
from ofrak_patch_maker.toolchain.gnu_x64 import GNU_X86_64_LINUX_EABI_10_3_0_Toolchain

from ofrak_patch_maker.toolchain.gnu_arm import GNU_ARM_NONE_EABI_10_2_1_Toolchain
from ofrak_patch_maker.toolchain.llvm_12 import LLVM_12_0_1_Toolchain
from ofrak_patch_maker.toolchain.abstract import Toolchain

from ofrak import OFRAKContext, ResourceFilter, ResourceAttributeRangeFilter
from ofrak.core.architecture import ProgramAttributes
from ofrak_type import MemoryPermissions
from ofrak_type.architecture import (
    InstructionSet,
    SubInstructionSet,
    InstructionSetMode,
)
from ofrak.core.basic_block import BasicBlock
from ofrak.core.complex_block import ComplexBlock
from ofrak.core.program import Program
from ofrak.core.patch_maker.linkable_symbol import LinkableSymbolType
from ofrak.core.patch_maker.modifiers import (
    FunctionReplacementModifierConfig,
    FunctionReplacementModifier,
    SegmentInjectorModifierConfig,
    SegmentInjectorModifier,
    SourceBundle,
)
from ofrak_patch_maker.toolchain.model import (
    CompilerOptimizationLevel,
    BinFileType,
    ToolchainConfig,
    Segment,
)
from ofrak_patch_maker.toolchain.utils import get_repository_config
from ofrak_type.bit_width import BitWidth
from ofrak_type.endianness import Endianness

PATCH_DIRECTORY = str(Path(__file__).parent / "assets" / "src")
X86_64_PROGRAM_PATH = str(Path(__file__).parent / "assets" / "hello.out")
ARM32_PROGRAM_PATH = str(Path(__file__).parent / "assets" / "simple_arm_gcc.o.elf")


@pytest.fixture(params=[EphemeralResourceContextFactory, ClientResourceContextFactory])
async def ofrak_context(request, ofrak_context):
    ofrak_context._resource_context_factory = request.param()
    return ofrak_context


def normalize_assembly(assembly_str: str) -> str:
    """
    Normalize an assembly string:
    - strip leading and trailing whitespace from all lines
    - replace all consecutive strings of whitespace (including tabs) with a single space
    """
    assembly_lines = assembly_str.splitlines()
    assembly_lines = [line.strip() for line in assembly_lines]
    assembly_lines = [re.sub(r"\s+", " ", line) for line in assembly_lines]
    return "\n".join(assembly_lines)


@dataclass
class ProgramConfig:
    """Information on a program and the function that will be targeted."""

    path: str
    attrs: ProgramAttributes
    function_name: str
    function_vaddr: int
    function_size: int


@dataclass
class FunctionReplacementTestCaseConfig:
    """Configuration for a function replacement modification."""

    program: ProgramConfig
    # Relative filename of the source code file to use as replacement, within PATCH_DIRECTORY
    replacement_patch: str
    # Name of the section to use in the toolchain.conf file
    toolchain_name: str
    toolchain: Type[Toolchain]
    # A list of lines that are expected to appear consecutively in the output of `objdump -d <modified program>`.
    # Note that the comparison is done after applying `normalize_assembly()` on both texts.
    expected_objdump_output: List[str]
    compiler_optimization_level: CompilerOptimizationLevel = CompilerOptimizationLevel.SPACE


X86_64_PROGRAM_CONFIG = ProgramConfig(
    X86_64_PROGRAM_PATH,
    ProgramAttributes(
        InstructionSet.X86,
        None,
        BitWidth.BIT_64,
        Endianness.LITTLE_ENDIAN,
        None,
    ),
    "main",
    0x4004C4,
    28,
)

ARM32_PROGRAM_CONFIG = ProgramConfig(
    ARM32_PROGRAM_PATH,
    ProgramAttributes(
        InstructionSet.ARM,
        SubInstructionSet.ARMv5T,
        BitWidth.BIT_32,
        Endianness.LITTLE_ENDIAN,
        None,
    ),
    "main",
    0x8068,
    40,
)

TEST_CASE_CONFIGS = [
    FunctionReplacementTestCaseConfig(
        X86_64_PROGRAM_CONFIG,
        "patch_basic.c",
        "GNU_X86_64_LINUX_EABI_10_3_0",
        GNU_X86_64_LINUX_EABI_10_3_0_Toolchain,
        [
            "00000000004004c4 <main>:",
            "  4004c4: b8 03 00 00 00        mov    $0x3,%eax",
            "  4004c9: c3                    retq",
        ],
    ),
    FunctionReplacementTestCaseConfig(
        X86_64_PROGRAM_CONFIG,
        "patch_basic.c",
        "LLVM_12_0_1",
        LLVM_12_0_1_Toolchain,
        [
            "00000000004004c4 <main>:",
            "  4004c4: 55 pushq %rbp",
            "  4004c5: 48 89 e5 movq %rsp, %rbp",
            "  4004c8: b8 03 00 00 00 movl $3, %eax",
            "  4004cd: 5d popq %rbp",
            "  4004ce: c3 retq",
        ],
    ),
    FunctionReplacementTestCaseConfig(
        ARM32_PROGRAM_CONFIG,
        "patch_basic.c",
        "GNU_ARM_NONE_EABI_10_2_1",
        GNU_ARM_NONE_EABI_10_2_1_Toolchain,
        [
            "00008068 <main>:",
            "    8068: e3a00003  mov r0, #3",
            "    806c: e12fff1e  bx lr",
        ],
    ),
    FunctionReplacementTestCaseConfig(
        X86_64_PROGRAM_CONFIG,
        "patch_two_functions.c",
        "GNU_X86_64_LINUX_EABI_10_3_0",
        GNU_X86_64_LINUX_EABI_10_3_0_Toolchain,
        [
            "00000000004004c4 <main>:",
            "  4004c4: 55                    push   %rbp",
            "  4004c5: 48 89 e5              mov    %rsp,%rbp",
            "  4004c8: b8 00 00 00 00        mov    $0x0,%eax",
            "  4004cd: e8 02 00 00 00        callq  4004d4 <main+0x10>",
            "  4004d2: 5d                    pop    %rbp",
            "  4004d3: c3                    retq   ",
            "  4004d4: 55                    push   %rbp",
            "  4004d5: 48 89 e5              mov    %rsp,%rbp",
            "  4004d8: b8 04 00 00 00        mov    $0x4,%eax",
            "  4004dd: 5d                    pop    %rbp",
            "  4004de: c3                    retq   ",
        ],
        CompilerOptimizationLevel.NONE,
    ),
]


@pytest.mark.parametrize("config", TEST_CASE_CONFIGS)
async def test_function_replacement_modifier(ofrak_context: OFRAKContext, config, tmp_path):
    root_resource = await ofrak_context.create_root_resource_from_file(config.program.path)
    await root_resource.unpack_recursively()
    target_program = await root_resource.view_as(Program)

    function_cb = ComplexBlock(
        virtual_address=config.program.function_vaddr,
        size=config.program.function_size,
        name=config.program.function_name,
    )

    function_cb_parent_code_region = await target_program.get_code_region_for_vaddr(
        config.program.function_vaddr
    )

    function_cb.resource = await function_cb_parent_code_region.create_child_region(function_cb)

    # Create a dummy basic block in the complex block, so its `get_mode` method won't fail.
    dummy_bb = BasicBlock(0, 0, InstructionSetMode.NONE, False, None)
    await function_cb.resource.create_child_from_view(dummy_bb)

    await target_program.define_linkable_symbols(
        {config.program.function_name: (config.program.function_vaddr, LinkableSymbolType.FUNC)}
    )

    target_program.resource.add_attributes(config.program.attrs)

    await target_program.resource.save()

    function_replacement_config = FunctionReplacementModifierConfig(
        SourceBundle.slurp(PATCH_DIRECTORY),
        {config.program.function_name: config.replacement_patch},
        ToolchainConfig(
            file_format=BinFileType.ELF,
            force_inlines=True,
            relocatable=False,
            no_std_lib=True,
            no_jump_tables=True,
            no_bss_section=True,
            compiler_optimization_level=config.compiler_optimization_level,
            check_overlap=False,
        ),
        config.toolchain,
    )

    await target_program.resource.run(FunctionReplacementModifier, function_replacement_config)
    new_program_path = str(tmp_path / f"replaced_{Path(config.program.path).name}")

    # When running tests in parallel, do this one at a time
    lock = filelock.FileLock(new_program_path + ".lock")
    with lock:
        await target_program.resource.flush_data_to_disk(new_program_path)

        # Check that the modified program looks as expected.
        readobj_path = get_repository_config(config.toolchain_name, "BIN_PARSER")

        # LLVM-specific fix: use llvm-objdump, not llvm-readobj
        if "readobj" in readobj_path:
            readobj_path = readobj_path.replace("readobj", "objdump")

        subprocess_result = subprocess.run(
            [readobj_path, "-d", new_program_path], capture_output=True, text=True
        )
        readobj_output = subprocess_result.stdout

    expected_objdump_output_str = "\n".join(config.expected_objdump_output)

    assert normalize_assembly(expected_objdump_output_str) in normalize_assembly(readobj_output)


async def test_segment_injector_deletes_patched_descendants(ofrak_context: OFRAKContext):
    # unpack_recursively an ELF
    root_resource = await ofrak_context.create_root_resource_from_file(ARM32_PROGRAM_PATH)
    await root_resource.unpack_recursively()

    main_start = 0x8068
    main_end = main_start + 40

    function_cb = ComplexBlock(
        virtual_address=main_start,
        size=main_end - main_start,
        name="main",
    )

    target_program = await root_resource.view_as(Program)

    function_cb_parent_code_region = await target_program.get_code_region_for_vaddr(main_start)

    function_cb.resource = await function_cb_parent_code_region.create_child_region(function_cb)

    # Create a dummy basic block in the complex block, so its `get_mode` method won't fail.
    dummy_bb = BasicBlock(0x8068, 8, InstructionSetMode.NONE, False, None)
    await function_cb.create_child_region(dummy_bb)

    # get IDs of resources in a vaddr range
    expected_deleted_ids = set()
    for r in await root_resource.get_descendants(
        r_filter=ResourceFilter(
            attribute_filters=(
                ResourceAttributeRangeFilter(MemoryRegion.VirtualAddress, min=main_start),
                ResourceAttributeRangeFilter(MemoryRegion.EndVaddr, max=main_end + 1),
            )
        )
    ):
        expected_deleted_ids.add(r.get_id())
        for r in await r.get_descendants():
            expected_deleted_ids.add(r.get_id())

    assert len(expected_deleted_ids) > 0

    # create a SegmentInjectorModifierConfig
    cfg = SegmentInjectorModifierConfig(
        (
            (
                Segment(".text", main_start, 0, False, main_end - main_start, MemoryPermissions.RX),
                b"\x00" * (main_end - main_start),
            ),
        )
    )

    # run SegmentInjectorModifier
    results = await root_resource.run(SegmentInjectorModifier, cfg)

    # check that resources have been deleted
    assert results.resources_deleted == expected_deleted_ids
