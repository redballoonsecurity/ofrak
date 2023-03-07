import tempfile

from ofrak_patch_maker.toolchain.llvm_12 import LLVM_12_0_1_Toolchain
from ofrak.core.architecture import ProgramAttributes
from ofrak_type.architecture import (
    InstructionSet,
)
from ofrak_patch_maker.patch_maker import PatchMaker
from ofrak_patch_maker.toolchain.model import (
    CompilerOptimizationLevel,
    BinFileType,
    ToolchainConfig,
)
from ofrak_type.bit_width import BitWidth
from ofrak_type.endianness import Endianness


def test_patch_symbol_resolution(
    large_elf_source_file,
    patch_file,
):
    # Set up PatchMaker
    proc = ProgramAttributes(
        isa=InstructionSet.X86,
        sub_isa=None,
        bit_width=BitWidth.BIT_64,
        endianness=Endianness.LITTLE_ENDIAN,
        processor=None,
    )

    tc_config = ToolchainConfig(
        file_format=BinFileType.ELF,
        force_inlines=True,
        relocatable=False,
        no_std_lib=True,
        no_jump_tables=True,
        no_bss_section=True,
        create_map_files=True,
        compiler_optimization_level=CompilerOptimizationLevel.SPACE,
        debug_info=False,
        check_overlap=False,
    )

    toolchain = LLVM_12_0_1_Toolchain(proc, tc_config)

    patch_maker = PatchMaker(
        toolchain=toolchain,
        build_dir=tempfile.mkdtemp(),
    )

    # Create BOM from multiple source files
    source_list = [patch_file, large_elf_source_file]
    bom = patch_maker.make_bom(
        name="hello_world_patch",
        source_list=source_list,
        object_list=[],
        header_dirs=[],
    )

    # Assert that symbols defined within different source files have been resolved properly
    assert len(bom.unresolved_symbols) == 0
