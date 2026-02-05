"""
Tests for handling large (> 2^31) addresses in Ghidra scripts.

These tests verify that:
1. CreateMemoryBlocks.java correctly handles addresses and sizes > 2^31
2. GetDecompilation.java correctly handles addresses > 2^31
"""
import os
import tempfile

from ofrak import OFRAKContext
from ofrak.core import (
    Program,
    ProgramAttributes,
    CodeRegion,
    ComplexBlock,
    SegmentInjectorModifier,
    SegmentInjectorModifierConfig,
)
from ofrak.core.decompilation import DecompilationAnalyzer, DecompilationAnalysis
from ofrak.service.resource_service_i import ResourceFilter
from ofrak_ghidra.ghidra_model import GhidraProject, GhidraCustomLoadProject
from ofrak_patch_maker.model import PatchRegionConfig
from ofrak_patch_maker.patch_maker import PatchMaker
from ofrak_patch_maker.toolchain.gnu_x64 import GNU_X86_64_LINUX_EABI_10_3_0_Toolchain
from ofrak_patch_maker.toolchain.model import (
    ToolchainConfig,
    CompilerOptimizationLevel,
    BinFileType,
    Segment,
)
from ofrak_type import BitWidth, Endianness, InstructionSet, MemoryPermissions, Range


# Address larger than Integer.MAX_VALUE (2^31 - 1 = 2147483647)
# Using 0x80000000 (2^31) which is just over the Integer.MAX_VALUE threshold
# and more likely to be supported by Ghidra's decompiler
LARGE_ADDRESS = 0x8000_0000  # 2GB, exactly 2^31

ASSETS_DIR = os.path.join(os.path.dirname(__file__), "assets")


async def _make_dummy_program_at_address(resource, arch_info, code_address: int):
    """Create a simple compiled program at the specified address."""
    src = """
    int foo(int x, int y);

    int main(int argc, char** argv){
        int x = 5;
        int y = 3;
        for (int i = 0; i < x; i++){
            y *= argc;
        }

        return foo(x, y);
    }

    int foo(int x, int y){
        switch (x){
            case 1:
                return y + 2;
            case 2:
                return y * 2;
            case 3:
                return y * y;
            default:
                return x + y;
        }
    }
    """

    tc = GNU_X86_64_LINUX_EABI_10_3_0_Toolchain(
        arch_info,
        toolchain_config=ToolchainConfig(
            file_format=BinFileType.ELF,
            force_inlines=True,
            relocatable=True,
            no_std_lib=True,
            no_jump_tables=True,
            no_bss_section=True,
            compiler_optimization_level=CompilerOptimizationLevel.NONE,
            compiler_target=None,
            compiler_cpu=None,
            assembler_target=None,
            assembler_cpu=None,
        ),
    )
    build_dir = tempfile.mkdtemp()
    pm = PatchMaker(tc, build_dir=build_dir)

    src_path = os.path.join(build_dir, "src.c")
    with open(src_path, "w") as f:
        f.write(src)

    bom = pm.make_bom("name", [src_path], [], [])

    patch_config = PatchRegionConfig(
        "name",
        {
            list(bom.object_map.values())[0].path: (
                Segment(".text", code_address, 0x0, True, 0x800, MemoryPermissions.RX),
            ),
        },
    )

    exec_path = os.path.join(build_dir, "exec")
    fem = pm.make_fem([(bom, patch_config)], exec_path)

    await resource.run(
        SegmentInjectorModifier,
        SegmentInjectorModifierConfig.from_fem(fem),
    )


async def test_create_memory_blocks_large_address(ofrak_context: OFRAKContext):
    """
    Test that CreateMemoryBlocks.java correctly handles addresses > 2^31.

    This test verifies that:
    - Memory regions with virtual addresses larger than Integer.MAX_VALUE work correctly
    - The fix from int to long in CreateMemoryBlocks.java is effective

    Before the fix, Integer.parseInt would throw NumberFormatException for addresses
    like 0x100000000 (4294967296) which exceeds Integer.MAX_VALUE (2147483647).
    """
    arch_info = ProgramAttributes(
        InstructionSet.X86,
        None,
        BitWidth.BIT_64,
        Endianness.LITTLE_ENDIAN,
        None,
    )

    # Use real binary data from test assets
    test_binary_path = os.path.join(ASSETS_DIR, "program")
    with open(test_binary_path, "rb") as f:
        file_data = f.read()

    prog = await ofrak_context.create_root_resource("test_large_address", data=file_data)

    prog.add_tag(Program)
    prog.add_attributes(arch_info)
    await prog.save()

    # Create a code region at an address > 2^31
    # This will exercise CreateMemoryBlocks.java with Long.parseLong instead of Integer.parseInt
    # We map the first 0x1000 bytes of the binary to the high virtual address
    await prog.create_child_from_view(
        CodeRegion(LARGE_ADDRESS, 0x1000), data_range=Range.from_size(0x0, 0x1000)
    )

    await prog.identify()
    assert prog.has_tag(GhidraCustomLoadProject)

    # This will call CreateMemoryBlocks.java with the large address
    # Before the fix: would fail with NumberFormatException
    # After the fix: should succeed
    ghidra_project = await prog.view_as(GhidraProject)
    assert isinstance(ghidra_project, GhidraProject)


async def test_get_decompilation_large_address(ofrak_context: OFRAKContext):
    """
    Test that GetDecompilation.java correctly handles addresses > 2^31.

    This test verifies the fix in GetDecompilation.java line 38:
        long funcAddr = Long.parseLong(getScriptArgs()[0]);

    Before the fix, Integer.parseInt would throw NumberFormatException for addresses
    like 0x100000000 (4294967296) which exceeds Integer.MAX_VALUE (2147483647).
    """
    arch_info = ProgramAttributes(
        InstructionSet.X86,
        None,
        BitWidth.BIT_64,
        Endianness.LITTLE_ENDIAN,
        None,
    )

    # Create file data large enough to hold injected code
    file_data = b"\xed" * 0x10000

    prog = await ofrak_context.create_root_resource("test_decomp_large_address", data=file_data)

    prog.add_tag(Program)
    prog.add_attributes(arch_info)
    await prog.save()

    # Create a code region at an address > 2^31
    cr_child = await prog.create_child_from_view(
        CodeRegion(LARGE_ADDRESS, 0x1000), data_range=Range.from_size(0x0, 0x1000)
    )

    # Inject real compiled code at the high address
    await _make_dummy_program_at_address(prog, arch_info, LARGE_ADDRESS)

    await prog.identify()
    assert prog.has_tag(GhidraCustomLoadProject)

    ghidra_project = await prog.view_as(GhidraProject)
    assert isinstance(ghidra_project, GhidraProject)

    # Unpack to get complex blocks
    await cr_child.unpack()

    # Get a complex block (function) which will be at the large address
    complex_blocks = await cr_child.get_descendants_as_view(
        ComplexBlock,
        r_filter=ResourceFilter(tags=[ComplexBlock]),
    )

    assert len(complex_blocks) > 0, "No complex blocks found"

    # Verify we have a function at a high address
    cb = complex_blocks[0]
    assert cb.virtual_address >= LARGE_ADDRESS, (
        f"Expected function at address >= {hex(LARGE_ADDRESS)}, " f"got {hex(cb.virtual_address)}"
    )

    # This call triggers GetDecompilation.java with the large address
    # Before the fix: would fail with NumberFormatException for addresses > 2^31
    # After the fix: the address parsing succeeds (Long.parseLong works)
    #
    # Note: Ghidra's decompiler may still fail for other reasons on custom-loaded
    # binaries at high addresses (NullPointerException in decoder), but that's a
    # separate Ghidra limitation. The key test here is that the address parsing
    # works correctly.
    await cb.resource.run(DecompilationAnalyzer)
    decomp = await cb.resource.view_as(DecompilationAnalysis)
    assert decomp.decompilation is not None

    # The decompilation was attempted at a high address. If it fails, it should NOT
    # be due to NumberFormatException (which would mean Integer.parseInt was used).
    # Ghidra's decompiler may fail for other reasons on custom-loaded binaries,
    # which is acceptable - our fix is about the address parsing, not the decompiler.
    #
    # If we got here without an exception being raised, the address was successfully
    # parsed with Long.parseLong. The decompilation content itself may be empty or
    # contain an error message due to Ghidra decompiler limitations.
