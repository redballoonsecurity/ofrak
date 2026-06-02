"""Tests for handling large (> 2^31) addresses in Ghidra scripts."""
import os

from ofrak import OFRAKContext
from ofrak.core import Program, ProgramAttributes, CodeRegion, ComplexBlock
from ofrak.core.decompilation import DecompilationAnalyzer, DecompilationAnalysis
from ofrak.service.resource_service_i import ResourceFilter
from ofrak_ghidra.ghidra_model import GhidraProject, GhidraCustomLoadProject
from ofrak_type import BitWidth, Endianness, InstructionSet, Range


# Java Integer.MAX_VALUE boundary — triggers NumberFormatException with parseInt
LARGE_ADDRESS = 0x8000_0000

ASSETS_DIR = os.path.join(os.path.dirname(__file__), "assets")

X86_64 = ProgramAttributes(
    InstructionSet.X86, None, BitWidth.BIT_64, Endianness.LITTLE_ENDIAN, None
)


async def test_create_memory_blocks_large_address(ofrak_context: OFRAKContext):
    """Test that CreateMemoryBlocks.java correctly handles addresses > 2^31."""
    test_binary_path = os.path.join(ASSETS_DIR, "program")
    with open(test_binary_path, "rb") as f:
        file_data = f.read()

    prog = await ofrak_context.create_root_resource("test_large_address", data=file_data)
    prog.add_tag(Program)
    prog.add_attributes(X86_64)
    await prog.save()

    await prog.create_child_from_view(
        CodeRegion(LARGE_ADDRESS, 0x1000), data_range=Range.from_size(0x0, 0x1000)
    )

    await prog.identify()
    assert prog.has_tag(GhidraCustomLoadProject)

    ghidra_project = await prog.view_as(GhidraProject)
    assert isinstance(ghidra_project, GhidraProject)


async def test_get_decompilation_large_address(ofrak_context: OFRAKContext):
    """Test that GetDecompilation.java correctly handles addresses > 2^31."""
    root = await ofrak_context.create_root_resource_from_file(
        os.path.join(ASSETS_DIR, "large_address_program")
    )
    await root.unpack_recursively(do_not_unpack=[ComplexBlock])

    complex_blocks = await root.get_descendants_as_view(
        ComplexBlock,
        r_filter=ResourceFilter(tags=[ComplexBlock]),
    )
    assert len(complex_blocks) > 0

    cb = next(cb for cb in complex_blocks if cb.virtual_address >= LARGE_ADDRESS)
    await cb.resource.run(DecompilationAnalyzer)
    decomp = await cb.resource.view_as(DecompilationAnalysis)
    # "foo" is a function defined in large_address_program.c
    assert "foo" in decomp.decompilation
