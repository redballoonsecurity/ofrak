from ofrak import OFRAKContext
from ofrak.core import (
    Program,
    ProgramAttributes,
    NamedProgramSection,
    MemoryRegion,
    CodeRegion,
    Elf,
)
from ofrak.resource import Resource
from ofrak_ghidra.ghidra_model import GhidraProject, GhidraCustomLoadProject
from ofrak_type import BitWidth, Endianness, InstructionSet


async def test_ghidra_project_analyzer(hello_world_elf_resource: Resource):
    """
    Test that the
    [GhidraProject][ofrak_ghidra.components.ghidra_analyzer.GhidraProject] object can
    be successfully generated
    """
    hello_world_elf_resource.add_tag(Elf)
    await hello_world_elf_resource.save()
    await hello_world_elf_resource.identify()
    ghidra_project = await hello_world_elf_resource.view_as(GhidraProject)
    assert isinstance(ghidra_project, GhidraProject)


async def test_ghidra_custom_loader(ofrak_context: OFRAKContext):
    file_data = b"\xed" * 0x10000

    prog = await ofrak_context.create_root_resource("test_custom_load", data=file_data)

    prog.add_tag(Program)
    prog.add_attributes(
        ProgramAttributes(
            InstructionSet.PPC,
            None,
            BitWidth.BIT_32,
            Endianness.LITTLE_ENDIAN,
            None,
        )
    )
    await prog.save()

    await prog.create_child_from_view(NamedProgramSection(0x0, 0x1000, "FIRST_SECTION"))
    await prog.create_child_from_view(MemoryRegion(0x1000, 0x2000))
    await prog.create_child_from_view(CodeRegion(0x2000, 0x3000))

    await prog.identify()

    assert prog.has_tag(GhidraCustomLoadProject)

    ghidra_project = await prog.view_as(GhidraProject)
    assert isinstance(ghidra_project, GhidraProject)
