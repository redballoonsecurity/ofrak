from ofrak.resource import Resource
from ofrak_ghidra.ghidra_model import GhidraProject


async def test_ghidra_project_analyzer(hello_world_elf_resource: Resource):
    """
    Test that the
    [GhidraProject][ofrak_ghidra.components.ghidra_analyzer.GhidraProject] object can
    be successfully generated
    """
    await hello_world_elf_resource.identify()
    ghidra_project = await hello_world_elf_resource.view_as(GhidraProject)
    assert isinstance(ghidra_project, GhidraProject)
