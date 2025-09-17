import pytest

from ofrak import Resource
from ofrak_ghidra.ghidra_model import GhidraProject
from .example_ghidra_package import example_ghidra_package


@pytest.fixture(autouse=True)
def ghidra_extension_components(ofrak_injector):
    ofrak_injector.discover(example_ghidra_package)


async def test_loading_new_ofrak_ghidra_package(hello_world_elf_resource: Resource):
    """
    Test that the
    [GhidraProject][ofrak_ghidra.components.ghidra_analyzer.GhidraProject] object can
    be successfully generated
    """
    await hello_world_elf_resource.identify()
    ghidra_project = await hello_world_elf_resource.view_as(GhidraProject)
    assert isinstance(ghidra_project, GhidraProject)

    await hello_world_elf_resource.run(example_ghidra_package.GhidraExampleComponent, None)
