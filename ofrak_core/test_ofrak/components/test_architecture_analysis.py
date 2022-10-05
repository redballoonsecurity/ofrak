import os

import pytest

from ofrak import Resource, ResourceFilter, OFRAKContext
from ofrak.core.memory_region import MemoryRegion
from ofrak.core.architecture import ProgramAttributes


@pytest.fixture
async def resource(ofrak_context: OFRAKContext):
    assets_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "assets"))
    filepath = os.path.join(assets_dir, "arm_reloc_relocated.elf")
    resource = await ofrak_context.create_root_resource_from_file(filepath)
    return resource


async def test_architecture_analysis(resource: Resource):
    """
    Test that the `MemoryRegionProgramAttributesAnalyzer` correctly extracts the program's
    program attributes.
    """
    await resource.unpack()
    program_attributes = await resource.analyze(ProgramAttributes)
    first_memory_region_resource = next(
        await resource.get_children(ResourceFilter.with_tags(MemoryRegion))
    )
    program_attributes_from_memory_region = await first_memory_region_resource.analyze(
        ProgramAttributes
    )
    assert program_attributes == program_attributes_from_memory_region
