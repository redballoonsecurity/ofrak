import pytest
from ofrak.core import FreeSpace

from ofrak.component.modifier import ModifierError

from ofrak import OFRAKContext, Resource, ResourceFilter
from ofrak.core import (
    MemoryRegion,
    Program,
    PartialFreeSpaceModifierConfig,
    PartialFreeSpaceModifier,
)
from ofrak_type.memory_permissions import MemoryPermissions
from ofrak_type.range import Range


@pytest.fixture
async def resource_under_test(ofrak_context: OFRAKContext) -> Resource:
    resource = await ofrak_context.create_root_resource(
        "mock_memory_region",
        b"\xff" * 0x100,
        (Program, MemoryRegion),
    )
    resource.add_view(MemoryRegion(0x0, 0x100))
    await resource.save()
    return resource


async def test_partial_free_modifier_out_of_bounds(resource_under_test: Resource):
    """
    Test that trying to run PartialFreeSpaceModifier past a memory regions bounds results in a
    ValueError.
    """
    data_length = await resource_under_test.get_data_length()
    config = PartialFreeSpaceModifierConfig(
        MemoryPermissions.RX,
        range_to_remove=Range.from_size(0, data_length + 4),
        fill=b"\xfe\xed\xfa\xce",
    )
    with pytest.raises(ModifierError):
        await resource_under_test.run(PartialFreeSpaceModifier, config)


async def test_partial_free_modifier(resource_under_test: Resource):
    """
    Test that the PartialFreeSpaceModifier returns expected results.
    """
    data_length = await resource_under_test.get_data_length()
    config = PartialFreeSpaceModifierConfig(
        MemoryPermissions.RX,
        range_to_remove=Range.from_size(0, data_length - 10),
        fill=b"\xfe\xed\xfa\xce",
    )
    await resource_under_test.run(PartialFreeSpaceModifier, config)
    free_space = await resource_under_test.get_only_child_as_view(
        FreeSpace, ResourceFilter.with_tags(FreeSpace)
    )
    free_space_data = await free_space.resource.get_data()
    assert free_space_data == config.fill + (b"\x00" * (data_length - 10 - len(config.fill)))
