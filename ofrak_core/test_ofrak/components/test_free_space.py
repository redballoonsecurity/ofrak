import pytest
from ofrak.core import FreeSpace, FreeSpaceModifier, FreeSpaceModifierConfig

from ofrak.component.modifier import ModifierError

from ofrak import OFRAKContext, Resource, ResourceFilter, ResourceAttributeValueFilter
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
        (Program,),
    )
    memory_region = await resource.create_child_from_view(
        MemoryRegion(0, 0x100), data_range=Range(0, 0x100)
    )
    await resource.save()
    await memory_region.save()
    return memory_region


async def test_partial_free_modifier_out_of_bounds(resource_under_test: Resource):
    """
    Test that trying to run PartialFreeSpaceModifier past a memory regions bounds results in a
    ValueError.
    """
    data_length = await resource_under_test.get_data_length()
    config = PartialFreeSpaceModifierConfig(
        MemoryPermissions.RX,
        range_to_remove=Range.from_size(0, data_length + 4),
        stub=b"\xfe\xed\xfa\xce",
        fill=b"\x00",
    )
    with pytest.raises(ModifierError):
        await resource_under_test.run(PartialFreeSpaceModifier, config)


async def test_partial_free_modifier(resource_under_test: Resource):
    """
    Test that the PartialFreeSpaceModifier returns expected results.
    """
    partial_start_offset = 4
    partial_end_offset = 10
    parent = await resource_under_test.get_parent()
    data_length = await resource_under_test.get_data_length()
    range_to_remove = Range.from_size(4, data_length - 4 - 10)
    config = PartialFreeSpaceModifierConfig(
        MemoryPermissions.RX,
        range_to_remove=range_to_remove,
        stub=b"\xfe\xed\xfa\xce",
        fill=b"\x00",
    )
    await resource_under_test.run(PartialFreeSpaceModifier, config)

    # Assert free space is as required
    free_space = await resource_under_test.get_only_child_as_view(FreeSpace)
    free_space_data = await free_space.resource.get_data()
    assert free_space_data == (b"\x00" * (range_to_remove.length() - len(config.stub)))

    # Assert stub is injected
    memory_region_data = await resource_under_test.get_data()
    assert (
        memory_region_data[partial_start_offset : partial_start_offset + len(config.stub)]
        == config.stub
    )


async def test_free_space_modifier(resource_under_test: Resource):
    """
    Test that the FreeSpaceModifier returns expected results
    """
    data_length = await resource_under_test.get_data_length()
    config = FreeSpaceModifierConfig(
        MemoryPermissions.RX,
        stub=b"\xfe\xed\xfa\xce",
        fill=b"\x00",
    )
    parent = await resource_under_test.get_parent()
    await resource_under_test.run(FreeSpaceModifier, config)

    # Assert free space created as required
    free_space = await parent.get_only_child_as_view(
        FreeSpace, r_filter=ResourceFilter.with_tags(FreeSpace)
    )
    free_space_data = await free_space.resource.get_data()
    # Free space should not include the stub
    assert free_space_data == (config.fill * (data_length - len(config.stub)))

    # If stub exists, assert that it matches
    child = await parent.get_only_child(
        r_filter=ResourceFilter(
            tags=(MemoryRegion,),
            attribute_filters=(ResourceAttributeValueFilter(MemoryRegion.Size, len(config.stub)),),
        )
    )
    child_data = await child.get_data()
    assert child_data == config.stub
