from ofrak.core.free_space import RuntimeFreeSpace
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
        "mock_program",
        b"\xff" * 0x100,
        (Program,),
    )
    memory_region = await resource.create_child_from_view(
        MemoryRegion(0x100, 0xF0), data_range=Range(0x10, 0x100)
    )
    await resource.save()
    await memory_region.save()
    return memory_region


@pytest.fixture
async def dataless_resource_under_test(ofrak_context: OFRAKContext) -> Resource:
    resource = await ofrak_context.create_root_resource(
        "mock_empty",
        b"",
        (Program,),
    )
    memory_region = await resource.create_child_from_view(
        MemoryRegion(0x100, 0xF0), data_range=None
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
    partial_start_address = 0x104
    partial_end_address = 0x10A
    range_to_remove = Range(partial_start_address, partial_end_address)
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
    memory_region_view = await resource_under_test.view_as(MemoryRegion)
    start_offset_in_region = memory_region_view.get_offset_in_self(partial_start_address)
    memory_region_stub_data = await resource_under_test.get_data(
        Range.from_size(start_offset_in_region, len(config.stub))
    )
    assert memory_region_stub_data == config.stub


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


async def test_dataless_free_space_modifier(dataless_resource_under_test: Resource):
    original_region = await dataless_resource_under_test.view_as(MemoryRegion)
    parent = await dataless_resource_under_test.get_parent()

    rw_config = FreeSpaceModifierConfig(MemoryPermissions.RW)
    await dataless_resource_under_test.run(FreeSpaceModifier, rw_config)

    # Assert runtime free space created as required
    runtime_free_region = await parent.get_only_child_as_view(
        MemoryRegion, r_filter=ResourceFilter.with_tags(RuntimeFreeSpace)
    )
    assert original_region == runtime_free_region


async def test_dataless_free_space_modifier_readonly_fails(dataless_resource_under_test: Resource):
    ro_config = FreeSpaceModifierConfig(MemoryPermissions.R)
    with pytest.raises(ValueError, match=r".*RW.*"):
        await dataless_resource_under_test.run(FreeSpaceModifier, ro_config)


async def test_dataless_free_space_modifier_stub_fails(dataless_resource_under_test: Resource):
    stub_config = FreeSpaceModifierConfig(MemoryPermissions.RW, stub=b"\x00")
    with pytest.raises(ValueError, match=r".*stub.*"):
        await dataless_resource_under_test.run(FreeSpaceModifier, stub_config)


def test_free_space_modifier_config_fill_parameters():
    """
    Test that the length of fill passed to `FreeSpaceModifierConfig` is greater than 0.
    """
    with pytest.raises(ValueError):
        FreeSpaceModifierConfig(MemoryPermissions.RX, stub=b"", fill=b"")


def test_partial_space_modifier_config_fill_parameters():
    """
    Test that the length of fill passed to `PartialFreeSpaceModifierConfig` is greater than 0.
    """
    with pytest.raises(ValueError):
        PartialFreeSpaceModifierConfig(
            MemoryPermissions.RX, range_to_remove=Range(0, 10), stub=b"", fill=b""
        )
