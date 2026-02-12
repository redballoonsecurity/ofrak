"""
Test the functionality of the BinaryNinjaAnalyzer component.
"""
from dataclasses import dataclass
from typing import Tuple

import pytest

from ofrak import OFRAKContext
from ofrak.core.filesystem import File
from ofrak_binary_ninja.components.binary_ninja_analyzer import (
    BinaryNinjaAnalyzer,
    BinaryNinjaCustomLoadAnalyzer,
)
from ofrak_binary_ninja.model import BinaryNinjaCustomLoadProject
from ofrak_binary_ninja.model import BinaryNinjaAnalysis
from ofrak_type.memory_permissions import MemoryPermissions
from pytest_ofrak.patterns.program_metadata import (
    custom_binary_resource,  # noqa: F401
    setup_program_with_metadata,
    add_rodata_region,
    assert_complex_block_at_vaddr,
)
from test_ofrak.unit.component.analyzer.analyzer_test_case import PopulatedAnalyzerTestCase


@dataclass
class PopulatedBinaryNinjaAnalyzerTestCase(PopulatedAnalyzerTestCase):
    resource_contents: bytes


@pytest.fixture()
async def test_case(
    hello_world_elf, ofrak_context: OFRAKContext, test_id: str
) -> PopulatedBinaryNinjaAnalyzerTestCase:
    resource = await ofrak_context.create_root_resource(test_id, hello_world_elf, tags=(File,))
    return PopulatedBinaryNinjaAnalyzerTestCase(
        BinaryNinjaAnalyzer,
        Tuple[BinaryNinjaAnalysis],
        ofrak_context,
        resource,
        hello_world_elf,
    )


async def test_binary_ninja_analyzer(test_case: PopulatedBinaryNinjaAnalyzerTestCase):
    """
    Test that the [BinaryNinjaAnalysis][ofrak_binary_ninja.model.BinaryNinjaAnalysis]
    object can be successfully generated

    This test verifies that:
    - The resource can be identified
    - The BinaryNinjaAnalyzer can analyze the resource and produce a BinaryNinjaAnalysis object
    - The resulting analysis is of the correct type
    """
    await test_case.resource.identify()
    analysis = await test_case.resource.analyze(BinaryNinjaAnalysis)
    assert isinstance(analysis, BinaryNinjaAnalysis)


async def test_binary_ninja_with_program_metadata(custom_binary_resource):
    """
    Test that Binary Ninja correctly handles ProgramAttributes (base_address and entry_points)
    when loading an entire binary as a flat blob.

    This test verifies that when ProgramAttributes is provided:
    - base_address is used by Binary Ninja to rebase the binary view
    - entry_points are used to seed function discovery

    Binary Ninja loads the entire binary as a flat blob. Since .text is at offset 0
    in the binary, text_vaddr must equal base_address (the rebase sets where the
    binary starts in virtual memory).

    Requirements Mapping:
    - REQ2.2
    """
    base_address = 0x400000
    # For flat binary loading, .text at offset 0 maps to base_address
    text_vaddr = base_address
    text_section = await setup_program_with_metadata(
        custom_binary_resource, base_address=base_address, text_vaddr=text_vaddr
    )
    assert custom_binary_resource.has_tag(BinaryNinjaCustomLoadProject)

    await custom_binary_resource.run(BinaryNinjaCustomLoadAnalyzer)

    # Verify base_address was applied to the Binary Ninja view
    binja_analysis = custom_binary_resource.get_attributes(BinaryNinjaAnalysis)
    assert binja_analysis.binaryview.start == base_address

    await text_section.unpack()
    await assert_complex_block_at_vaddr(custom_binary_resource, text_vaddr)


async def test_binary_ninja_custom_loader_with_memory_regions(custom_binary_resource):
    """
    Test that BinaryNinjaCustomLoadAnalyzer correctly consumes MemoryRegion children to create
    user segments at their specified virtual addresses with per-region permissions.

    This test verifies that when MemoryRegion children exist:
    - Each region's data is loaded at its specified virtual address
    - Permissions are correctly applied (MemoryRegionPermissions → SegmentFlags)
    - Entry points from ProgramAttributes seed function discovery
    - Function discovery works correctly at the expected virtual addresses

    Requirements Mapping:
    - REQ2.2
    """
    text_vaddr = 0x400130
    text_section = await setup_program_with_metadata(
        custom_binary_resource, base_address=0x100000, text_vaddr=text_vaddr
    )
    await add_rodata_region(
        custom_binary_resource, rodata_vaddr=0x40A0A0, permissions=MemoryPermissions.R
    )
    assert custom_binary_resource.has_tag(BinaryNinjaCustomLoadProject)

    await custom_binary_resource.run(BinaryNinjaCustomLoadAnalyzer)

    await text_section.unpack()
    await assert_complex_block_at_vaddr(custom_binary_resource, text_vaddr)
