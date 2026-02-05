"""
Test the functionality of the BinaryNinjaAnalyzer component.
"""
from dataclasses import dataclass
from typing import Tuple

import pytest

from ofrak import OFRAKContext
from ofrak.core.filesystem import File
from ofrak_binary_ninja.components.binary_ninja_analyzer import BinaryNinjaAnalyzer
from ofrak_binary_ninja.model import BinaryNinjaAnalysis
from pytest_ofrak.patterns.program_metadata import (
    custom_binary_resource,  # noqa: F401
    setup_program_with_metadata,
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
    Test that Binary Ninja correctly handles ProgramMetadata (base_address and entry_points).

    This test verifies that when ProgramMetadata is provided:
    - base_address is used by Binary Ninja to rebase the binary view
    - entry_points are used to seed function discovery

    Requirements Mapping:
    - REQ2.2
    """
    base_address = 0x400000
    text_vaddr = base_address  # .text starts at offset 0
    text_section = await setup_program_with_metadata(
        custom_binary_resource, base_address=base_address, text_vaddr=text_vaddr
    )

    await custom_binary_resource.run(BinaryNinjaAnalyzer)
    await text_section.unpack()
    await assert_complex_block_at_vaddr(custom_binary_resource, text_vaddr)
