"""
Test the functionality of the BinaryNinjaAnalyzer component.
"""
import os
from dataclasses import dataclass
from typing import Tuple

import pytest

from ofrak import OFRAKContext, ResourceFilter, ResourceAttributeValueFilter
from ofrak.core.filesystem import File
from ofrak.core import (
    Program,
    CodeRegion,
    ComplexBlock,
    Addressable,
    ProgramAttributes,
)
from ofrak.core.program_metadata import ProgramMetadata
from ofrak_binary_ninja.components.binary_ninja_analyzer import BinaryNinjaAnalyzer
from ofrak_binary_ninja.model import BinaryNinjaAnalysis
from ofrak_type import InstructionSet, BitWidth, Endianness, SubInstructionSet, Range
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


@pytest.fixture
async def custom_binary_resource(ofrak_context: OFRAKContext):
    # This is a custom binary created from this aarch64 statically compiled binary:
    # https://github.com/ryanwoodsmall/static-binaries/blob/master/aarch64/tini
    # See test_pyghidra_components.py for details on how it was created.
    return await ofrak_context.create_root_resource_from_file(
        os.path.join(
            os.path.dirname(__file__),
            "../../ofrak_pyghidra/tests/assets/tini_custom_binary",
        )
    )


async def test_binary_ninja_with_program_metadata(custom_binary_resource):
    """
    Test that Binary Ninja correctly handles ProgramMetadata (base_address and entry_points).

    This test verifies that when ProgramMetadata is provided:
    - base_address is used by Binary Ninja to rebase the binary view
    - entry_points are used to seed function discovery

    Requirements Mapping:
    - REQ2.2
    """
    custom_binary_resource.add_tag(Program)
    await custom_binary_resource.save()
    await custom_binary_resource.identify()

    program_attributes = ProgramAttributes(
        isa=InstructionSet.AARCH64,
        sub_isa=SubInstructionSet.ARMv8A,
        bit_width=BitWidth.BIT_64,
        endianness=Endianness.LITTLE_ENDIAN,
        processor=None,
    )
    custom_binary_resource.add_attributes(program_attributes)

    # Binary Ninja will rebase to base_address, then add entry_points.
    # The entry point should be the absolute address where function discovery starts.
    # Since the .text section starts at offset 0 in this custom binary,
    # the entry point is at base_address + 0 = base_address.
    base_address = 0x400000
    text_vaddr = base_address  # .text starts at offset 0
    text_size = 40792

    program_metadata = ProgramMetadata(
        entry_points=(text_vaddr,),
        base_address=base_address,
    )
    custom_binary_resource.add_attributes(program_metadata)
    await custom_binary_resource.save()

    # Manually create CodeRegion for .text
    text_offset = 0
    text_section = await custom_binary_resource.create_child(
        tags=(CodeRegion,),
        data_range=Range.from_size(text_offset, text_size),
    )
    text_section.add_view(
        CodeRegion(
            virtual_address=text_vaddr,
            size=text_size,
        )
    )
    await text_section.save()

    # Run Binary Ninja analysis
    # The ProgramMetadata entry_points and base_address will be used by BinaryNinjaAnalyzer
    await custom_binary_resource.run(BinaryNinjaAnalyzer)

    # Unpack the code region to get complex blocks
    await text_section.unpack()

    # Verify that a function is found at the entry point address we specified
    # This confirms that ProgramMetadata's entry_points is being used by Binary Ninja
    cb = await custom_binary_resource.get_only_descendant_as_view(
        v_type=ComplexBlock,
        r_filter=ResourceFilter(
            tags=[ComplexBlock],
            attribute_filters=(
                ResourceAttributeValueFilter(Addressable.VirtualAddress, text_vaddr),
            ),
        ),
    )
    assert cb is not None
    assert cb.virtual_address == text_vaddr
