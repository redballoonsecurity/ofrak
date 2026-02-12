"""
Shared helpers for testing ProgramAttributes entry_points/base_address with disassembler backends.

Requirements Mapping:
- REQ2.2
"""
import os
from typing import Optional

import pytest

from ofrak import OFRAKContext, ResourceFilter, ResourceAttributeValueFilter
from ofrak.core import (
    Program,
    CodeRegion,
    ComplexBlock,
    BasicBlock,
    Addressable,
    ProgramAttributes,
)
from ofrak.core.memory_region import MemoryRegion, MemoryRegionPermissions
from ofrak.resource import Resource
from ofrak_type import InstructionSet, BitWidth, Endianness, SubInstructionSet, Range
from ofrak_type.memory_permissions import MemoryPermissions

from pytest_ofrak import ASSETS_DIR

TINI_CUSTOM_BINARY = os.path.join(ASSETS_DIR, "tini_custom_binary")

# Constants for the tini_custom_binary test asset.
# This is a custom binary created from an aarch64 statically compiled binary:
# https://github.com/ryanwoodsmall/static-binaries/blob/master/aarch64/tini
# It was created like so:
# - `aarch64-linux-gnu-objcopy -O binary --only-section=.text tini tini.text.bin`
# - `aarch64-linux-gnu-objcopy -O binary --only-section=.rodata tini tini.rodata.bin`
# - `dd if=/dev/zero of=gap.bin bs=1 count=$((0x1234))`
# - `cat tini.text.bin gap.bin tini.rodata.bin > tini_custom_binary`
# So it contains: .text section binary content, a zero gap of 0x1234 bytes, then .rodata content.
TINI_TEXT_SIZE = 40792
TINI_TEXT_OFFSET = 0
TINI_GAP_SIZE = 0x1234
TINI_RODATA_OFFSET = TINI_TEXT_OFFSET + TINI_TEXT_SIZE + TINI_GAP_SIZE
TINI_RODATA_SIZE = 7052


@pytest.fixture
async def custom_binary_resource(ofrak_context: OFRAKContext):
    """Load the tini_custom_binary test asset as a root resource."""
    return await ofrak_context.create_root_resource_from_file(TINI_CUSTOM_BINARY)


async def setup_program_with_metadata(
    resource: Resource,
    *,
    base_address: int,
    text_vaddr: int,
    text_size: int = TINI_TEXT_SIZE,
) -> Resource:
    """
    Set up a resource as a Program with ProgramAttributes (including entry_points
    and base_address) and a CodeRegion child.

    Tags the resource as a Program, adds ProgramAttributes for AARCH64 with the given
    base_address and entry point at text_vaddr, and creates a CodeRegion child.

    :param resource: the root resource (should be the tini_custom_binary asset)
    :param base_address: the base address for ProgramAttributes
    :param text_vaddr: the virtual address for the .text CodeRegion and first entry point
    :param text_size: the size of the .text CodeRegion

    :return: the created CodeRegion child resource
    """
    resource.add_tag(Program)
    await resource.save()
    await resource.identify()

    resource.add_attributes(
        ProgramAttributes(
            isa=InstructionSet.AARCH64,
            sub_isa=SubInstructionSet.ARMv8A,
            bit_width=BitWidth.BIT_64,
            endianness=Endianness.LITTLE_ENDIAN,
            processor=None,
            entry_points=(text_vaddr,),
            base_address=base_address,
        )
    )
    await resource.save()

    text_section = await resource.create_child(
        tags=(CodeRegion,),
        data_range=Range.from_size(TINI_TEXT_OFFSET, text_size),
    )
    text_section.add_view(
        CodeRegion(
            virtual_address=text_vaddr,
            size=text_size,
        )
    )
    await text_section.save()
    return text_section


async def add_rodata_region(
    resource: Resource,
    rodata_vaddr: int,
    rodata_size: int = TINI_RODATA_SIZE,
    permissions: Optional[MemoryPermissions] = None,
) -> Resource:
    """
    Add a non-executable MemoryRegion child for .rodata.

    :param resource: the root resource
    :param rodata_vaddr: the virtual address for the .rodata region
    :param rodata_size: the size of the .rodata region
    :param permissions: optional memory permissions to attach to the region

    :return: the created MemoryRegion child resource
    """
    rodata_section = await resource.create_child(
        tags=(MemoryRegion,),
        data_range=Range.from_size(TINI_RODATA_OFFSET, rodata_size),
    )
    rodata_section.add_view(
        MemoryRegion(
            virtual_address=rodata_vaddr,
            size=rodata_size,
        )
    )
    if permissions is not None:
        rodata_section.add_attributes(MemoryRegionPermissions(permissions))
    await rodata_section.save()
    return rodata_section


async def assert_complex_block_at_vaddr(resource: Resource, vaddr: int) -> ComplexBlock:
    """
    Assert that a ComplexBlock exists at the given virtual address and contains
    actual analysis results (non-zero size and at least one BasicBlock child).

    :param resource: the root resource to search descendants of
    :param vaddr: the expected virtual address of the ComplexBlock

    :return: the found ComplexBlock
    """
    cb = await resource.get_only_descendant_as_view(
        v_type=ComplexBlock,
        r_filter=ResourceFilter(
            tags=[ComplexBlock],
            attribute_filters=(ResourceAttributeValueFilter(Addressable.VirtualAddress, vaddr),),
        ),
    )
    assert cb.virtual_address == vaddr
    assert cb.size > 0, f"ComplexBlock at 0x{vaddr:x} has zero size"

    # Verify the disassembler actually produced basic blocks, not just a stub entry
    await cb.resource.unpack()
    basic_blocks = list(
        await cb.resource.get_children_as_view(
            BasicBlock, r_filter=ResourceFilter(tags=[BasicBlock])
        )
    )
    assert (
        len(basic_blocks) > 0
    ), f"ComplexBlock at 0x{vaddr:x} has no BasicBlock children after unpacking"
    return cb
