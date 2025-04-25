import os

import pytest

import test_ofrak.components
from ofrak import OFRAKContext, Resource
from ofrak.core import (
    ElfProgramHeader,
    Elf,
    ElfSymbolSection,
    ElfSymbolBinding,
    ElfSymbolType,
    ElfSymbolVisibility,
    ElfSegment,
)
from ofrak_type.memory_permissions import MemoryPermissions
from ofrak_type.range import Range


@pytest.mark.parametrize(
    "memory_permissions",
    [
        MemoryPermissions.R,
        MemoryPermissions.W,
        MemoryPermissions.X,
        MemoryPermissions.RW,
        MemoryPermissions.RX,
        MemoryPermissions.RWX,
    ],
)
def test_get_memory_permissions(memory_permissions: MemoryPermissions):
    """
    Test that ElfProgramHeader.get_memory_permissions returns the correct value.
    """
    elf_program_header = ElfProgramHeader(0, 0, 0, 0, 0, 0, 0, memory_permissions.value, 0)
    assert elf_program_header.get_memory_permissions() == memory_permissions


@pytest.fixture
async def elf_o_resource(elf_object_file: str, ofrak_context: OFRAKContext) -> Resource:
    return await ofrak_context.create_root_resource_from_file(elf_object_file)


async def test_elf_section_headers(elf_o_resource: Resource):
    """
    Test that ElfSectionHeaders returned from Elf.get_section_headers match the corresponding
    section header returned by Elf.get_section_header_by_index.
    """
    await elf_o_resource.unpack()
    elf = await elf_o_resource.view_as(Elf)
    for section_header in await elf.get_section_headers():
        file_range = section_header.get_file_range()
        assert isinstance(file_range, Range)
        section_header_by_index = await elf.get_section_header_by_index(
            section_header.section_index
        )
        assert section_header == section_header_by_index


async def test_elf_symbols(elf_o_resource: Resource):
    """
    Test Elf.get_symbol_section, ElfSymbol APIs.
    """
    await elf_o_resource.unpack()
    elf = await elf_o_resource.view_as(Elf)

    symbol_section = await elf.get_symbol_section()
    assert isinstance(symbol_section, ElfSymbolSection)
    for symbol in await symbol_section.get_symbols():
        assert isinstance(symbol.get_binding(), ElfSymbolBinding)
        assert isinstance(symbol.get_type(), ElfSymbolType)
        assert isinstance(symbol.get_visibility(), ElfSymbolVisibility)
        symbol_section_index = symbol.get_section_index()
        if symbol_section_index is not None:
            assert isinstance(symbol_section_index, int)


async def test_elf_sections(elf_o_resource: Resource):
    """
    Test that ElfSections returned from Elf.get_sections match corresponding sections returned by
    Elf.{get_sections, get_section_by_index, get_section_by_name}.
    """
    await elf_o_resource.unpack()
    elf = await elf_o_resource.view_as(Elf)

    for elf_section in await elf.get_sections():
        section_by_index = await elf.get_section_by_index(elf_section.section_index)
        section_by_name = await elf.get_section_by_name(elf_section.name)
        assert elf_section == section_by_index == section_by_name

        # Test that the section caption builds a string
        caption = elf_section.resource.get_caption()
        assert isinstance(caption, str)


@pytest.fixture
async def elf_resource(elf_executable_file: str, ofrak_context: OFRAKContext) -> Resource:
    return await ofrak_context.create_root_resource_from_file(elf_executable_file)


async def test_elf_program_headers(elf_resource: Resource):
    """
    Test that ElfProgramHeaders returned by Elf.get_program_header matches corresponding program
    header returned by Elf.get_program_header_by_index.
    """
    await elf_resource.unpack()
    elf = await elf_resource.view_as(Elf)
    for program_header in await elf.get_program_headers():
        assert isinstance(program_header.get_memory_permissions(), MemoryPermissions)
        program_header_by_index = await elf.get_program_header_by_index(
            program_header.segment_index
        )
        assert program_header == program_header_by_index


@pytest.fixture
async def elf_no_sections(ofrak_context: OFRAKContext) -> Resource:
    """
    An ELF with no sections to test ElfSegment functionality.
    """
    file_path = os.path.join(test_ofrak.components.ASSETS_DIR, "hello_nosections.out")
    return await ofrak_context.create_root_resource_from_file(file_path)


async def test_elf_segments(elf_no_sections: Resource):
    """
    Test that Elf.get_segments returns ElfSegments.
    """
    await elf_no_sections.unpack()
    elf = await elf_no_sections.view_as(Elf)
    for segment in await elf.get_segments():
        assert isinstance(segment, ElfSegment)


@pytest.fixture
async def elf_permstest(
    elf_permstest_executable_file: str, ofrak_context: OFRAKContext
) -> Resource:
    """
    An ELF with all combinations of permission flags
    """
    return await ofrak_context.create_root_resource_from_file(elf_permstest_executable_file)


async def test_elf_perms_header_analysis(elf_permstest: Resource):
    """
    Test getting memory permissions for all flag combinations
    """
    await elf_permstest.unpack()
    elf = await elf_permstest.view_as(Elf)
    for prog_header in await elf.get_program_headers():
        prog_header.get_memory_permissions()
