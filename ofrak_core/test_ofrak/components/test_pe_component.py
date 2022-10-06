import os
from typing import List

import pytest

from ofrak import OFRAKContext, Resource
from ofrak.core.pe.model import Pe, PeSection, PeSectionFlag, PeSectionHeader, PeOptionalHeader


@pytest.fixture(params=["jumpnbump.exe", "kernel32.dll"])
async def pe_root_resource(ofrak_context: OFRAKContext, request):
    return await _get_test_resource_from_file_name(ofrak_context, request.param)


async def test_pe_unpacker(pe_root_resource: Resource):
    await pe_root_resource.unpack_recursively()

    pe_view = await pe_root_resource.view_as(Pe)
    optional_header = await pe_view.get_optional_header()
    assert isinstance(optional_header, PeOptionalHeader)

    # Get the sections, tet get_header / get_flags()
    sections: List[PeSection] = list(await pe_view.get_sections())
    assert len(sections) > 0
    for section in sections:
        section_header = await section.get_header()
        assert isinstance(section_header, PeSectionHeader)
        for section_flag in section_header.get_flags():
            assert isinstance(section_flag, PeSectionFlag)

    # Get the code region; test get_header() / get_body()
    code_regions = list(await pe_view.get_sections())
    assert code_regions is not []
    code_region = await pe_view.get_section_by_name(".text")
    code_region_header = await code_region.get_header()
    assert code_region_header.name == ".text"
    assert await code_region_header.get_body() == code_region


@pytest.fixture
async def kernel32_dll(ofrak_context: OFRAKContext) -> Resource:
    return await _get_test_resource_from_file_name(ofrak_context, "kernel32.dll")


async def test_pe_get_memory_region_for_vaddr(kernel32_dll: Resource):
    """
    Test that Program.get_memory_region_for_vaddr works for Pe as intended.
    """
    await kernel32_dll.unpack()
    pe_view = await kernel32_dll.view_as(Pe)
    for section in await pe_view.get_sections():
        section_header = await section.get_header()
        virtual_address = section_header.m_virtual_address
        memory_region = await pe_view.get_memory_region_for_vaddr(virtual_address + 4)
        assert memory_region.virtual_address == virtual_address


async def _get_test_resource_from_file_name(
    ofrak_context: OFRAKContext, test_file_name: str
) -> Resource:
    assets_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "./assets"))
    file_path = os.path.join(assets_dir, test_file_name)
    root_resource = await ofrak_context.create_root_resource_from_file(file_path)
    return root_resource
