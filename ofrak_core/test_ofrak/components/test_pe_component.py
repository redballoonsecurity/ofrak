import os
import pytest

from ofrak.core.pe.model import Pe

PE_TESTFILE_PATHS = [
    "./jumpnbump.exe",
    "./kernel32.dll",
]


@pytest.mark.parametrize("test_case", PE_TESTFILE_PATHS)
async def test_pe_unpacker(ofrak_context, test_case):
    assets_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "./assets"))
    pe_file_path = os.path.join(assets_dir, test_case)
    root_resource = await ofrak_context.create_root_resource_from_file(pe_file_path)
    await root_resource.unpack_recursively()

    pe_view = await root_resource.view_as(Pe)

    # Get the sections
    sections = list(await pe_view.get_sections())
    assert len(sections) > 0

    # Get the code region; test get_header() / get_body()
    code_regions = list(await pe_view.get_sections())
    assert code_regions is not []
    code_region = await pe_view.get_section_by_name(".text")
    code_region_header = await code_region.get_header()
    assert code_region_header.name == ".text"
    assert await code_region_header.get_body() == code_region
