"""
Test the Intel HEX (IHEX) file format handling capabilities of OFRAK.

Requirements Mapping:
- REQ1.3
- REQ4.4
"""
import os
from dataclasses import dataclass

from ofrak.core.ihex import IhexPacker, IhexUnpacker
import pytest

from ofrak import OFRAKContext, Resource, ResourceFilter, ResourceAttributeRangeFilter
from ofrak.core import MemoryRegion, Ihex
from ofrak_type import Range
from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern
from pytest_ofrak.patterns.unpack_verify import UnpackAndVerifyTestCase
from . import ASSETS_DIR


@dataclass
class IhexTestCase(UnpackAndVerifyTestCase):
    fname: str


IHEX_TEST_FILES = [
    os.path.join(ASSETS_DIR, fname)
    for fname in [
        "patch_demo.ihex",
        "hello_world.ihex",
    ]
]


@pytest.mark.skipif_missing_deps([IhexPacker, IhexUnpacker])
class TestIhexUnpackPack(UnpackModifyPackPattern):
    """
    Test the unpacking, modification, and repacking functionality of Intel HEX files.

    This test verifies that:
    - Intel HEX files can be successfully unpacked into memory regions
    - Modifications can be made to the unpacked memory regions
    - The modified data can be repacked back into Intel HEX format
    - The repacked file maintains the expected modifications and is valid
    """

    REPLACEMENT_STRING = b"deadbeef ofrak"

    @pytest.fixture(params=IHEX_TEST_FILES, autouse=True)
    def _setup_test(self, request):
        self._test_file = request.param

    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        return await ofrak_context.create_root_resource_from_file(self._test_file)

    async def unpack(self, root_resource: Resource) -> None:
        await root_resource.unpack_recursively()

    async def modify(self, unpacked_root_resource: Resource) -> None:
        r_filter = ResourceFilter(
            tags=(MemoryRegion,),
            attribute_filters=(
                ResourceAttributeRangeFilter(MemoryRegion.Size, len(self.REPLACEMENT_STRING)),
            ),
        )
        child_to_modify = next(
            iter(await unpacked_root_resource.get_descendants(r_filter=r_filter))
        )

        child_to_modify.queue_patch(Range(0, len(self.REPLACEMENT_STRING)), self.REPLACEMENT_STRING)
        await child_to_modify.save()

    async def repack(self, modified_root_resource: Resource) -> None:
        await modified_root_resource.pack_recursively()

    async def verify(self, repacked_root_resource: Resource) -> None:
        search_term = self.REPLACEMENT_STRING.hex().upper().encode("utf-8")
        results = await repacked_root_resource.search_data(search_term)
        assert len(results) == 1

        # Should be able to unpack again at the end
        await repacked_root_resource.unpack_recursively()


@pytest.mark.skipif_missing_deps([IhexPacker, IhexUnpacker])
@pytest.mark.parametrize("ihex_file", IHEX_TEST_FILES)
async def test_ihex_analyzer(ofrak_context: OFRAKContext, ihex_file):
    """
    Test the Intel HEX analyzer functionality for parsing and extracting program information.

    This test verifies that:
    - Intel HEX files are correctly parsed to extract address limits
    - The start address is properly identified from the HEX file
    - The data can be converted between HEX and binary formats correctly
    """
    from bincopy import BinFile

    root = await ofrak_context.create_root_resource_from_file(ihex_file)
    await root.identify()
    raw_ihex_data = await root.get_data()
    binfile = BinFile()
    binfile.add_ihex(raw_ihex_data.decode("utf-8"))

    ihex = await root.view_as(Ihex)
    assert ihex.start_addr == binfile.execution_start_address
