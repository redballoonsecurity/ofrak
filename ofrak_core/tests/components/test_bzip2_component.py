import bz2
import logging

from ofrak import OFRAKContext
from ofrak.core.binary import GenericBinary
from ofrak.resource import Resource
from ofrak.core.bzip2 import Bzip2Data
from ofrak.core.strings import StringPatchingConfig, StringPatchingModifier
from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern

LOGGER = logging.getLogger(__name__)

INITIAL_DATA = b"Hello World"
EXPECTED_DATA = b"Hello OFRAK"
TARGET_BZIP2_FILE = "hello_bzip2.bz2"
BZIP2_ENTRY_NAME = "hello_bzip2_file"


class TestBzip2UnpackModifyPack(UnpackModifyPackPattern):
    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        compressed_data = bz2.compress(INITIAL_DATA)
        root_resource = await ofrak_context.create_root_resource("bzip2", compressed_data)
        root_resource.add_tag(GenericBinary)
        await root_resource.save()
        return root_resource

    async def unpack(self, bzip2_resource: Resource) -> None:
        await bzip2_resource.unpack()
        assert bzip2_resource.has_tag(Bzip2Data)

    async def modify(self, unpacked_bzip2_resource: Resource) -> None:
        bzip2_r = await unpacked_bzip2_resource.get_only_child()
        string_patch_config = StringPatchingConfig(6, "OFRAK")
        await bzip2_r.run(StringPatchingModifier, string_patch_config)
        LOGGER.info(await bzip2_r.get_data())

    async def repack(self, bzip2_resource: Resource) -> None:
        LOGGER.info(await bzip2_resource.get_data())
        await bzip2_resource.pack()

    async def verify(self, repacked_bzip2_resource: Resource) -> None:
        resource_data = await repacked_bzip2_resource.get_data()
        decompressed_data = bz2.decompress(resource_data)
        assert decompressed_data == EXPECTED_DATA
        assert repacked_bzip2_resource.has_tag(Bzip2Data)
