import os

import test_ofrak.components
from ofrak import OFRAKContext
from ofrak.resource import Resource
from pytest_ofrak.patterns.unpack_modify_pack import UnpackPackPattern

TEST_FILE_PATH = os.path.join(test_ofrak.components.ASSETS_DIR, "flash_test.bin")


class TestFlashUnpackModifyPack(UnpackPackPattern):
    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        return await ofrak_context.create_root_resource_from_file(TEST_FILE_PATH)

    async def unpack(self, resource: Resource) -> None:
        await resource.unpack()

    async def repack(self, resource: Resource) -> None:
        await resource.pack()

    async def verify(self, repacked_resource: Resource) -> None:
        with open(TEST_FILE_PATH, "rb") as f:
            original_data = f.read()
        repacked_data = await repacked_resource.get_data()

        assert original_data == repacked_data
