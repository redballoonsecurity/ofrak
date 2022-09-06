import os

import test_ofrak.components
from ofrak import OFRAKContext, ResourceFilter
from ofrak.resource import Resource
from ofrak_components.flash import FlashResource, FlashLogicalDataResource
from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern
from ofrak.core.binary import BinaryPatchConfig, BinaryPatchModifier

TEST_FILE_PATH = os.path.join(test_ofrak.components.ASSETS_DIR, "flash_test.bin")
TEST_VERIFY_FILE_PATH = os.path.join(test_ofrak.components.ASSETS_DIR, "flash_test_verify.bin")


class TestFlashUnpackModifyPack(UnpackModifyPackPattern):
    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        return await ofrak_context.create_root_resource_from_file(TEST_FILE_PATH)

    async def unpack(self, resource: Resource) -> None:
        resource.add_tag(FlashResource)
        await resource.save()
        await resource.unpack()

    async def modify(self, unpacked_root_resource: Resource) -> None:
        logical_data_resource = await unpacked_root_resource.get_only_descendant(
            r_filter=ResourceFilter.with_tags(
                FlashLogicalDataResource,
            ),
        )
        new_data = b"INSERT ME!"
        patch_config = BinaryPatchConfig(0x16, new_data)
        await logical_data_resource.run(BinaryPatchModifier, patch_config)

    async def repack(self, resource: Resource) -> None:
        await resource.pack_recursively()

    async def verify(self, repacked_resource: Resource) -> None:
        # Check that the new file matches the manually verified file
        with open(TEST_VERIFY_FILE_PATH, "rb") as f:
            verified_data = f.read()
        repacked_data = await repacked_resource.get_data()

        assert verified_data == repacked_data
