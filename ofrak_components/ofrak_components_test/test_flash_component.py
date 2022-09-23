import os
from hashlib import md5
from ofrak_components.ecc.reedsolomon import ReedSolomon

import test_ofrak.components
from ofrak import OFRAKContext, ResourceFilter
from ofrak.resource import Resource
from ofrak_components.flash import (
    FlashResource,
    FlashEccResource,
    FlashLogicalDataResource,
    FlashConfig,
    FlashEccConfig,
    FlashField,
    FlashFieldType,
    FlashEccIdentifier,
    FlashEccProtectedResourceUnpacker,
    FlashLogicalDataResourcePacker,
    FlashEccResourcePacker,
    FlashResourcePacker,
)
from ofrak_components.ecc.reedsolomon import ReedSolomon
from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern
from ofrak.core.binary import BinaryPatchConfig, BinaryPatchModifier

TEST_FILE_PATH = os.path.join(test_ofrak.components.ASSETS_DIR, "flash_test.bin")
TEST_VERIFY_FILE_PATH = os.path.join(test_ofrak.components.ASSETS_DIR, "flash_test_verify.bin")


class TestFlashUnpackModifyPack(UnpackModifyPackPattern):
    ECC_CONFIG = FlashEccConfig(
        ecc_class=ReedSolomon(nsym=32, fcr=1),
        ecc_magic=b"ECC_ME!",
        head_delimiter=b"*",
        data_delimiter=b"*",
        last_data_delimiter=b"$",
        tail_delimiter=b"!",
    )
    FLASH_CONFIG = FlashConfig(
        header_block_format=[
            FlashField(FlashFieldType.MAGIC, 7),
            FlashField(FlashFieldType.DATA, 215),
            FlashField(FlashFieldType.DELIMITER, 1),
            FlashField(FlashFieldType.ECC, 32),
        ],
        data_block_format=[
            FlashField(FlashFieldType.DATA, 222),
            FlashField(FlashFieldType.DELIMITER, 1),
            FlashField(FlashFieldType.ECC, 32),
        ],
        last_data_block_format=[
            FlashField(FlashFieldType.DATA, 222),
            FlashField(FlashFieldType.DELIMITER, 1),
            FlashField(FlashFieldType.ECC, 32),
            FlashField(FlashFieldType.ALIGNMENT, 0),
        ],
        tail_block_format=[
            FlashField(FlashFieldType.DELIMITER, 1),
            FlashField(FlashFieldType.DATA_SIZE, 4),
            FlashField(FlashFieldType.CHECKSUM, 16),
            FlashField(FlashFieldType.ECC, 32),
        ],
        ecc_config=ECC_CONFIG,
        checksum_func=(lambda x: md5(x).digest()),
    )

    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        return await ofrak_context.create_root_resource_from_file(TEST_FILE_PATH)

    async def unpack(self, resource: Resource) -> None:
        resource.add_tag(FlashResource)
        await resource.save()
        await resource.run(FlashEccIdentifier, self.FLASH_CONFIG)
        await resource.run(FlashEccProtectedResourceUnpacker, self.FLASH_CONFIG)

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
        logical_data_resource = await resource.get_only_descendant(
            r_filter=ResourceFilter.with_tags(
                FlashLogicalDataResource,
            ),
        )
        await logical_data_resource.run(FlashLogicalDataResourcePacker, self.FLASH_CONFIG)
        ecc_resource = await resource.get_only_child(
            r_filter=ResourceFilter.with_tags(FlashEccResource)
        )
        await ecc_resource.run(FlashEccResourcePacker, self.FLASH_CONFIG)
        await resource.run(FlashResourcePacker, self.FLASH_CONFIG)

    async def verify(self, repacked_resource: Resource) -> None:
        # Check that the new file matches the manually verified file
        with open(TEST_VERIFY_FILE_PATH, "rb") as f:
            verified_data = f.read()
        repacked_data = await repacked_resource.get_data()

        assert verified_data == repacked_data
