import pytest
import os
from hashlib import md5
from ofrak_components.ecc.reedsolomon import ReedSolomon

import test_ofrak.components
from ofrak import OFRAKContext, ResourceFilter
from ofrak.resource import Resource
from ofrak_components.flash import (
    FlashResource,
    FlashLogicalDataResource,
    FlashAttributes,
    FlashEccAttributes,
    FlashField,
    FlashFieldType,
)
from ofrak_components.ecc.reedsolomon import ReedSolomon
from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern
from ofrak.core.binary import BinaryPatchConfig, BinaryPatchModifier

DEFAULT_TEST_FILE = os.path.join(test_ofrak.components.ASSETS_DIR, "flash_test_default.bin")
DEFAULT_VERIFY_FILE = os.path.join(
    test_ofrak.components.ASSETS_DIR, "flash_test_default_verify.bin"
)
DEFAULT_UNPACKED_VERIFY_FILE = os.path.join(
    test_ofrak.components.ASSETS_DIR, "flash_test_default_unpacked_verify.bin"
)
DEFAULT_TEST_ATTR = FlashAttributes(
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
    ecc_attributes=FlashEccAttributes(
        ecc_class=ReedSolomon(nsym=32, fcr=1),
        ecc_magic=b"ECC_ME!",
        head_delimiter=b"*",
        data_delimiter=b"*",
        last_data_delimiter=b"$",
        tail_delimiter=b"!",
    ),
    checksum_func=(lambda x: md5(x).digest()),
)

FLASH_TEST_CASES = [
    (DEFAULT_TEST_FILE, DEFAULT_VERIFY_FILE, DEFAULT_TEST_ATTR),
    (
        os.path.join(test_ofrak.components.ASSETS_DIR, "flash_test_plain.bin"),
        os.path.join(test_ofrak.components.ASSETS_DIR, "flash_test_plain_verify.bin"),
        FlashAttributes(
            data_block_format=[
                FlashField(FlashFieldType.DATA, 223),
                FlashField(FlashFieldType.ECC, 32),
            ],
            ecc_attributes=FlashEccAttributes(
                ecc_class=ReedSolomon(nsym=32),
            ),
        ),
    ),
    (
        os.path.join(test_ofrak.components.ASSETS_DIR, "flash_test_totalsize_in_header.bin"),
        os.path.join(test_ofrak.components.ASSETS_DIR, "flash_test_totalsize_in_header_verify.bin"),
        FlashAttributes(
            header_block_format=[
                FlashField(FlashFieldType.TOTAL_SIZE, 4),
            ],
            data_block_format=[
                FlashField(FlashFieldType.DATA, 223),
                FlashField(FlashFieldType.ECC, 32),
            ],
            ecc_attributes=FlashEccAttributes(
                ecc_class=ReedSolomon(nsym=32),
            ),
        ),
    ),
    (
        os.path.join(test_ofrak.components.ASSETS_DIR, "flash_test_datasize_checksum.bin"),
        os.path.join(test_ofrak.components.ASSETS_DIR, "flash_test_datasize_checksum_verify.bin"),
        FlashAttributes(
            header_block_format=[
                FlashField(FlashFieldType.DATA_SIZE, 4),
            ],
            data_block_format=[
                FlashField(FlashFieldType.DATA, 223),
                FlashField(FlashFieldType.ECC, 32),
            ],
            tail_block_format=[
                FlashField(FlashFieldType.CHECKSUM, 16),
            ],
            ecc_attributes=FlashEccAttributes(
                ecc_class=ReedSolomon(nsym=32, fcr=1),
            ),
            checksum_func=(lambda x: md5(x).digest()),
        ),
    ),
]


class TestFlashUnpackModifyPack(UnpackModifyPackPattern):
    @pytest.mark.parametrize(["TEST_FILE", "VERIFY_FILE", "TEST_ATTR"], FLASH_TEST_CASES)
    async def test_unpack_modify_pack(self, ofrak_context, TEST_FILE, VERIFY_FILE, TEST_ATTR):
        root_resource = await self.create_root_resource(ofrak_context, TEST_FILE)
        root_resource.add_attributes(TEST_ATTR)
        await root_resource.save()
        await self.unpack(root_resource)
        await self.modify(root_resource)
        await self.repack(root_resource)
        await self.verify(root_resource, VERIFY_FILE)

    async def create_root_resource(self, ofrak_context: OFRAKContext, TEST_FILE: str) -> Resource:
        return await ofrak_context.create_root_resource_from_file(TEST_FILE)

    async def unpack(self, resource: Resource, config=None) -> None:
        resource.add_tag(FlashResource)
        await resource.save()
        await resource.unpack_recursively()

    async def modify(self, unpacked_root_resource: Resource) -> None:
        logical_data_resource = await unpacked_root_resource.get_only_descendant(
            r_filter=ResourceFilter.with_tags(
                FlashLogicalDataResource,
            ),
        )
        new_data = b"INSERT ME!"
        patch_config = BinaryPatchConfig(0x16, new_data)
        await logical_data_resource.run(BinaryPatchModifier, patch_config)

    async def repack(self, resource: Resource, config=None) -> None:
        await resource.pack_recursively()

    async def verify(self, repacked_resource: Resource, VERIFY_FILE: str) -> None:
        # Check that the new file matches the manually verified file
        with open(VERIFY_FILE, "rb") as f:
            verified_data = f.read()
        repacked_data = await repacked_resource.get_data()

        assert verified_data == repacked_data


class TestFlashUnpackModifyPackUnpackVerify(TestFlashUnpackModifyPack):
    async def test_unpack_modify_pack(self, ofrak_context):
        root_resource = await self.create_root_resource(ofrak_context, DEFAULT_TEST_FILE)
        root_resource.add_attributes(DEFAULT_TEST_ATTR)
        await root_resource.save()
        await self.unpack(root_resource)
        await self.modify(root_resource)
        await self.repack(root_resource)
        await self.unpack(root_resource)
        logical_data_resource = await root_resource.get_only_descendant(
            r_filter=ResourceFilter.with_tags(
                FlashLogicalDataResource,
            ),
        )
        await self.verify(logical_data_resource, DEFAULT_UNPACKED_VERIFY_FILE)
