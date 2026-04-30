"""
This module tests the Flash component's unpacking, modification, and repacking functionality.

Requirements Mapping:
- REQ1.3
- REQ3.4
- REQ4.4
"""

import pytest
import os
from abc import ABC
from hashlib import md5

from .. import components
from ofrak import OFRAKContext, ResourceFilter
from ofrak.resource import Resource
from ofrak.core.flash import (
    FlashResource,
    FlashLogicalDataResource,
    FlashLogicalEccResource,
    FlashSpareAreaResource,
    FlashAttributes,
    FlashEccAttributes,
    FlashField,
    FlashFieldType,
)
from ofrak.core.ecc.reedsolomon import ReedSolomon
from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern
from ofrak.core.binary import BinaryPatchConfig, BinaryPatchModifier

DEFAULT_TEST_FILE = os.path.join(components.ASSETS_DIR, "flash_test_default.bin")
DEFAULT_VERIFY_FILE = os.path.join(components.ASSETS_DIR, "flash_test_default_verify.bin")
DEFAULT_UNPACKED_VERIFY_FILE = os.path.join(
    components.ASSETS_DIR, "flash_test_default_unpacked_verify.bin"
)
DEFAULT_UNPACKED_MODIFIED_VERIFY_FILE = os.path.join(
    components.ASSETS_DIR, "flash_test_default_unpacked_modified_verify.bin"
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
        os.path.join(components.ASSETS_DIR, "flash_test_plain.bin"),
        os.path.join(components.ASSETS_DIR, "flash_test_plain_verify.bin"),
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
        os.path.join(components.ASSETS_DIR, "flash_test_totalsize_in_header.bin"),
        os.path.join(components.ASSETS_DIR, "flash_test_totalsize_in_header_verify.bin"),
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
        os.path.join(components.ASSETS_DIR, "flash_test_datasize_checksum.bin"),
        os.path.join(components.ASSETS_DIR, "flash_test_datasize_checksum_verify.bin"),
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
    (
        os.path.join(components.ASSETS_DIR, "flash_test_magic.bin"),
        os.path.join(components.ASSETS_DIR, "flash_test_magic_verify.bin"),
        FlashAttributes(
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
                FlashField(FlashFieldType.MAGIC, 7),
                FlashField(FlashFieldType.CHECKSUM, 16),
                FlashField(FlashFieldType.ECC, 32),
            ],
            ecc_attributes=FlashEccAttributes(
                ecc_class=ReedSolomon(nsym=32, fcr=1),
                ecc_magic=b"ECC_ME!",
                head_delimiter=b"*",
                data_delimiter=b"*",
                last_data_delimiter=b"$",
            ),
            checksum_func=(lambda x: md5(x).digest()),
        ),
    ),
]


class TestFlashUnpackModifyPack(UnpackModifyPackPattern):
    @pytest.mark.parametrize(["TEST_FILE", "VERIFY_FILE", "TEST_ATTR"], FLASH_TEST_CASES)
    async def test_unpack_modify_pack(self, ofrak_context, TEST_FILE, VERIFY_FILE, TEST_ATTR):
        """
        Test full workflow of unpacking, modifying, repacking and verifying Flash resources.

        This test verifies that:
        - Flash attributes are properly added to the resource
        - Resource can be unpacked recursively
        - Logical data can be modified using a binary patch
        - Resource can be repacked after modification
        - Final packed data matches expected verification file
        """
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


SPARE_TEST_FILE = os.path.join(components.ASSETS_DIR, "flash_test_plain.bin")
SPARE_BLOCK_DATA = 223
SPARE_BLOCK_OOB = 32
SPARE_BLOCK_TOTAL = SPARE_BLOCK_DATA + SPARE_BLOCK_OOB  # 255
SPARE_TEST_ATTR = FlashAttributes(
    data_block_format=[
        FlashField(FlashFieldType.DATA, SPARE_BLOCK_DATA),
        FlashField(FlashFieldType.SPARE, SPARE_BLOCK_OOB),
    ],
)


def _split_blocks(raw: bytes, block_size: int, data_size: int):
    data_parts = []
    spare_parts = []
    for off in range(0, len(raw), block_size):
        block = raw[off : off + block_size]
        data_parts.append(block[:data_size])
        spare_parts.append(block[data_size:])
    return b"".join(data_parts), b"".join(spare_parts)


class TestFlashSpareAreaUnpacker:
    async def test_spare_field_creates_spare_resource(self, ofrak_context: OFRAKContext):
        """
        Asserts that a `FlashAttributes` with a `SPARE` field (and no `ecc_attributes`) causes
        `FlashOobResourceUnpacker` to emit a `FlashSpareAreaResource` containing the raw
        per-block OOB bytes verbatim, with no ECC decode or checksum verification.
        """
        with open(SPARE_TEST_FILE, "rb") as f:
            raw = f.read()
        assert (
            len(raw) % SPARE_BLOCK_TOTAL == 0
        ), f"Asset size {len(raw)} is not a multiple of {SPARE_BLOCK_TOTAL}"
        expected_data, expected_spare = _split_blocks(raw, SPARE_BLOCK_TOTAL, SPARE_BLOCK_DATA)

        root = await ofrak_context.create_root_resource_from_file(SPARE_TEST_FILE)
        root.add_tag(FlashResource)
        root.add_attributes(SPARE_TEST_ATTR)
        await root.save()
        await root.unpack_recursively()

        logical = await root.get_only_descendant(
            r_filter=ResourceFilter.with_tags(FlashLogicalDataResource),
        )
        spare = await root.get_only_descendant(
            r_filter=ResourceFilter.with_tags(FlashSpareAreaResource),
        )

        logical_bytes = await logical.get_data()
        spare_bytes = await spare.get_data()

        assert logical_bytes == expected_data
        assert spare_bytes == expected_spare

        # No ECC resource should be created when ecc_attributes is unset.
        ecc_descendants = list(
            await root.get_descendants(
                r_filter=ResourceFilter.with_tags(FlashLogicalEccResource),
            )
        )
        assert ecc_descendants == []


class _SpareUMPBase(UnpackModifyPackPattern, ABC):
    """
    Shared scaffolding for `FlashLogicalDataResourcePacker` tests that exercise block formats
    declaring a `SPARE` field. The packer must consume the sibling `FlashSpareAreaResource`
    and re-emit each per-block spare slice into its original position so the OOB layout is
    reconstructed verbatim. Subclasses provide `modify` and `verify` to express each scenario.
    """

    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        root = await ofrak_context.create_root_resource_from_file(SPARE_TEST_FILE)
        root.add_tag(FlashResource)
        root.add_attributes(SPARE_TEST_ATTR)
        await root.save()
        return root

    async def unpack(self, root_resource: Resource) -> None:
        await root_resource.unpack_recursively()

    async def repack(self, modified_root_resource: Resource) -> None:
        await modified_root_resource.pack_recursively()


class TestFlashSpareAreaPackerRoundtrip(_SpareUMPBase):
    """
    Unpack and immediately repack with no modifications; the packed bytes must equal the
    original file byte-for-byte (DATA from `FlashLogicalDataResource`, SPARE from
    `FlashSpareAreaResource`).
    """

    async def modify(self, unpacked_root_resource: Resource) -> None:
        pass

    async def verify(self, repacked_root_resource: Resource) -> None:
        with open(SPARE_TEST_FILE, "rb") as f:
            original = f.read()
        repacked = await repacked_root_resource.get_data()
        assert repacked == original


class TestFlashSpareAreaPackerLogicalDataPatch(_SpareUMPBase):
    """
    Modifying logical data must not disturb the spare-area bytes: the per-block OOB regions
    in the repacked dump should match the original file's OOB regions exactly.
    """

    PATCH_OFFSET = 0x10
    PATCH = b"PATCHED!"

    async def modify(self, unpacked_root_resource: Resource) -> None:
        logical = await unpacked_root_resource.get_only_descendant(
            r_filter=ResourceFilter.with_tags(FlashLogicalDataResource),
        )
        await logical.run(BinaryPatchModifier, BinaryPatchConfig(self.PATCH_OFFSET, self.PATCH))

    async def verify(self, repacked_root_resource: Resource) -> None:
        with open(SPARE_TEST_FILE, "rb") as f:
            original = f.read()
        _, expected_spare = _split_blocks(original, SPARE_BLOCK_TOTAL, SPARE_BLOCK_DATA)
        repacked = await repacked_root_resource.get_data()

        assert len(repacked) == len(original)
        repacked_data, repacked_spare = _split_blocks(repacked, SPARE_BLOCK_TOTAL, SPARE_BLOCK_DATA)
        assert repacked_spare == expected_spare
        assert repacked_data[self.PATCH_OFFSET : self.PATCH_OFFSET + len(self.PATCH)] == self.PATCH


class TestFlashSpareAreaPackerSparePatch(_SpareUMPBase):
    """
    Modifying the spare-area resource directly must round-trip into the packed image at
    the corresponding per-block OOB offsets, while logical data stays intact.
    """

    async def modify(self, unpacked_root_resource: Resource) -> None:
        spare = await unpacked_root_resource.get_only_descendant(
            r_filter=ResourceFilter.with_tags(FlashSpareAreaResource),
        )
        # Patch the very first byte of the very first block's spare region.
        await spare.run(BinaryPatchModifier, BinaryPatchConfig(0, b"\xAB"))

    async def verify(self, repacked_root_resource: Resource) -> None:
        with open(SPARE_TEST_FILE, "rb") as f:
            original = f.read()
        expected_data, expected_spare = _split_blocks(original, SPARE_BLOCK_TOTAL, SPARE_BLOCK_DATA)
        repacked = await repacked_root_resource.get_data()

        assert len(repacked) == len(original)
        repacked_data, repacked_spare = _split_blocks(repacked, SPARE_BLOCK_TOTAL, SPARE_BLOCK_DATA)
        assert repacked_data == expected_data
        assert repacked_spare == b"\xAB" + expected_spare[1:]


class TestFlashUnpackModifyPackUnpackVerify(TestFlashUnpackModifyPack):
    async def test_unpack_modify_pack(self, ofrak_context):
        """
        Test unpacking, modifying, repacking, and unpacking Flash resources.

        This test verifies that:
        - Resource can be unpacked and verified at intermediate stages
        - Repacked resource can be unpacked again and verified
        """
        root_resource = await self.create_root_resource(ofrak_context, DEFAULT_TEST_FILE)
        root_resource.add_attributes(DEFAULT_TEST_ATTR)
        await root_resource.save()
        await self.unpack(root_resource)
        logical_data_resource = await root_resource.get_only_descendant(
            r_filter=ResourceFilter.with_tags(
                FlashLogicalDataResource,
            ),
        )
        await self.verify(logical_data_resource, DEFAULT_UNPACKED_VERIFY_FILE)
        await self.modify(root_resource)
        await self.repack(root_resource)
        await self.unpack(root_resource)
        logical_data_resource = await root_resource.get_only_descendant(
            r_filter=ResourceFilter.with_tags(
                FlashLogicalDataResource,
            ),
        )
        await self.verify(logical_data_resource, DEFAULT_UNPACKED_MODIFIED_VERIFY_FILE)
