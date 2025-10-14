"""
This module tests the Ext filesystem unpacking functionality for EXT2, EXT3, and EXT4 filesystems.
"""
import os.path
from dataclasses import dataclass
from typing import Dict

import pytest
from ofrak.core.filesystem import File

from ofrak.resource import Resource

from ofrak import OFRAKContext
from ofrak.core.extfs import *
from pytest_ofrak.patterns.unpack_verify import (
    UnpackAndVerifyPattern,
    UnpackAndVerifyTestCase,
)
from .. import components


pytestmark = pytest.mark.skipif_missing_deps([ExtUnpacker])


@dataclass
class ExtUnpackerTestCase(UnpackAndVerifyTestCase[str, bytes]):
    filename: str


EXT2_UNPACKER_TEST_CASES = [
    ExtUnpackerTestCase(
        "Single text file",
        {"apple.txt": b"apple\n", "banana.txt": b"banana\n", "cherry.txt": b"cherry\n"},
        set(),
        "ext2.1024.img",
    ),
    ExtUnpackerTestCase(
        "Single text file",
        {"apple.txt": b"apple\n", "banana.txt": b"banana\n", "cherry.txt": b"cherry\n"},
        set(),
        "ext2.2048.img",
    ),
    ExtUnpackerTestCase(
        "Single text file",
        {"apple.txt": b"apple\n", "banana.txt": b"banana\n", "cherry.txt": b"cherry\n"},
        set(),
        "ext2.4096.img",
    ),
]

EXT3_UNPACKER_TEST_CASES = [
    ExtUnpackerTestCase(
        "Single text file",
        {"apple.txt": b"apple\n", "banana.txt": b"banana\n", "cherry.txt": b"cherry\n"},
        set(),
        "ext3.1024.img",
    ),
    ExtUnpackerTestCase(
        "Single text file",
        {"apple.txt": b"apple\n", "banana.txt": b"banana\n", "cherry.txt": b"cherry\n"},
        set(),
        "ext3.2048.img",
    ),
    ExtUnpackerTestCase(
        "Single text file",
        {"apple.txt": b"apple\n", "banana.txt": b"banana\n", "cherry.txt": b"cherry\n"},
        set(),
        "ext3.4096.img",
    ),
]

EXT4_UNPACKER_TEST_CASES = [
    ExtUnpackerTestCase(
        "Single text file",
        {"apple.txt": b"apple\n", "banana.txt": b"banana\n", "cherry.txt": b"cherry\n"},
        set(),
        "ext4.1024.img",
    ),
    ExtUnpackerTestCase(
        "Single text file",
        {"apple.txt": b"apple\n", "banana.txt": b"banana\n", "cherry.txt": b"cherry\n"},
        set(),
        "ext4.2048.img",
    ),
    ExtUnpackerTestCase(
        "Single text file",
        {"apple.txt": b"apple\n", "banana.txt": b"banana\n", "cherry.txt": b"cherry\n"},
        set(),
        "ext4.4096.img",
    ),
]


class _TestExtUnpackModifyPack(UnpackAndVerifyPattern):
    @pytest.fixture
    async def root_resource(
        self,
        unpack_verify_test_case: ExtUnpackerTestCase,
        ofrak_context: OFRAKContext,
        test_id: str,
    ) -> Resource:
        asset_path = os.path.join(components.ASSETS_DIR, unpack_verify_test_case.filename)
        with open(asset_path, "rb") as f:
            data = f.read()
        return await ofrak_context.create_root_resource(test_id, data, tags=(File,))

    async def unpack(self, root_resource: Resource):
        await root_resource.unpack_recursively()

    async def verify_descendant(self, unpacked_descendant: bytes, specified_result: bytes):
        assert unpacked_descendant == specified_result

    async def unpack_verify_test_case(self, request) -> ExtUnpackerTestCase:
        raise NotImplementedError

    async def get_descendants_to_verify(self, unpacked_root_resource: Resource) -> Dict[str, bytes]:
        raise NotImplementedError


class TestExt2UnpackModifyPack(_TestExtUnpackModifyPack):
    """
    This test verifies that EXT2 filesystems can be correctly unpacked and their contents verified.

    This test verifies that:
    - The EXT2 filesystem is successfully unpacked
    - The files within the EXT2 filesystem are correctly identified and extracted
    """

    @pytest.fixture(params=EXT2_UNPACKER_TEST_CASES, ids=lambda tc: tc.label)
    async def unpack_verify_test_case(self, request) -> ExtUnpackerTestCase:
        return request.param

    async def get_descendants_to_verify(self, unpacked_root_resource: Resource) -> Dict[str, bytes]:
        ext2_view = await unpacked_root_resource.view_as(Ext2Filesystem)
        children = await ext2_view.list_dir()
        return {
            name: await child.resource.get_data()
            for name, child in children.items()
            if child.is_file()
        }


class TestExt3UnpackModifyPack(_TestExtUnpackModifyPack):
    """
    This test verifies that EXT3 filesystems can be correctly unpacked and their contents verified.

    This test verifies that:
    - The EXT3 filesystem is successfully unpacked
    - The files within the EXT3 filesystem are correctly identified and extracted
    """

    @pytest.fixture
    async def root_resource(
        self,
        unpack_verify_test_case: ExtUnpackerTestCase,
        ofrak_context: OFRAKContext,
        test_id: str,
    ) -> Resource:
        asset_path = os.path.join(components.ASSETS_DIR, unpack_verify_test_case.filename)
        with open(asset_path, "rb") as f:
            data = f.read()
        return await ofrak_context.create_root_resource(test_id, data, tags=(Ext3Filesystem,))

    @pytest.fixture(params=EXT3_UNPACKER_TEST_CASES, ids=lambda tc: tc.label)
    async def unpack_verify_test_case(self, request) -> ExtUnpackerTestCase:
        return request.param

    async def get_descendants_to_verify(self, unpacked_root_resource: Resource) -> Dict[str, bytes]:
        ext3_view = await unpacked_root_resource.view_as(Ext3Filesystem)
        children = await ext3_view.list_dir()
        return {
            name: await child.resource.get_data()
            for name, child in children.items()
            if child.is_file()
        }


class TestExt4UnpackModifyPack(_TestExtUnpackModifyPack):
    """
    This test verifies that EXT4 filesystems can be correctly unpacked and their contents verified.

    This test verifies that:
    - The EXT4 filesystem is successfully unpacked
    - The files within the EXT4 filesystem are correctly identified and extracted
    """

    @pytest.fixture
    async def root_resource(
        self,
        unpack_verify_test_case: ExtUnpackerTestCase,
        ofrak_context: OFRAKContext,
        test_id: str,
    ) -> Resource:
        asset_path = os.path.join(components.ASSETS_DIR, unpack_verify_test_case.filename)
        with open(asset_path, "rb") as f:
            data = f.read()
        return await ofrak_context.create_root_resource(test_id, data, tags=(Ext4Filesystem,))

    @pytest.fixture(params=EXT4_UNPACKER_TEST_CASES, ids=lambda tc: tc.label)
    async def unpack_verify_test_case(self, request) -> ExtUnpackerTestCase:
        return request.param

    async def get_descendants_to_verify(self, unpacked_root_resource: Resource) -> Dict[str, bytes]:
        ext4_view = await unpacked_root_resource.view_as(Ext4Filesystem)
        children = await ext4_view.list_dir()
        return {
            name: await child.resource.get_data()
            for name, child in children.items()
            if child.is_file()
        }
