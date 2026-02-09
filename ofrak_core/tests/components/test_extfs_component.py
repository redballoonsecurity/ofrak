"""
Test the Ext filesystem unpacking functionality for EXT2, EXT3, and EXT4 filesystems.

Requirements Mapping:
- REQ1.3
- REQ4.4
"""
import os
import os.path
import shutil
import subprocess
import tempfile312 as tempfile
from dataclasses import dataclass
from typing import Dict

import pytest
from ofrak.core.filesystem import File

from ofrak.resource import Resource

from ofrak import OFRAKContext
from ofrak.core.extfs import *
from pytest_ofrak.patterns.pack_unpack_filesystem import FilesystemPackUnpackVerifyPattern
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


class _TestExtPackUnpack(FilesystemPackUnpackVerifyPattern):
    EXT_TYPE: str

    def setup(self):
        super().setup()
        self.check_stat = False
        self.check_xattrs = False

    async def create_root_resource(self, ofrak_context: OFRAKContext, directory: str) -> Resource:
        with tempfile.NamedTemporaryFile(suffix=".img", delete_on_close=False) as ext_blob:
            ext_blob.close()
            command = [
                "mke2fs",
                "-t",
                self.EXT_TYPE,
                "-d",
                directory,
                ext_blob.name,
                "20M",
            ]
            subprocess.run(command, check=True, capture_output=True)
            return await ofrak_context.create_root_resource_from_file(ext_blob.name)

    async def unpack(self, root_resource: Resource) -> None:
        await root_resource.unpack()

    async def repack(self, root_resource: Resource) -> None:
        await root_resource.pack()

    async def extract(self, root_resource: Resource, extract_dir: str) -> None:
        async with root_resource.temp_to_disk() as ext_blob_path:
            with tempfile.TemporaryDirectory() as temp_dir:
                command = [
                    "debugfs",
                    "-R",
                    f"rdump / {temp_dir}",
                    ext_blob_path,
                ]
                subprocess.run(command, check=True, capture_output=True)
                for item in os.listdir(temp_dir):
                    src = os.path.join(temp_dir, item)
                    dst = os.path.join(str(extract_dir), item)
                    if os.path.isdir(src):
                        shutil.copytree(src, dst, symlinks=True)
                    else:
                        shutil.copy2(src, dst)


@pytest.mark.skipif_missing_deps([ExtUnpacker, ExtPacker])
class TestExt2PackUnpack(_TestExtPackUnpack):
    EXT_TYPE = "ext2"


@pytest.mark.skipif_missing_deps([ExtUnpacker, ExtPacker])
class TestExt3PackUnpack(_TestExtPackUnpack):
    EXT_TYPE = "ext3"


@pytest.mark.skipif_missing_deps([ExtUnpacker, ExtPacker])
class TestExt4PackUnpack(_TestExtPackUnpack):
    EXT_TYPE = "ext4"


@pytest.mark.skipif_missing_deps([ExtUnpacker, ExtPacker])
async def test_attributes_preserved(ofrak_context: OFRAKContext):
    asset_path = os.path.join(components.ASSETS_DIR, "ext2.4096.img")
    original_resource = await ofrak_context.create_root_resource_from_file(asset_path)
    await original_resource.identify()
    original_view = await original_resource.view_as(Ext2Filesystem)
    original_attrs = {
        "block_size": original_view.block_size,
        "block_count": original_view.block_count,
        "blocks_per_group": original_view.blocks_per_group,
        "inode_size": original_view.inode_size,
        "number_of_inodes": original_view.number_of_inodes,
        "reserved_block_count": original_view.reserved_block_count,
        "creator_os": original_view.creator_os,
        "filesystem_features": original_view.filesystem_features,
        "filesystem_revision": original_view.filesystem_revision,
        "uuid": original_view.uuid,
    }

    await original_resource.unpack()
    await original_resource.pack()

    async with original_resource.temp_to_disk(suffix=".img") as repacked_path:
        repacked_resource = await ofrak_context.create_root_resource_from_file(repacked_path)

    await repacked_resource.identify()
    repacked_view = await repacked_resource.view_as(Ext2Filesystem)
    repacked_attrs = {
        "block_size": repacked_view.block_size,
        "block_count": repacked_view.block_count,
        "blocks_per_group": repacked_view.blocks_per_group,
        "inode_size": repacked_view.inode_size,
        "number_of_inodes": repacked_view.number_of_inodes,
        "reserved_block_count": repacked_view.reserved_block_count,
        "creator_os": repacked_view.creator_os,
        "filesystem_features": repacked_view.filesystem_features,
        "filesystem_revision": repacked_view.filesystem_revision,
        "uuid": repacked_view.uuid,
    }

    for attr_name, original_val in original_attrs.items():
        repacked_val = repacked_attrs[attr_name]
        assert original_val == repacked_val, (
            f"Attribute {attr_name!r} changed after repack: "
            f"{original_val!r} -> {repacked_val!r}"
        )
