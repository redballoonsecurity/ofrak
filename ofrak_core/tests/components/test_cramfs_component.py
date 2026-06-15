"""
This module tests CramFS filesystem unpacking, modification, and repacking functionality.

Requirements Mapping:
- REQ1.3
- REQ4.4
"""
import os
import subprocess
import tempfile312 as tempfile

import pytest

from ofrak import OFRAKContext
from ofrak.resource import Resource
from ofrak.core.cramfs import Cramfs, CramfsPacker, CramfsUnpacker, CRAMFS_MAGIC_BE
from ofrak.core.strings import StringPatchingConfig, StringPatchingModifier
from ofrak_type.endianness import Endianness
from ofrak_type.range import Range
from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern

INITIAL_DATA = b"hello world"
EXPECTED_DATA = b"hello ofrak"
TARGET_CRAMFS_FILE = "test.cramfs"
CRAMFS_ENTRY_NAME = "hello_cramfs_file"


@pytest.mark.skipif_missing_deps([CramfsUnpacker, CramfsPacker])
class TestCramfsUnpackModifyPack(UnpackModifyPackPattern):
    """
    Test case for unpacking, modifying, and repacking a CramFS filesystem.

    This test verifies that:
    - A CramFS filesystem can be created and loaded as a resource
    - The filesystem can be unpacked recursively
    - Modifications to embedded files are applied correctly
    - The filesystem can be repacked recursively
    - The final output contains the modified data as expected
    """

    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        with tempfile.TemporaryDirectory() as tmpdir:
            entry_name = os.path.join(tmpdir, CRAMFS_ENTRY_NAME)
            target_file = os.path.join(tmpdir, TARGET_CRAMFS_FILE)

            with open(entry_name, "wb") as f:
                f.write(INITIAL_DATA)
            command = ["mkfs.cramfs", tmpdir, target_file]
            subprocess.run(command, check=True, capture_output=True)
            return await ofrak_context.create_root_resource_from_file(target_file)

    async def unpack(self, cramfs_resource: Resource) -> None:
        await cramfs_resource.unpack_recursively()

    async def modify(self, unpacked_cramfs_resource: Resource) -> None:
        cramfs_v = await unpacked_cramfs_resource.view_as(Cramfs)
        child_text_string_config = StringPatchingConfig(6, "ofrak")
        child_textfile = await cramfs_v.get_entry(CRAMFS_ENTRY_NAME)
        await child_textfile.resource.run(StringPatchingModifier, child_text_string_config)

    async def repack(self, cramfs_resource: Resource) -> None:
        await cramfs_resource.pack_recursively()

    async def verify(self, repacked_cramfs_resource: Resource) -> None:
        async with repacked_cramfs_resource.temp_to_disk() as temp_path:
            with tempfile.TemporaryDirectory() as temp_parent:
                extract_dir = os.path.join(temp_parent, "cramfs_extract")
                command = ["fsck.cramfs", f"--extract={extract_dir}", temp_path]
                subprocess.run(command, check=True, capture_output=True)
                with open(os.path.join(extract_dir, CRAMFS_ENTRY_NAME), "rb") as f:
                    patched_data = f.read()
                assert patched_data == EXPECTED_DATA


@pytest.mark.skipif_missing_deps([CramfsUnpacker, CramfsPacker])
class TestCramfsBigEndianUnpackModifyPack(UnpackModifyPackPattern):
    """
    Test case for unpacking, modifying, and repacking a big-endian CramFS filesystem.

    This test verifies that endianness is correctly detected during unpack and
    preserved through the repack cycle.
    """

    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        with tempfile.TemporaryDirectory() as tmpdir:
            entry_name = os.path.join(tmpdir, CRAMFS_ENTRY_NAME)
            target_file = os.path.join(tmpdir, TARGET_CRAMFS_FILE)

            with open(entry_name, "wb") as f:
                f.write(INITIAL_DATA)
            command = ["mkfs.cramfs", "-N", "big", tmpdir, target_file]
            subprocess.run(command, check=True, capture_output=True)
            return await ofrak_context.create_root_resource_from_file(target_file)

    async def unpack(self, cramfs_resource: Resource) -> None:
        await cramfs_resource.unpack_recursively()
        cramfs_view = await cramfs_resource.view_as(Cramfs)
        assert cramfs_view.endianness == Endianness.BIG_ENDIAN

    async def modify(self, unpacked_cramfs_resource: Resource) -> None:
        cramfs_v = await unpacked_cramfs_resource.view_as(Cramfs)
        child_text_string_config = StringPatchingConfig(6, "ofrak")
        child_textfile = await cramfs_v.get_entry(CRAMFS_ENTRY_NAME)
        await child_textfile.resource.run(StringPatchingModifier, child_text_string_config)

    async def repack(self, cramfs_resource: Resource) -> None:
        await cramfs_resource.pack_recursively()

    async def verify(self, repacked_cramfs_resource: Resource) -> None:
        data = await repacked_cramfs_resource.get_data(Range(0, 4))
        assert data == CRAMFS_MAGIC_BE, "Repacked CramFS image should be big-endian"

        async with repacked_cramfs_resource.temp_to_disk() as temp_path:
            with tempfile.TemporaryDirectory() as temp_parent:
                extract_dir = os.path.join(temp_parent, "cramfs_extract")
                command = ["fsck.cramfs", f"--extract={extract_dir}", temp_path]
                subprocess.run(command, check=True, capture_output=True)
                with open(os.path.join(extract_dir, CRAMFS_ENTRY_NAME), "rb") as f:
                    patched_data = f.read()
                assert patched_data == EXPECTED_DATA
