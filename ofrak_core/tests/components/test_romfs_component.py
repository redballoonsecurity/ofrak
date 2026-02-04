"""
Test the RomFS filesystem component functionality.

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
from ofrak.core.romfs import RomfsFilesystem, RomfsPacker, RomfsUnpacker
from ofrak.core.strings import StringPatchingConfig, StringPatchingModifier
from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern

INITIAL_DATA = b"hello world"
EXPECTED_DATA = b"hello ofrak"
TARGET_ROMFS_FILE = "test.romfs"
ROMFS_ENTRY_NAME = "hello_romfs_file"


@pytest.mark.skipif_missing_deps([RomfsUnpacker, RomfsPacker])
class TestRomfsUnpackModifyPack(UnpackModifyPackPattern):
    """
    Test that a RomFS image can be unpacked, modified, and repacked correctly.

    This test verifies that:
    - A RomFS image can be created from a temporary directory
    - The image can be unpacked recursively
    - A file inside the image can be modified
    - The image can be repacked
    - The resulting image contains the expected modified data
    """

    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        with tempfile.TemporaryDirectory() as tmpdir:
            entry_name = os.path.join(tmpdir, ROMFS_ENTRY_NAME)
            target_file = os.path.join(tmpdir, TARGET_ROMFS_FILE)

            with open(entry_name, "wb") as f:
                f.write(INITIAL_DATA)

            command = ["genromfs", "-f", target_file, "-d", tmpdir]
            subprocess.run(command, check=True, capture_output=True)
            return await ofrak_context.create_root_resource_from_file(target_file)

    async def unpack(self, romfs_resource: Resource) -> None:
        await romfs_resource.unpack_recursively()

    async def modify(self, unpacked_romfs_resource: Resource) -> None:
        romfs_v = await unpacked_romfs_resource.view_as(RomfsFilesystem)
        child_text_string_config = StringPatchingConfig(6, "ofrak")
        child_textfile = await romfs_v.get_entry(ROMFS_ENTRY_NAME)
        await child_textfile.resource.run(StringPatchingModifier, child_text_string_config)

    async def repack(self, romfs_resource: Resource) -> None:
        await romfs_resource.pack_recursively()

    async def verify(self, repacked_romfs_resource: Resource) -> None:
        repacked_data = await repacked_romfs_resource.get_data()
        # Verify that the repacked data is a valid RomFS image
        assert repacked_data[:8] == b"-rom1fs-", "Repacked data is not a valid RomFS image"

        # Extract the repacked image and check the modified file
        with tempfile.TemporaryDirectory() as temp_flush_dir:
            romfs_path = os.path.join(temp_flush_dir, "repacked.romfs")
            with open(romfs_path, "wb") as f:
                f.write(repacked_data)

            extract_dir = os.path.join(temp_flush_dir, "extracted")
            os.makedirs(extract_dir)

            # Use the unpacker's Python parser to extract and verify
            from ofrak.core.romfs import _extract_romfs

            _extract_romfs(repacked_data, extract_dir)

            with open(os.path.join(extract_dir, ROMFS_ENTRY_NAME), "rb") as f:
                patched_data = f.read()
            assert patched_data == EXPECTED_DATA


@pytest.mark.skipif_missing_deps([RomfsUnpacker, RomfsPacker])
class TestRomfsWithSubdirectories(UnpackModifyPackPattern):
    """
    Test RomFS handling with nested directory structures.

    This test verifies that:
    - RomFS images with subdirectories can be unpacked correctly
    - Files in subdirectories can be modified
    - The directory structure is preserved after repacking
    """

    SUBDIR_FILE_DATA = b"nested world here"
    SUBDIR_EXPECTED_DATA = b"nested ofrak here"

    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        with tempfile.TemporaryDirectory() as tmpdir:
            content_dir = os.path.join(tmpdir, "content")
            os.makedirs(content_dir)

            # Create a file in the root
            with open(os.path.join(content_dir, "root_file.txt"), "wb") as f:
                f.write(b"root data")

            # Create a subdirectory with a file
            subdir = os.path.join(content_dir, "subdir")
            os.makedirs(subdir)
            with open(os.path.join(subdir, "nested_file.txt"), "wb") as f:
                f.write(self.SUBDIR_FILE_DATA)

            target_file = os.path.join(tmpdir, "test_subdirs.romfs")
            command = ["genromfs", "-f", target_file, "-d", content_dir]
            subprocess.run(command, check=True, capture_output=True)
            return await ofrak_context.create_root_resource_from_file(target_file)

    async def unpack(self, romfs_resource: Resource) -> None:
        await romfs_resource.unpack_recursively()

    async def modify(self, unpacked_romfs_resource: Resource) -> None:
        romfs_v = await unpacked_romfs_resource.view_as(RomfsFilesystem)
        child_text_string_config = StringPatchingConfig(7, "ofrak")
        child_textfile = await romfs_v.get_entry("subdir/nested_file.txt")
        await child_textfile.resource.run(StringPatchingModifier, child_text_string_config)

    async def repack(self, romfs_resource: Resource) -> None:
        await romfs_resource.pack_recursively()

    async def verify(self, repacked_romfs_resource: Resource) -> None:
        repacked_data = await repacked_romfs_resource.get_data()
        assert repacked_data[:8] == b"-rom1fs-"

        with tempfile.TemporaryDirectory() as temp_dir:
            from ofrak.core.romfs import _extract_romfs

            _extract_romfs(repacked_data, temp_dir)

            # Verify the nested file was modified
            with open(os.path.join(temp_dir, "subdir", "nested_file.txt"), "rb") as f:
                patched_data = f.read()
            assert patched_data == self.SUBDIR_EXPECTED_DATA

            # Verify the root file still exists unchanged
            with open(os.path.join(temp_dir, "root_file.txt"), "rb") as f:
                root_data = f.read()
            assert root_data == b"root data"


@pytest.mark.skipif_missing_deps([RomfsUnpacker])
class TestRomfsUnpackOnly:
    """
    Test RomFS unpacking without requiring the packer (no genromfs dependency).
    """

    async def test_unpack_simple(self, ofrak_context: OFRAKContext) -> None:
        """
        Test unpacking a RomFS image with a single file.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            entry_name = os.path.join(tmpdir, "test.txt")
            with open(entry_name, "wb") as f:
                f.write(b"sample text")

            target_file = os.path.join(tmpdir, "simple.romfs")
            subprocess.run(
                ["genromfs", "-f", target_file, "-d", tmpdir],
                check=True,
                capture_output=True,
            )

            root_resource = await ofrak_context.create_root_resource_from_file(target_file)
            await root_resource.unpack_recursively()

            romfs_v = await root_resource.view_as(RomfsFilesystem)
            entry = await romfs_v.get_entry("test.txt")
            assert entry is not None
            entry_data = await entry.resource.get_data()
            assert entry_data == b"sample text"

    async def test_unpack_empty_dir(self, ofrak_context: OFRAKContext) -> None:
        """
        Test unpacking a RomFS image that contains an empty subdirectory.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            content_dir = os.path.join(tmpdir, "content")
            os.makedirs(os.path.join(content_dir, "empty_dir"))

            target_file = os.path.join(tmpdir, "empty_dir.romfs")
            subprocess.run(
                ["genromfs", "-f", target_file, "-d", content_dir],
                check=True,
                capture_output=True,
            )

            root_resource = await ofrak_context.create_root_resource_from_file(target_file)
            await root_resource.unpack_recursively()

            romfs_v = await root_resource.view_as(RomfsFilesystem)
            entry = await romfs_v.get_entry("empty_dir")
            assert entry is not None
            assert entry.is_folder()

    async def test_invalid_magic(self, ofrak_context: OFRAKContext) -> None:
        """
        Test that unpacking fails with a clear error for non-RomFS data.
        """
        from ofrak.core.romfs import _extract_romfs

        with pytest.raises(ValueError, match="bad magic"):
            _extract_romfs(b"not a romfs image", "/tmp")
