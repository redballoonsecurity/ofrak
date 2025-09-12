import os
import subprocess
import tempfile312 as tempfile

import pytest

from ofrak import OFRAKContext
from ofrak.resource import Resource
from ofrak.core.squashfs import SquashfsFilesystem, SquashfsPacker, SquashfsUnpacker
from ofrak.core.strings import StringPatchingConfig, StringPatchingModifier
from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern

INITIAL_DATA = b"hello world"
EXPECTED_DATA = b"hello ofrak"
TARGET_SQSH_FILE = "test.sqsh"
SQUASH_ENTRY_NAME = "hello_squash_file"


@pytest.mark.skipif_missing_deps([SquashfsUnpacker, SquashfsPacker])
class TestSquashfsUnpackModifyPack(UnpackModifyPackPattern):
    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        with tempfile.TemporaryDirectory() as tmpdir:
            entry_name = os.path.join(tmpdir, SQUASH_ENTRY_NAME)
            target_file = os.path.join(tmpdir, TARGET_SQSH_FILE)

            # Create a squashfs file from the current directory
            with open(entry_name, "wb") as f:
                f.write(INITIAL_DATA)
            command = ["mksquashfs", entry_name, target_file]
            subprocess.run(command, check=True, capture_output=True)
            return await ofrak_context.create_root_resource_from_file(target_file)

    async def unpack(self, squashfs_resource: Resource) -> None:
        await squashfs_resource.unpack_recursively()

    async def modify(self, unpacked_zip_resource: Resource) -> None:
        squashfs_v = await unpacked_zip_resource.view_as(SquashfsFilesystem)
        child_text_string_config = StringPatchingConfig(6, "ofrak")
        child_textfile = await squashfs_v.get_entry(SQUASH_ENTRY_NAME)
        await child_textfile.resource.run(StringPatchingModifier, child_text_string_config)

    async def repack(self, squashfs_resource: Resource) -> None:
        await squashfs_resource.pack_recursively()

    async def verify(self, repacked_squashfs_resource: Resource) -> None:
        async with repacked_squashfs_resource.temp_to_disk() as temp_path:
            with tempfile.TemporaryDirectory() as temp_flush_dir:
                command = ["unsquashfs", "-f", "-d", temp_flush_dir, temp_path]
                subprocess.run(command, check=True, capture_output=True)
                with open(os.path.join(temp_flush_dir, SQUASH_ENTRY_NAME), "rb") as f:
                    patched_data = f.read()
                assert patched_data == EXPECTED_DATA
