"""
Test the functionality of the UBIFS filesystem component.

Requirements Mapping:
- REQ1.3
- REQ4.4
"""
import subprocess
import tempfile312 as tempfile

import pytest

from ofrak import OFRAKContext
from ofrak.core.ubifs import UbifsPacker, UbifsUnpacker
from ofrak.resource import Resource
from pytest_ofrak.patterns.pack_unpack_filesystem import FilesystemPackUnpackVerifyPattern


@pytest.mark.skipif_missing_deps([UbifsUnpacker, UbifsPacker])
class TestUbifsUnpackRepack(FilesystemPackUnpackVerifyPattern):
    """
    Test that UBIFS filesystems can be properly unpacked and repacked.

    This test verifies that:
    - A UBIFS image can be created from a directory of files
    - The UBIFS image can be unpacked into its constituent files
    - The unpacked files can be repacked back into a valid UBIFS image
    - The repacked image produces the same file structure as the original
    """

    def setup(self):
        super().setup()
        # Don't compare stat values since several entries (like time modified and inode number) will be unequal
        self.check_stat = False

    async def create_root_resource(self, ofrak_context: OFRAKContext, directory: str) -> Resource:
        """
        Generated the test UBIFS image with the assistance of the FilesystemPackUnpackVerify test pattern.
        """
        with tempfile.NamedTemporaryFile(delete_on_close=False) as ubifs_blob:
            ubifs_blob.close()
            command = [
                "mkfs.ubifs",
                "-m",
                "512",
                "-e",
                "128KiB",
                "-c",
                "100",
                "-r",
                directory,
                ubifs_blob.name,
            ]
            subprocess.run(command, check=True, capture_output=True)
            return await ofrak_context.create_root_resource_from_file(ubifs_blob.name)

    async def unpack(self, root_resource: Resource) -> None:
        await root_resource.unpack()

    async def repack(self, root_resource: Resource) -> None:
        await root_resource.pack()

    async def extract(self, root_resource: Resource, extract_dir: str) -> None:
        """
        Use 'ubireader' to extract the generated test UBIFS image into a directory and compare its contents with those
        expected by the FilesystemPackUnpackVerify pattern.
        """

        async with root_resource.temp_to_disk() as ubifs_blob_path:
            command = ["ubireader_extract_files", "-k", "-o", extract_dir, ubifs_blob_path]

            subprocess.run(command, check=True, capture_output=True)
