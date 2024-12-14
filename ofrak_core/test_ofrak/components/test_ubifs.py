import subprocess
import tempfile

import pytest

from ofrak import OFRAKContext
from ofrak.core.ubifs import UbifsPacker, UbifsUnpacker
from ofrak.resource import Resource
from pytest_ofrak.patterns.pack_unpack_filesystem import FilesystemPackUnpackVerifyPattern

# from pytest_ofrak.patterns.unpack_modify_pack import UnpackPackPattern


@pytest.mark.skipif_missing_deps([UbifsUnpacker, UbifsPacker])
class TestUbifsUnpackRepack(FilesystemPackUnpackVerifyPattern):
    def setup(self):
        super().setup()
        # Don't compare stat values since several entries (like time modified and inode number) will be unequal
        self.check_stat = False

    def create_root_resource(self, ofrak_context: OFRAKContext, directory: str) -> Resource:
        """
        Generated the test UBIFS image with the assistance of the FilesystemPackUnpackVerify test pattern.
        """
        with tempfile.NamedTemporaryFile() as ubifs_blob:
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
            return ofrak_context.create_root_resource_from_file(ubifs_blob.name)

    def unpack(self, root_resource: Resource) -> None:
        root_resource.unpack()

    def repack(self, root_resource: Resource) -> None:
        root_resource.pack()

    def extract(self, root_resource: Resource, extract_dir: str) -> None:
        """
        Use 'ubireader' to extract the generated test UBIFS image into a directory and compare its contents with those
        expected by the FilesystemPackUnpackVerify pattern.
        """

        with tempfile.NamedTemporaryFile() as ubifs_blob:
            data = root_resource.get_data()
            ubifs_blob.write(data)
            ubifs_blob.flush()

            command = ["ubireader_extract_files", "-k", "-o", extract_dir, ubifs_blob.name]

            subprocess.run(command, check=True, capture_output=True)
