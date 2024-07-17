import subprocess
from ofrak import tempfile

from ofrak import OFRAKContext
from ofrak.resource import Resource
from pytest_ofrak.patterns.pack_unpack_filesystem import FilesystemPackUnpackVerifyPattern

# from pytest_ofrak.patterns.unpack_modify_pack import UnpackPackPattern


class TestUbifsUnpackRepack(FilesystemPackUnpackVerifyPattern):
    def setup(self):
        super().setup()
        # Don't compare stat values since several entries (like time modified and inode number) will be unequal
        self.check_stat = False

    async def create_root_resource(self, ofrak_context: OFRAKContext, directory: str) -> Resource:
        """
        Generated the test UBIFS image with the assistance of the FilesystemPackUnpackVerify test pattern.
        """
        with tempfile.NamedTemporaryFile() as ubifs_blob:
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

        with tempfile.NamedTemporaryFile() as ubifs_blob:
            data = await root_resource.get_data()
            ubifs_blob.write(data)
            ubifs_blob.close()

            command = ["ubireader_extract_files", "-k", "-o", extract_dir, ubifs_blob.name]

            subprocess.run(command, check=True, capture_output=True)
