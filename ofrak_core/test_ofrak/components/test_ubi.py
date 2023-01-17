import os

import pytest
from _pytest._py.path import LocalPath

from ofrak.core.ubi import Ubi
from pytest_ofrak.patterns.compressed_filesystem_unpack_modify_pack import CompressedFileUnpackModifyPackPattern

from test_ofrak.components import ASSETS_DIR

from ofrak import OFRAKContext
from ofrak.resource import Resource


class TestUbiUnpackModifyPack(CompressedFileUnpackModifyPackPattern):
    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        """
        Create a root resource from the test image stored in Git LFS.
        """
        testfile_path = os.path.join(
            ASSETS_DIR, "bcm53xx-generic-carved.ubi"
        )
        image_path = os.path.abspath(os.path.join(os.path.dirname(__file__), testfile_path))
        resource = await ofrak_context.create_root_resource_from_file(image_path)
        return resource

    async def unpack(self, root_resource: Resource) -> None:
        await root_resource.unpack_recursively()

    async def modify(self, unpacked_uf2_resource: Resource) -> None:
        pass

    async def repack(self, root_resource: Resource) -> None:
        await root_resource.pack()

    async def verify(self, root_resource: Resource) -> None:
        """

        with tempfile.NamedTemporaryFile() as ubi_blob:
            data = await root_resource.get_data()
            ubi_blob.write(data)
            ubi_blob.flush()

            #command = ["ubireader_extract_files", "-k", "-o", extract_dir, ubi_blob.name]

            subprocess.run(command, check=True, capture_output=True)
        """
        print("Root resource:")
        print(await root_resource.summarize_tree())
        print("---")
        assert root_resource.has_tag(Ubi)
