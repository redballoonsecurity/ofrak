import os

import pytest
from _pytest._py.path import LocalPath

from ofrak.core.ubi import Ubi, UbiVolume
from ofrak_type import Range
from pytest_ofrak.patterns.compressed_filesystem_unpack_modify_pack import CompressedFileUnpackModifyPackPattern

from test_ofrak.components import ASSETS_DIR

from ofrak import OFRAKContext
from ofrak.resource import Resource

TEST_DATA = b"$ base64 -d <<< f0VMRuH//xAICIDSEAAAFAIAtwABAAAABAAAAAEAAAAcAAAAAAAAAAAA\
AAAAAAAAAQAAAEAAOAABAADU8v//FwAAAADy//8XAAAAAIIAgNL6//8X > aarch64.elf;EOF"

EXPECTED_OUTPUTS = [
    b'hsqs\x94\x04\x00\x00\x8dd\x13^\x00\x00\x04\x00\x15\x00\x00\x00\x04\x00\x12\x00\xc0\x06\x01\x00\x04\x00\x00\x00a\x17\xc4\x18\x00\x00\x00\x00\x020\x1c\x00\x00\x00\x00\x00\xfa/\x1c\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xffv\xdf\x1b\x00\x00\x00\x00\x00\xa8\xfd\x1b\x00\x00\x00\x00\x00\xf0)\x1c\x00\x00\x00\x00\x00\xe4/\x1c\x00\x00\x00\x00\x00\x0c\x80\x00\x00\x04\x00\x1c\x00\t\x00\x90\x00@\x00\xfd7zXZ\x00\x00\x01i"\xde6\x04\xc1\x9f\xe3\x06\x80\x80\x10\x07\x00!\x01\x0c\x00\x00\x00\x8e1\x91\xc6\xe2As\xef\xfel\x00?\x91E\x84`\x0e\xfcJV\xfc\xf5\xd4\x8a\x1d\xf8\xbb\xeb\xf6#\xbco\x0e\xf0\x136\xef7\xee\xbf\xc9\xbb\xe9\xfa\x9cP\x92\x1c\xf2N\xac\xf3\x03*\xbd\x95%cu|\x82|\x96\xb2\x1e\xb3t\x98.\xe9\x13?\xec:\xcfr(\xe09Q;<\xd9\xda\x8a\x1b\xfe\xc2d\nKn\xce\xa6&\x11C\x86\x8e\x1c\xa8U\x7f\x8d\xed\xabx\xd6j\xbb\xa0\xc0\x91\x9a\xcb\'B\x0b',
    b'',
    b'$ base64 -d <<< f0VMRuH//xAICIDSEAAAFAIAtwABAAAABAAAAAEAAAAcAAAAAAAAAAAAAAAAAAAAAQAAAEAAOAABAADU8v//FwAAAADy//8XAAAAAIIAgNL6//8X > aarch64.elf;EOF\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
]
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
        await root_resource.unpack()

    async def modify(self, root_resource: Resource) -> None:
        ubi_view = await root_resource.view_as(Ubi)
        ubi_vol_resource = UbiVolume(
            2,
            (await root_resource.get_data_length() // ubi_view.peb_size),
            'dynamic',
            "ohfrak",
            False,  # Autoresize flag for standard UBI
            1
        )
        await root_resource.create_child_from_view(
            ubi_vol_resource,
            data=TEST_DATA
        )
        await root_resource.save()

    async def repack(self, root_resource: Resource) -> None:
        await root_resource.pack()

    async def verify(self, root_resource: Resource) -> None:
        assert root_resource.has_tag(Ubi)
        await root_resource.unpack()
        tree = await root_resource.summarize_tree()

        for child in await root_resource.get_children():
            if not (await child.get_data()) in EXPECTED_OUTPUTS:
                print("Not in EXPECTED OUTPUTS")


        print()
