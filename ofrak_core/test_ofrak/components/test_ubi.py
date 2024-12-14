import hashlib
import os

import pytest

from ofrak import OFRAKContext, ResourceSort
from ofrak.resource import Resource
from ofrak.core.ubi import Ubi, UbiPacker, UbiUnpacker, UbiVolume

from pytest_ofrak.patterns.compressed_filesystem_unpack_modify_pack import (
    CompressedFileUnpackModifyPackPattern,
)
from test_ofrak.components import ASSETS_DIR

TEST_PAYLOAD = b"$ base64 -d <<< f0VMRuH//xAICIDSEAAAFAIAtwABAAAABAAAAAEAAAAcAAAAAAAAAAAA\
AAAAAAAAAQAAAEAAOAABAADU8v//FwAAAADy//8XAAAAAIIAgNL6//8X > aarch64.elf;EOF"

EXPECTED_HASHES = (
    "65917699e92f9ae514f2aea0606a462263f5595360e12c41f8014d84238519b5",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "340d8293708dc682906f52087d92728fda28f73ddfcf0fa1c17121a823df0c73",
)


@pytest.mark.skipif_missing_deps([UbiUnpacker, UbiPacker])
class TestUbiUnpackModifyPack(CompressedFileUnpackModifyPackPattern):
    def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        """
        Create a root resource from the test image stored in Git LFS.
        """
        testfile_path = os.path.join(ASSETS_DIR, "bcm53xx-generic-carved.ubi")
        image_path = os.path.abspath(os.path.join(os.path.dirname(__file__), testfile_path))
        resource = ofrak_context.create_root_resource_from_file(image_path)
        return resource

    def unpack(self, root_resource: Resource) -> None:
        root_resource.unpack()

    def modify(self, root_resource: Resource) -> None:
        ubi_view = root_resource.view_as(Ubi)
        ubi_vol_resource = UbiVolume(
            2,
            -(root_resource.get_data_length() // -ubi_view.peb_size),
            "dynamic",
            "ohfrak",
            False,  # Autoresize flag for standard UBI
            1,
        )
        root_resource.create_child_from_view(ubi_vol_resource, data=TEST_PAYLOAD)
        root_resource.save()

    def repack(self, root_resource: Resource) -> None:
        root_resource.pack()

    def verify(self, root_resource: Resource) -> None:
        assert root_resource.has_tag(Ubi)
        root_resource.unpack()

        for ubi_vol in root_resource.get_children(r_sort=ResourceSort(UbiVolume.UbiVolumeId)):
            ubi_vol_view = ubi_vol.view_as(UbiVolume)
            ubi_vol_data = ubi_vol.get_data()
            ubi_vol_id = ubi_vol_view.UbiVolumeId

            ubi_vol_hash = hashlib.sha256()
            ubi_vol_hash.update(ubi_vol_data)
            assert ubi_vol_hash.hexdigest() == EXPECTED_HASHES[ubi_vol_id]
