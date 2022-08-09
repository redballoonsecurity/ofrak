import os
import subprocess

import pytest

from ofrak import OFRAKContext
from ofrak.resource import Resource
from ofrak_components.uimage import (
    UImage,
    UImageHeaderModifierConfig,
    UImageHeaderModifier,
)
import test_ofrak.components

NEW_UIMAGE_NAME = "new image name"
UIMAGE_TESTFILE_PATHS = [
    "./uimage",
    "./uimage_zimage",
    # From https://github.com/HerXtheSlayer/uImage_builder/blob/master/ZT280_C91-3a
    "./uimage_nested",
    # From https://github.com/HerXtheSlayer/uImage_builder/tree/master/YDP-G18-v1
    "./uimage_lzma",
    "./uimage_multi",
]


@pytest.mark.parametrize("test_case", UIMAGE_TESTFILE_PATHS)
async def test_uimage_unpack_modify_pack(test_case, ofrak_context, tmpdir):
    """Test unpacking, modifying and then repacking a UImage file."""
    root_resource = await create_root_resource(ofrak_context, test_case)
    await root_resource.unpack_recursively()
    await modify(root_resource)
    await root_resource.pack_recursively()
    await verify(root_resource, tmpdir)


async def create_root_resource(ofrak_context: OFRAKContext, path) -> Resource:
    """
    Create a root resource from the test image stored in Git LFS. The test image was created by
    doing the following command on a Linux system:
            mkimage -C none -n "old image name" -d /bin/bash ./assets/uimage
    """
    uimage_path = os.path.join(test_ofrak.components.ASSETS_DIR, path)
    return await ofrak_context.create_root_resource_from_file(uimage_path)


async def modify(unpacked_root_resource: Resource) -> None:
    uimage = await unpacked_root_resource.view_as(UImage)
    header = await uimage.get_header()
    header_modifier_config = UImageHeaderModifierConfig(
        ih_name=bytes(NEW_UIMAGE_NAME, encoding="ASCII")
    )
    await header.resource.run(UImageHeaderModifier, header_modifier_config)


async def verify(repacked_root_resource: Resource, tmpdir) -> None:
    """
    Verify the integrity of the UImage using mkimage -l.

    mkimage -l will fail (return a different output) if:

    - the header CRC is incorrect
    - the data CRC is incorrect
    - the data size is incorrect
    """
    resource_data = await repacked_root_resource.get_data()
    repacked_uimage_file = tmpdir / "repacked_uimage"
    with open(repacked_uimage_file, "wb") as f:
        f.write(resource_data)
        f.flush()
    mkimage_verify_cmd = ["mkimage", "-l", repacked_uimage_file]
    stdout = subprocess.run(mkimage_verify_cmd, check=True, capture_output=True).stdout.decode(
        "utf-8"
    )
    assert f"Image Name:   {NEW_UIMAGE_NAME}" in stdout, stdout
