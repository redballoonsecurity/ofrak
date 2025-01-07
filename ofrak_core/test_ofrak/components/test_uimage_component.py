import os
import subprocess
import shutil

import pytest

from ofrak import OFRAKContext
from ofrak.core import ProgramAttributes
from ofrak.resource import Resource
from ofrak.core.uimage import (
    UImage,
    UImageHeaderModifierConfig,
    UImageHeaderModifier,
    UImageOperatingSystem,
    UImageArch,
    UImageCompressionType,
    UImageType,
    UImageMultiHeader,
)
import test_ofrak.components
from ofrak_type.error import NotFoundError

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


@pytest.fixture(params=UIMAGE_TESTFILE_PATHS)
async def uimage_resource(ofrak_context, request) -> Resource:
    uimage_path = os.path.join(test_ofrak.components.ASSETS_DIR, request.param)
    return await ofrak_context.create_root_resource_from_file(uimage_path)


@pytest.mark.skipif(
    shutil.which("mkimage") is None, reason="Test requires mkimage from u-boot-tools"
)
async def test_uimage_unpack_modify_pack(uimage_resource: Resource, tmpdir):
    """Test unpacking, modifying and then repacking a UImage file."""
    await uimage_resource.unpack_recursively()
    await modify(uimage_resource)
    await uimage_resource.pack_recursively()
    await verify(uimage_resource, tmpdir)


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


async def test_uimage_header(uimage_resource: Resource) -> None:
    """
    Test that UImageHeader and UImageMultiHeader methods return expected types.
    """
    await uimage_resource.unpack()
    uimage = await uimage_resource.view_as(UImage)
    header = await uimage.get_header()
    assert isinstance(header.get_os(), UImageOperatingSystem)
    assert isinstance(header.get_arch(), UImageArch)
    assert isinstance(header.get_compression_type(), UImageCompressionType)
    assert isinstance(header.get_type(), UImageType)
    assert isinstance(header.get_name(), str)
    assert isinstance(header.get_data_size(), int)
    assert isinstance(header.get_load_vaddr(), int)
    assert isinstance(header.get_entry_point_vaddr(), int)

    header_type = header.get_type()
    if header_type is UImageType.MULTI:
        multi_header = await uimage.get_multi_header()
        assert isinstance(multi_header, UImageMultiHeader)
        assert isinstance(multi_header.get_number_of_bodies(), int)
        assert all([isinstance(size, int) for size in multi_header.get_image_sizes()])
    else:
        with pytest.raises(NotFoundError):
            _ = await uimage.get_multi_header()


async def test_uimage_program_attributes_analzyer(uimage_resource: Resource) -> None:
    """
    Test that UImageProgramAttributesAnalyzer returns ProgramAttributes.
    """
    await uimage_resource.unpack()
    program_attributes = await uimage_resource.analyze(ProgramAttributes)
    assert isinstance(program_attributes, ProgramAttributes)
