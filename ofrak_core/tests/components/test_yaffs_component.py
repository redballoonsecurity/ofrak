import os
import subprocess
import tempfile312 as tempfile
from pathlib import Path

import pytest

from ofrak import OFRAKContext
from ofrak.resource import Resource
from ofrak.core.strings import StringPatchingConfig, StringPatchingModifier
from ofrak.core.yaffs import (
    Yaffs2Filesystem,
    Yaffs2FilesystemAttributes,
    Yaffs2Packer,
    Yaffs2Unpacker,
)
from ofrak_type.endianness import Endianness
from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern

from .. import components

ASSETS_DIR = Path(components.ASSETS_DIR)

# Contents of the pre-built YAFFS2 test images (see tests/components/assets/).
MODIFY_TARGET = "hello.txt"
INITIAL_DATA = b"Hello YAFFS2\n"
EXPECTED_DATA = b"Hello ofrak!\n"


@pytest.mark.skipif_missing_deps([Yaffs2Unpacker, Yaffs2Packer])
@pytest.mark.parametrize(
    "asset,page_size,spare_size,endian",
    [
        ("yaffs2_2k_64_le.img", 2048, 64, Endianness.LITTLE_ENDIAN),
        ("yaffs2_4k_128_le.img", 4096, 128, Endianness.LITTLE_ENDIAN),
        ("yaffs2_2k_64_be.img", 2048, 64, Endianness.BIG_ENDIAN),
    ],
)
class TestYaffs2UnpackModifyPack(UnpackModifyPackPattern):
    """
    Unpack a real YAFFS2 image, modify a contained file, repack, and verify the
    result by extracting it again with `unyaffs2`.
    """

    @pytest.fixture(autouse=True)
    def _params(self, asset, page_size, spare_size, endian):
        self.asset = asset
        self.page_size = page_size
        self.spare_size = spare_size
        self.endian = endian

    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        return await ofrak_context.create_root_resource_from_file(str(ASSETS_DIR / self.asset))

    async def unpack(self, root_resource: Resource) -> None:
        await root_resource.identify()
        assert root_resource.has_tag(Yaffs2Filesystem)
        attrs = root_resource.get_attributes(Yaffs2FilesystemAttributes)
        assert attrs.page_size == self.page_size
        assert attrs.spare_size == self.spare_size
        assert attrs.endian == self.endian
        await root_resource.unpack_recursively()

    async def modify(self, unpacked_root_resource: Resource) -> None:
        view = await unpacked_root_resource.view_as(Yaffs2Filesystem)
        entry = await view.get_entry(MODIFY_TARGET)
        # Patch "YAFFS2\n" -> "ofrak!\n" (same length, 7 bytes) starting at offset 6.
        await entry.resource.run(StringPatchingModifier, StringPatchingConfig(6, "ofrak!\n"))

    async def repack(self, modified_root_resource: Resource) -> None:
        await modified_root_resource.pack_recursively()

    async def verify(self, repacked_root_resource: Resource) -> None:
        async with repacked_root_resource.temp_to_disk() as temp_path:
            with tempfile.TemporaryDirectory() as temp_flush_dir:
                cmd = [
                    "unyaffs2",
                    "-p",
                    str(self.page_size),
                    "-s",
                    str(self.spare_size),
                ]
                if self.endian == Endianness.BIG_ENDIAN:
                    cmd.append("-e")
                cmd += [temp_path, temp_flush_dir]
                subprocess.run(cmd, check=True, capture_output=True)
                with open(os.path.join(temp_flush_dir, MODIFY_TARGET), "rb") as f:
                    assert f.read() == EXPECTED_DATA


ASSETS_DIR = Path(components.ASSETS_DIR)


@pytest.fixture(
    params=[
        "yaffs2_2k_64_le.img",
        "yaffs2_4k_128_le.img",
        "yaffs2_2k_64_be.img",
    ]
)
def yaffs2_asset(request):
    return request.param


async def test_yaffs2_identify(ofrak_context: OFRAKContext, yaffs2_asset: str) -> None:
    """
    Valid YAFFS2 images are tagged as Yaffs2Filesystem.
    """
    asset_path = ASSETS_DIR / yaffs2_asset
    resource = await ofrak_context.create_root_resource_from_file(str(asset_path))
    await resource.identify()
    assert resource.has_tag(
        Yaffs2Filesystem
    ), f"Expected {yaffs2_asset} to be identified as Yaffs2Filesystem"


async def test_yaffs2_not_identified_for_small_data(ofrak_context: OFRAKContext) -> None:
    """
    Data too small to be YAFFS2 should not be identified.
    """
    resource = await ofrak_context.create_root_resource("tiny", b"\x03\x00\x00\x00\x01")
    await resource.identify()
    assert not resource.has_tag(Yaffs2Filesystem)


async def test_yaffs2_not_identified_for_partial_magic(ofrak_context: OFRAKContext) -> None:
    """
    Data with valid header magic but no valid spare area should not be identified.
    """
    data = b"\x03\x00\x00\x00\x01\x00\x00\x00\xff\xff" + b"\x00" * 40000
    resource = await ofrak_context.create_root_resource("partial_magic", data)
    await resource.identify()
    assert not resource.has_tag(Yaffs2Filesystem)
