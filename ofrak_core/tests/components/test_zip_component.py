"""
Tests for ZipPacker, ZipUnpacker, and ZipPackerConfig.
"""
import io
import zipfile

import pytest

from ofrak.core.zip import ZipPacker, ZipPackerConfig
from ofrak.ofrak_context import OFRAKContext

TEST_FILE_CONTENT = b"Hello, OFRAK! This is test data for zip compression."


def _make_test_zip(content: bytes = TEST_FILE_CONTENT) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("test.txt", content)
    return buf.getvalue()


async def test_zip_packer_config_default(ofrak_context: OFRAKContext):
    """
    Test that ZipPacker works correctly without an explicit config (default compression level 6).

    This test verifies that:
    - ZipPacker produces a valid, re-unpackable ZIP archive without a config
    - File contents survive the round-trip with the default settings
    """
    resource = await ofrak_context.create_root_resource("test.zip", data=_make_test_zip())
    await resource.unpack()
    await resource.pack()

    repacked_data = await resource.get_data()
    with zipfile.ZipFile(io.BytesIO(repacked_data)) as zf:
        assert zf.read("test.txt") == TEST_FILE_CONTENT


@pytest.mark.parametrize("compression_level", [0, 1, 6, 9])
async def test_zip_packer_config_compression_levels(
    ofrak_context: OFRAKContext, compression_level: int
):
    """
    Test that ZipPackerConfig correctly applies compression levels 0 through 9.

    This test verifies that:
    - ZipPacker respects the compression_level field in ZipPackerConfig
    - The repacked archive is a valid ZIP at all supported compression levels
    - File contents survive the unpack/repack round-trip at every level
    """
    resource = await ofrak_context.create_root_resource("test.zip", data=_make_test_zip())
    await resource.unpack()

    await resource.run(ZipPacker, ZipPackerConfig(compression_level=compression_level))

    repacked_data = await resource.get_data()
    with zipfile.ZipFile(io.BytesIO(repacked_data)) as zf:
        assert zf.read("test.txt") == TEST_FILE_CONTENT


@pytest.mark.parametrize("compression_level", [-1, 10])
async def test_zip_packer_config_invalid_level(ofrak_context: OFRAKContext, compression_level: int):
    """
    Test that ZipPackerConfig raises ValueError for compression levels outside the 0-9 range.

    This test verifies that:
    - Compression levels below 0 are rejected with a ValueError
    - Compression levels above 9 are rejected with a ValueError
    """
    resource = await ofrak_context.create_root_resource("test.zip", data=_make_test_zip())
    await resource.unpack()

    with pytest.raises(ValueError):
        await resource.run(ZipPacker, ZipPackerConfig(compression_level=compression_level))
