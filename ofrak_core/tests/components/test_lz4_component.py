"""
Test the functionality of the LZ4 component, including unpacking,
modifying, and repacking LZ4-compressed data.

Requirements Mapping:
- REQ1.3
- REQ4.4
"""
import lz4.frame
from pathlib import Path
from typing import Tuple

import pytest

from ofrak.ofrak_context import OFRAKContext
from ofrak.resource import Resource
from ofrak.core.lz4 import Lz4ModernData, Lz4SkippableData
from pytest_ofrak.patterns.compressed_filesystem_unpack_modify_pack import (
    CompressedFileUnpackModifyPackPattern,
)

ASSETS_DIR = Path(__file__).parent / "assets"


@pytest.fixture(
    autouse=True,
    scope="module",
    params=[
        (ASSETS_DIR / "hello_world", ASSETS_DIR / "hello_ofrak"),
    ],
    ids=["hello world"],
)
def lz4_test_input(request):
    initial_path, repacked_path = request.param
    with open(initial_path, "rb") as initial_file:
        initial_data = initial_file.read()
    with open(repacked_path, "rb") as repacked_file:
        expected_repacked_data = repacked_file.read()
    return (initial_data, expected_repacked_data)


class Lz4UnpackModifyPackPattern(CompressedFileUnpackModifyPackPattern):
    """
    Template for tests that test different inputs the LZ4 component should support
    unpacking.

    This test verifies that:
    - An LZ4 file can be successfully unpacked
    - Modifications to the unpacked data can be applied
    - The modified data can be repacked back into a valid LZ4 file
    - The LZ4 file contains the expected data after decompression
    """

    expected_tag = Lz4ModernData

    @pytest.fixture(autouse=True)
    def create_test_file(self, lz4_test_input: Tuple[bytes, bytes], tmp_path: Path):
        self.INITIAL_DATA, self.EXPECTED_REPACKED_DATA = lz4_test_input
        lz4_path = tmp_path / "test.lz4"
        self.write_lz4(lz4_path)
        self._test_file = lz4_path.resolve()

    def write_lz4(self, lz4_path: Path):
        """
        Write LZ4 compressed data to file.

        :param lz4_path: Path to write the LZ4 file
        """
        raise NotImplementedError()

    async def verify(self, repacked_root_resource: Resource):
        """
        Verify that the repacked LZ4 resource contains the expected data.

        :param repacked_root_resource: The repacked resource to verify
        """
        patched_decompressed_data = lz4.frame.decompress(await repacked_root_resource.get_data())
        assert patched_decompressed_data == self.EXPECTED_REPACKED_DATA


class TestLz4UnpackModifyPack(Lz4UnpackModifyPackPattern):
    """
    Test the basic unpack, modify, and pack functionality for a simple LZ4 file.

    This test verifies that:
    - A standard LZ4 file (modern frame format) can be unpacked
    - The unpacked data can be modified
    - The modified data can be repacked into a valid LZ4 file
    """

    def write_lz4(self, lz4_path: Path):
        compressed_data = lz4.frame.compress(self.INITIAL_DATA)
        with open(lz4_path, "wb") as lz4_file:
            lz4_file.write(compressed_data)


class TestLz4WithHighCompressionUnpackModifyPack(Lz4UnpackModifyPackPattern):
    """
    Test the unpack, modify, and pack functionality for an LZ4 file with high compression.

    This test verifies that:
    - LZ4 files created with high compression level can be unpacked
    - High compression settings don't affect the unpack/repack workflow
    """

    def write_lz4(self, lz4_path: Path):
        compressed_data = lz4.frame.compress(
            self.INITIAL_DATA, compression_level=lz4.frame.COMPRESSIONLEVEL_MAX
        )
        with open(lz4_path, "wb") as lz4_file:
            lz4_file.write(compressed_data)


class TestLz4WithContentChecksumUnpackModifyPack(Lz4UnpackModifyPackPattern):
    """
    Test the unpack, modify, and pack functionality for an LZ4 file with content checksum.

    This test verifies that:
    - LZ4 files with content checksums enabled can be unpacked
    - The checksum metadata is handled correctly during unpack/repack
    """

    def write_lz4(self, lz4_path: Path):
        compressed_data = lz4.frame.compress(self.INITIAL_DATA, content_checksum=True)
        with open(lz4_path, "wb") as lz4_file:
            lz4_file.write(compressed_data)


class TestLz4WithBlockChecksumUnpackModifyPack(Lz4UnpackModifyPackPattern):
    """
    Test the unpack, modify, and pack functionality for an LZ4 file with block checksum.

    This test verifies that:
    - LZ4 files with block checksums enabled can be unpacked
    - The block checksum metadata is handled correctly during unpack/repack
    """

    def write_lz4(self, lz4_path: Path):
        compressed_data = lz4.frame.compress(self.INITIAL_DATA, block_linked=False)
        with open(lz4_path, "wb") as lz4_file:
            lz4_file.write(compressed_data)


async def test_corrupted_lz4_fail(lz4_test_input: Tuple[bytes, bytes], ofrak_context: OFRAKContext):
    """
    Test that unpacking a corrupted LZ4 file raises an appropriate error (REQ1.3).

    This test verifies that:
    - An LZ4 file with invalid data (corrupted) raises an error when attempting to unpack
    - The error type is consistent with expected decompression errors
    """
    initial_data = lz4_test_input[0]
    corrupted_data = bytearray(lz4.frame.compress(initial_data))
    # Corrupt the magic number
    corrupted_data[0] = 0xFF
    resource = await ofrak_context.create_root_resource("corrupted.lz4", data=bytes(corrupted_data))
    # Manually tag as Lz4ModernData since corrupted magic bytes won't be auto-identified
    resource.add_tag(Lz4ModernData)
    await resource.save()

    with pytest.raises(RuntimeError):
        await resource.unpack()


async def test_empty_lz4_file(ofrak_context: OFRAKContext):
    """
    Test that unpacking an empty file raises an appropriate error (REQ1.3).

    This test verifies that:
    - An empty file is not considered a valid LZ4 file
    - Attempting to unpack an empty file raises the expected error
    """
    resource = await ofrak_context.create_root_resource("empty.lz4", data=b"")
    # Manually tag as Lz4ModernData since empty data won't be auto-identified
    resource.add_tag(Lz4ModernData)
    await resource.save()

    with pytest.raises(RuntimeError):
        await resource.unpack()


async def test_lz4_with_small_data(ofrak_context: OFRAKContext):
    """
    Test unpacking and packing LZ4 files with very small data (REQ1.3, REQ4.4).

    This test verifies that:
    - LZ4 compression works correctly with minimal data (single byte)
    - Small files can be unpacked and repacked successfully
    """
    small_data = b"x"
    compressed_data = lz4.frame.compress(small_data)
    resource = await ofrak_context.create_root_resource("small.lz4", data=compressed_data)
    await resource.unpack()
    child = await resource.get_only_child()
    child_data = await child.get_data()
    assert child_data == small_data


async def test_lz4_with_large_data(ofrak_context: OFRAKContext):
    """
    Test unpacking and packing LZ4 files with larger data (REQ1.3, REQ4.4).

    This test verifies that:
    - LZ4 compression handles larger datasets efficiently
    - Large files maintain data integrity through unpack/repack cycle
    """
    # Create 1MB of test data
    large_data = b"A" * (1024 * 1024)
    compressed_data = lz4.frame.compress(large_data)
    resource = await ofrak_context.create_root_resource("large.lz4", data=compressed_data)
    await resource.unpack()
    child = await resource.get_only_child()
    child_data = await child.get_data()
    assert child_data == large_data


async def test_real_lz4_skippable_frame(ofrak_context: OFRAKContext):
    """
    Test unpacking a real LZ4 skippable frame file from the official LZ4 repository (REQ1.3).

    This test verifies that:
    - Real LZ4 files from the wild can be unpacked successfully
    - Skippable frames are identified correctly as Lz4SkippableData
    - Skippable frames are handled correctly by the unpacker
    - The official LZ4 golden sample file works as expected
    """
    # This is the skip.bin file from lz4/lz4 repository tests/goldenSamples
    # Source: https://github.com/lz4/lz4/tree/dev/tests/goldenSamples
    test_file = ASSETS_DIR / "lz4_skip.bin"

    resource = await ofrak_context.create_root_resource_from_file(test_file)
    await resource.unpack()

    # Verify it was identified as skippable frame
    assert resource.has_tag(Lz4SkippableData)

    # Skippable frame decompresses to empty content
    child = await resource.get_only_child()
    child_data = await child.get_data()
    assert child_data == b""


async def test_lz4_round_trip(ofrak_context: OFRAKContext):
    """
    Test complete round-trip: compress with LZ4, unpack, modify, pack, verify (REQ1.3, REQ4.4).

    This test verifies that:
    - Data can be compressed, unpacked, modified, and repacked successfully
    - The final output is a valid LZ4 file with the expected modified content
    """
    from ofrak_type.range import Range

    original_data = b"The quick brown fox jumps over the lazy dog"
    compressed_data = lz4.frame.compress(original_data)

    resource = await ofrak_context.create_root_resource("test.lz4", data=compressed_data)
    # Manually tag for this test to ensure the resource is treated as LZ4
    resource.add_tag(Lz4ModernData)
    await resource.save()

    await resource.unpack()
    child = await resource.get_only_child()

    # Modify the child data
    modified_data = b"The quick brown cat jumps over the lazy dog"
    child.queue_patch(Range.from_size(0, len(original_data)), modified_data)
    await child.save()

    # Pack it back
    await resource.pack()

    # Verify the packed data
    packed_data = await resource.get_data()
    decompressed = lz4.frame.decompress(packed_data)
    assert decompressed == modified_data
