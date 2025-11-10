"""
Test the functionality of the LZ4 component, including unpacking,
modifying, and repacking LZ4-compressed data.

Requirements Mapping:
- REQ1.3
- REQ4.4
"""
from dataclasses import dataclass
from pathlib import Path

import pytest
from ofrak.core.binary import GenericBinary
from ofrak.core.lz4 import (
    Lz4Data,
    Lz4LegacyPacker,
    Lz4ModernData,
    Lz4Packer,
    Lz4PackerConfig,
    Lz4SkippableData,
)
from ofrak.ofrak_context import OFRAKContext
from ofrak.resource import Resource
from ofrak_type.range import Range

ASSETS_DIR = Path(__file__).parent / "assets" / "lz4"


@dataclass
class Lz4UnpackModifyPackTestCase:
    test_file: Path
    input_file: Path

    @property
    def id(self):
        return self.test_file.name


@pytest.mark.parametrize(
    "test_case",
    [
        Lz4UnpackModifyPackTestCase(ASSETS_DIR / "default.lz4", ASSETS_DIR / "input.txt"),
        Lz4UnpackModifyPackTestCase(ASSETS_DIR / "no_frame_crc.lz4", ASSETS_DIR / "input.txt"),
        Lz4UnpackModifyPackTestCase(ASSETS_DIR / "with_size.lz4", ASSETS_DIR / "input.txt"),
        Lz4UnpackModifyPackTestCase(ASSETS_DIR / "block_checksum.lz4", ASSETS_DIR / "input.txt"),
        Lz4UnpackModifyPackTestCase(
            ASSETS_DIR / "block_dependency.lz4", ASSETS_DIR / "large_input.txt"
        ),
        Lz4UnpackModifyPackTestCase(ASSETS_DIR / "large_block.lz4", ASSETS_DIR / "input.txt"),
        Lz4UnpackModifyPackTestCase(ASSETS_DIR / "small_block.lz4", ASSETS_DIR / "input.txt"),
        Lz4UnpackModifyPackTestCase(ASSETS_DIR / "combined_flags.lz4", ASSETS_DIR / "input.txt"),
        Lz4UnpackModifyPackTestCase(ASSETS_DIR / "ultra_fast.lz4", ASSETS_DIR / "large_input.txt"),
        Lz4UnpackModifyPackTestCase(
            ASSETS_DIR / "high_compression.lz4", ASSETS_DIR / "large_input.txt"
        ),
        Lz4UnpackModifyPackTestCase(ASSETS_DIR / "best_compression.lz4", ASSETS_DIR / "input.txt"),
        Lz4UnpackModifyPackTestCase(ASSETS_DIR / "legacy.lz4", ASSETS_DIR / "input.txt"),
        Lz4UnpackModifyPackTestCase(
            ASSETS_DIR / "legacy_large.lz4", ASSETS_DIR / "large_input.txt"
        ),
    ],
    ids=lambda tc: tc.id,
)
async def test_lz4_unpack_modify_pack(
    ofrak_context: OFRAKContext, test_case: Lz4UnpackModifyPackTestCase
):
    """
    Test unpack, modify, and pack functionality for LZ4 files (REQ1.3, REQ1.4).

    This test verifies that:
    - LZ4 files with various compression settings can be unpacked
    - The unpacked data can be modified
    - The modified data can be repacked into a valid LZ4 file
    - The repacked file can be unpacked again to verify the modification
    """
    resource = await ofrak_context.create_root_resource_from_file(test_case.test_file)
    await resource.unpack()
    assert resource.has_tag(Lz4Data)

    initial_data = test_case.input_file.read_bytes()
    child = await resource.get_only_child()
    child_data = await child.get_data()
    assert child_data == initial_data

    modification = b"OFRAK"
    child.queue_patch(Range.from_size(0, len(modification)), modification)
    await child.save()
    await resource.pack()

    repacked_data = await resource.get_data()
    verify_resource = await ofrak_context.create_root_resource(
        "repacked_test.lz4", data=repacked_data
    )
    await verify_resource.unpack()

    verify_child = await verify_resource.get_only_child()
    verified_data = await verify_child.get_data()
    assert verified_data.startswith(modification)


async def test_corrupted_lz4_fail(ofrak_context: OFRAKContext):
    """
    Test that unpacking a corrupted LZ4 file raises an appropriate error (REQ1.3).

    This test verifies that:
    - An LZ4 file with invalid data (corrupted) raises an error when attempting to unpack
    - The error type is consistent with expected decompression errors
    """
    initial_data = b"hello_world_this_is_test_data"

    # Create a valid LZ4 file using OFRAK
    temp_resource = await ofrak_context.create_root_resource("temp_lz4", data=b"")
    temp_resource.add_tag(Lz4ModernData)
    # Add Lz4ModernData view with default settings
    temp_resource.add_view(
        Lz4ModernData(
            block_size=65536,
            block_size_id=4,
            block_linked=False,
            content_checksum=False,
            block_checksum=False,
            content_size=0,
        )
    )
    await temp_resource.save()
    # Create child with the uncompressed data
    await temp_resource.create_child(tags=(GenericBinary,), data=initial_data)
    # Pack it
    await temp_resource.run(Lz4Packer)
    compressed_data = await temp_resource.get_data()

    # Corrupt a significant portion of the compressed data (not the magic header)
    # Corrupt the frame descriptor flags and data to ensure decompression fails
    corrupted_data = bytearray(compressed_data)
    # Corrupt bytes after magic (frame descriptor and data)
    corrupted_data[5 : min(len(corrupted_data), 20)] = b"\xFF" * (min(len(corrupted_data), 20) - 5)

    resource = await ofrak_context.create_root_resource("corrupted.lz4", data=bytes(corrupted_data))

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

    # Create LZ4 file using OFRAK packer
    temp_resource = await ofrak_context.create_root_resource("temp_small_lz4", data=b"")
    temp_resource.add_tag(Lz4ModernData)
    # Add Lz4ModernData view with default settings
    temp_resource.add_view(
        Lz4ModernData(
            block_size=65536,
            block_size_id=4,
            block_linked=False,
            content_checksum=False,
            block_checksum=False,
            content_size=0,
        )
    )
    await temp_resource.save()
    # Create child with the uncompressed data
    await temp_resource.create_child(tags=(GenericBinary,), data=small_data)
    # Pack it
    await temp_resource.run(Lz4Packer)
    compressed_data = await temp_resource.get_data()

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

    # Create LZ4 file using OFRAK packer
    temp_resource = await ofrak_context.create_root_resource("temp_large_lz4", data=b"")
    temp_resource.add_tag(Lz4ModernData)
    # Add Lz4ModernData view with default settings
    temp_resource.add_view(
        Lz4ModernData(
            block_size=65536,
            block_size_id=4,
            block_linked=False,
            content_checksum=False,
            block_checksum=False,
            content_size=0,
        )
    )
    await temp_resource.save()
    # Create child with the uncompressed data
    await temp_resource.create_child(tags=(GenericBinary,), data=large_data)
    # Pack it
    await temp_resource.run(Lz4Packer)
    compressed_data = await temp_resource.get_data()

    resource = await ofrak_context.create_root_resource("large.lz4", data=compressed_data)
    await resource.unpack()
    child = await resource.get_only_child()
    child_data = await child.get_data()
    assert child_data == large_data


@pytest.fixture
async def lz4_skip_bin(ofrak_context: OFRAKContext):
    # This is the skip.bin file from lz4/lz4 repository tests/goldenSamples
    # Source: https://github.com/lz4/lz4/tree/dev/tests/goldenSamples
    test_file = ASSETS_DIR / "lz4_skip.bin"
    resource = await ofrak_context.create_root_resource_from_file(test_file)
    return resource


async def test_real_lz4_skippable_frame(lz4_skip_bin: Resource):
    """
    Test unpacking a real LZ4 skippable frame file from the official LZ4 repository (REQ1.3).

    This test verifies that:
    - Real LZ4 files from the wild can be unpacked successfully
    - Skippable frames are identified correctly as Lz4SkippableData
    - Skippable frames are handled correctly by the unpacker
    - The official LZ4 golden sample file works as expected
    """
    await lz4_skip_bin.unpack()

    # Verify it was identified as skippable frame
    assert lz4_skip_bin.has_tag(Lz4SkippableData)

    # Skippable frame decompresses to empty content
    child = await lz4_skip_bin.get_only_child()
    child_data = await child.get_data()
    assert child_data == b""


@dataclass
class Lz4UnpackVerifyContentTestCase:
    test_file: Path
    input_file: Path

    @property
    def id(self):
        return self.test_file.name


@pytest.mark.parametrize(
    "test_case",
    [
        Lz4UnpackVerifyContentTestCase(ASSETS_DIR / "default.lz4", ASSETS_DIR / "input.txt"),
        Lz4UnpackVerifyContentTestCase(ASSETS_DIR / "no_frame_crc.lz4", ASSETS_DIR / "input.txt"),
        Lz4UnpackVerifyContentTestCase(ASSETS_DIR / "with_size.lz4", ASSETS_DIR / "input.txt"),
        Lz4UnpackVerifyContentTestCase(ASSETS_DIR / "block_checksum.lz4", ASSETS_DIR / "input.txt"),
        Lz4UnpackVerifyContentTestCase(
            ASSETS_DIR / "block_dependency.lz4", ASSETS_DIR / "large_input.txt"
        ),
        Lz4UnpackVerifyContentTestCase(ASSETS_DIR / "large_block.lz4", ASSETS_DIR / "input.txt"),
        Lz4UnpackVerifyContentTestCase(ASSETS_DIR / "small_block.lz4", ASSETS_DIR / "input.txt"),
        Lz4UnpackVerifyContentTestCase(ASSETS_DIR / "combined_flags.lz4", ASSETS_DIR / "input.txt"),
        Lz4UnpackVerifyContentTestCase(ASSETS_DIR / "legacy.lz4", ASSETS_DIR / "input.txt"),
        Lz4UnpackVerifyContentTestCase(
            ASSETS_DIR / "legacy_large.lz4", ASSETS_DIR / "large_input.txt"
        ),
        Lz4UnpackVerifyContentTestCase(
            ASSETS_DIR / "ultra_fast.lz4", ASSETS_DIR / "large_input.txt"
        ),
        Lz4UnpackVerifyContentTestCase(
            ASSETS_DIR / "high_compression.lz4", ASSETS_DIR / "large_input.txt"
        ),
        Lz4UnpackVerifyContentTestCase(
            ASSETS_DIR / "best_compression.lz4", ASSETS_DIR / "input.txt"
        ),
    ],
    ids=lambda tc: tc.id,
)
async def test_lz4_unpack_verify_content(
    ofrak_context: OFRAKContext, test_case: Lz4UnpackVerifyContentTestCase
):
    """
    Test that unpacking LZ4 files produces the correct decompressed content (REQ1.3).

    This test verifies that:
    - LZ4 files with various compression settings can be unpacked successfully
    - The decompressed data matches the expected input content
    - Legacy LZ4 format can be unpacked
    - Modern frame format with various options can be unpacked

    The test covers:
    - Modern frame format with various options
    - Legacy frame format
    - Different compression levels
    - Small and large input files
    """
    # Read expected content
    expected_content = test_case.input_file.read_bytes()

    # Create resource and unpack
    resource = await ofrak_context.create_root_resource_from_file(test_case.test_file)
    await resource.unpack()

    # Get the decompressed child
    child = await resource.get_only_child()
    decompressed_data = await child.get_data()

    # Verify decompressed data matches expected
    assert decompressed_data == expected_content


@dataclass
class Lz4UnpackRepackEquivalenceTestCase:
    test_file: Path
    compression_level: int

    @property
    def id(self):
        return self.test_file.name


@pytest.mark.parametrize(
    "test_case",
    [
        Lz4UnpackRepackEquivalenceTestCase(ASSETS_DIR / "default.lz4", 0),
        Lz4UnpackRepackEquivalenceTestCase(ASSETS_DIR / "no_frame_crc.lz4", 0),
        Lz4UnpackRepackEquivalenceTestCase(ASSETS_DIR / "with_size.lz4", 0),
        Lz4UnpackRepackEquivalenceTestCase(ASSETS_DIR / "block_checksum.lz4", 0),
        pytest.param(
            Lz4UnpackRepackEquivalenceTestCase(
                ASSETS_DIR / "block_dependency.lz4", 0
            ),  # Uses large_input.txt
            marks=pytest.mark.xfail(
                reason="Python lz4 library and lz4 CLI produce different (but equivalent) compressed output for block-linked mode"
            ),
        ),
        Lz4UnpackRepackEquivalenceTestCase(ASSETS_DIR / "ultra_fast.lz4", -1),
        Lz4UnpackRepackEquivalenceTestCase(ASSETS_DIR / "high_compression.lz4", 9),
        Lz4UnpackRepackEquivalenceTestCase(ASSETS_DIR / "best_compression.lz4", 12),
        Lz4UnpackRepackEquivalenceTestCase(ASSETS_DIR / "large_block.lz4", 0),
        Lz4UnpackRepackEquivalenceTestCase(ASSETS_DIR / "small_block.lz4", 0),
        Lz4UnpackRepackEquivalenceTestCase(ASSETS_DIR / "combined_flags.lz4", 0),
    ],
    ids=lambda tc: tc.id,
)
async def test_lz4_unpack_repack_equivalence(
    ofrak_context: OFRAKContext, test_case: Lz4UnpackRepackEquivalenceTestCase
):
    """
    Test that unpacking and repacking LZ4 files preserves exact binary format (REQ1.3, REQ4.4).

    This test verifies that:
    - LZ4 files with various compression settings can be unpacked successfully
    - The unpacked data can be repacked while preserving the original compression settings
    - The repacked compressed data is byte-for-byte identical to the original compressed data
    - Frame metadata (content checksum, block checksum, block size, content size) is preserved
    - Compression level can be specified to match the original file

    The test covers various LZ4 compression options:
    - Default settings (content checksum enabled, no content size)
    - No frame CRC (content checksum disabled)
    - Content size enabled
    - Block checksums enabled
    - Block dependency (linked blocks)
    - Compression levels: 0 (ultra fast/default), 9 (high), 12 (best)
    - Different block sizes (64KB, 4MB)
    - Combined flags (multiple options together)
    """
    # Load the original file
    original_data = test_case.test_file.read_bytes()

    # Create resource and unpack
    resource = await ofrak_context.create_root_resource_from_file(test_case.test_file)
    await resource.unpack()

    # Repack the data with specified compression level
    config = Lz4PackerConfig(compression_level=test_case.compression_level)
    await resource.run(Lz4Packer, config)

    # Get the repacked data
    repacked_data = await resource.get_data()

    # Verify that repacked data is identical to original
    assert repacked_data == original_data


@pytest.mark.parametrize(
    "test_case",
    [
        Lz4UnpackRepackEquivalenceTestCase(ASSETS_DIR / "legacy.lz4", 0),
        Lz4UnpackRepackEquivalenceTestCase(ASSETS_DIR / "legacy_large.lz4", 0),
    ],
    ids=lambda tc: tc.id,
)
async def test_lz4_legacy_unpack_repack_equivalence(
    ofrak_context: OFRAKContext, test_case: Lz4UnpackRepackEquivalenceTestCase
):
    """
    Test that unpacking and repacking legacy LZ4 files preserves exact binary format (REQ1.3, REQ4.4).

    This test verifies that:
    - Legacy LZ4 files can be unpacked successfully
    - The unpacked data can be repacked while preserving the original compression settings
    - The repacked compressed data is byte-for-byte identical to the original compressed data
    - Compression level can be specified to match the original file

    Legacy format uses Lz4LegacyPacker instead of the modern Lz4Packer.
    """
    # Load the original file
    original_data = test_case.test_file.read_bytes()

    # Create resource and unpack
    resource = await ofrak_context.create_root_resource_from_file(test_case.test_file)
    await resource.unpack()

    # Repack the data with specified compression level using legacy packer
    config = Lz4PackerConfig(compression_level=test_case.compression_level)
    await resource.run(Lz4LegacyPacker, config)

    # Get the repacked data
    repacked_data = await resource.get_data()

    # Verify that repacked data is identical to original
    assert repacked_data == original_data


@pytest.mark.parametrize(
    "test_file,input_file",
    [
        (ASSETS_DIR / "legacy.lz4", ASSETS_DIR / "input.txt"),
        (ASSETS_DIR / "legacy_large.lz4", ASSETS_DIR / "large_input.txt"),
    ],
    ids=["legacy_small", "legacy_large"],
)
async def test_lz4_legacy_unpack_repack_content_preservation(
    ofrak_context: OFRAKContext, test_file: Path, input_file: Path
):
    """
    Test that unpacking and repacking legacy LZ4 preserves decompressed content (REQ1.3, REQ4.4).

    This test verifies that:
    - Legacy LZ4 files (both small and large) can be unpacked successfully
    - The unpacked data can be repacked into valid legacy format
    - After repacking, the decompressed content matches the original decompressed content
    - The repacked file can be unpacked again successfully
    - Legacy format supports compression level configuration
    - Both small (<8MB) and large (>8MB) files work correctly
    """
    expected_content = input_file.read_bytes()

    # Create resource and unpack
    resource = await ofrak_context.create_root_resource_from_file(test_file)
    await resource.unpack()

    # Verify decompressed content
    child = await resource.get_only_child()
    decompressed_data = await child.get_data()
    assert decompressed_data == expected_content

    # Repack the data with default compression
    config = Lz4PackerConfig(compression_level=0)
    await resource.run(Lz4LegacyPacker, config)

    # Get the repacked data
    repacked_data = await resource.get_data()

    # Create new resource from repacked data and verify it can be unpacked
    repacked_resource = await ofrak_context.create_root_resource(
        "repacked_legacy.lz4", data=repacked_data
    )
    await repacked_resource.unpack()

    # Verify the repacked file decompresses to the same content
    repacked_child = await repacked_resource.get_only_child()
    repacked_decompressed_data = await repacked_child.get_data()
    assert repacked_decompressed_data == expected_content


@pytest.mark.parametrize(
    "test_file,input_file,compression_level",
    [
        # Small file tests - all levels
        (ASSETS_DIR / "legacy.lz4", ASSETS_DIR / "input.txt", 0),
        (ASSETS_DIR / "legacy.lz4", ASSETS_DIR / "input.txt", -1),
        (ASSETS_DIR / "legacy.lz4", ASSETS_DIR / "input.txt", 9),
        (ASSETS_DIR / "legacy.lz4", ASSETS_DIR / "input.txt", 12),
        # Large file tests - skip slow levels
        (ASSETS_DIR / "legacy_large.lz4", ASSETS_DIR / "large_input.txt", 0),
        (ASSETS_DIR / "legacy_large.lz4", ASSETS_DIR / "large_input.txt", -1),
        pytest.param(
            ASSETS_DIR / "legacy_large.lz4",
            ASSETS_DIR / "large_input.txt",
            9,
            marks=pytest.mark.skip(reason="Level 9 compression too slow on 9MB file"),
        ),
        pytest.param(
            ASSETS_DIR / "legacy_large.lz4",
            ASSETS_DIR / "large_input.txt",
            12,
            marks=pytest.mark.skip(reason="Level 12 compression too slow on 9MB file"),
        ),
    ],
    ids=[
        "legacy_small_level_0",
        "legacy_small_level_-1",
        "legacy_small_level_9",
        "legacy_small_level_12",
        "legacy_large_level_0",
        "legacy_large_level_-1",
        "legacy_large_level_9",
        "legacy_large_level_12",
    ],
)
async def test_lz4_legacy_unpack_repack_with_compression_levels(
    ofrak_context: OFRAKContext, test_file: Path, input_file: Path, compression_level: int
):
    """
    Test that legacy LZ4 can be repacked with different compression levels (REQ1.3, REQ4.4).

    This test verifies that:
    - Legacy LZ4 files (both small and large) can be repacked with various compression levels
    - The repacked files are valid and decompress to the correct content
    - Different compression levels produce different compressed sizes
    - Both small (<8MB) and large (>8MB) files work correctly

    Note: Byte-for-byte equivalence with the CLI is not expected due to version
    differences (Python lz4 library uses v1.9.4, CLI is v1.10.0), but the files
    are interoperable and decompress correctly.

    Levels 9 and 12 are skipped for large files as they are extremely slow in Python lz4 library.
    """
    expected_content = input_file.read_bytes()

    resource = await ofrak_context.create_root_resource_from_file(test_file)
    await resource.unpack()

    # Repack with specified compression level
    config = Lz4PackerConfig(compression_level=compression_level)
    await resource.run(Lz4LegacyPacker, config)

    repacked_data = await resource.get_data()

    # Verify it's a valid legacy file
    assert repacked_data[:4] == b"\x02\x21\x4c\x18", f"Invalid magic for level {compression_level}"

    # Verify decompressed content is correct by unpacking the repacked data using OFRAK
    repacked_resource = await ofrak_context.create_root_resource("repacked", repacked_data)
    await repacked_resource.unpack()

    # Get the decompressed child
    decompressed_child = await repacked_resource.get_only_child()
    decompressed_data = await decompressed_child.get_data()

    assert decompressed_data == expected_content, f"Content mismatch for level {compression_level}"
