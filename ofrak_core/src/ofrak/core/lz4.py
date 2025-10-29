"""
Lz4 Components.

Lz4Unpacker currently supports unpacking modern LZ4 format (Lz4ModernData),
legacy format (see Lz4LegacyData), and skippable data (Lz4SkippableData).

Lz4Packer supports repacking the modern LZ4 format (Lz4ModernData), matching block/checksum
information extracted during unpacking. Compression level can be specified via config.

Lz4LegacyPacker supports repacking legacy LZ4 format (Lz4LegacyData) with compression level
support (default/fast/high modes). Compression level can be specified via config.
"""
import logging
from dataclasses import dataclass

import lz4.block  # type: ignore
import lz4.frame  # type: ignore
from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.core.binary import GenericBinary
from ofrak.core.magic import RawMagicPattern
from ofrak.model.component_model import ComponentConfig
from ofrak.resource import Resource
from ofrak_type.range import Range


LOGGER = logging.getLogger(__name__)

# LZ4 frame magic numbers (little-endian)
LZ4_MODERN_MAGIC = b"\x04\x22\x4d\x18"  # 0x184D2204 - Modern/default frame
LZ4_LEGACY_MAGIC = b"\x02\x21\x4c\x18"  # 0x184C2102 - Legacy frame
# Skippable frames: 0x184D2A50 to 0x184D2A5F (16 variants)
# Format: 0x5X 0x2A 0x4D 0x18 where X is 0-F


@dataclass
class Lz4Data(GenericBinary):
    """
    Base class for LZ4 binary blobs.

    LZ4 is a high-speed lossless compression algorithm.
    """


@dataclass
class Lz4ModernData(Lz4Data):
    """
    LZ4 modern frame format (v1.4+).
    """

    block_size: int
    block_size_id: int
    block_linked: bool
    content_checksum: bool
    block_checksum: bool
    content_size: int


@dataclass
class Lz4LegacyData(Lz4Data):
    """
    LZ4 legacy frame format (v0.1-v0.9).
    """


@dataclass
class Lz4SkippableData(Lz4Data):
    """
    LZ4 skippable frame.

    Special frame type for embedding metadata or application-specific data.
    """


class Lz4Unpacker(Unpacker[None]):
    """
    Unpack (decompress) LZ4 modern frame format files.

    Supports:
    - Modern frame format (Lz4ModernData)
    - Skippable frames (metadata containers: Lz4SkippableData)
    """

    id = b"Lz4Unpacker"
    targets = (Lz4ModernData, Lz4SkippableData)
    children = (GenericBinary,)

    async def unpack(self, resource: Resource, config=None):
        """
        Unpack LZ4 data.

        :param resource: The LZ4 resource to unpack

        :raises RuntimeError: if the data is not valid LZ4 format
        """
        resource_data = await resource.get_data()

        if resource.has_tag(Lz4ModernData):
            # lz4.frame.get_frame_info() does not support legacy frames
            frame_info = lz4.frame.get_frame_info(resource_data)
            resource.add_view(
                Lz4ModernData(
                    block_size=frame_info["block_size"],
                    block_size_id=frame_info["block_size_id"],
                    block_linked=frame_info["block_linked"],
                    content_checksum=frame_info["content_checksum"],
                    block_checksum=frame_info["block_checksum"],
                    content_size=frame_info["content_size"],
                )
            )

        try:
            decompressed_data = lz4.frame.decompress(resource_data)
        except RuntimeError as e:
            LOGGER.error(f"Failed to decompress LZ4 data: {e}")
            raise

        await resource.create_child(
            tags=(GenericBinary,),
            data=decompressed_data,
        )


class Lz4LegacyUnpacker(Unpacker[None]):
    """
    Unpack (decompress) LZ4 legacy frame format files.

    Legacy format (v0.1-v0.9) uses lz4.block decompression instead of lz4.frame.
    """

    id = b"Lz4LegacyUnpacker"
    targets = (Lz4LegacyData,)
    children = (GenericBinary,)

    async def unpack(self, resource: Resource, config=None):
        """
        Unpack LZ4 legacy data.

        :param resource: The LZ4 legacy resource to unpack

        :raises RuntimeError: if the data is not valid LZ4 legacy format
        """
        resource_data = await resource.get_data()

        # Parse legacy header: 4 bytes magic + 4 bytes block size
        if len(resource_data) < 8:
            raise RuntimeError("Invalid LZ4 legacy format: file too short")

        # Note: The header field is the compressed block size, not uncompressed size
        block_size = int.from_bytes(resource_data[4:8], "little")
        compressed_block = resource_data[8:]

        # Validate block size matches actual data
        if len(compressed_block) != block_size:
            raise RuntimeError(
                f"Invalid LZ4 legacy format: header says {block_size} bytes but found {len(compressed_block)}"
            )

        try:
            # LZ4 legacy blocks don't store uncompressed size, so we need to provide
            # a large enough buffer. Use a generous multiplier to handle any compression ratio.
            max_uncompressed_size = block_size * 255  # LZ4 max compression ratio
            decompressed_data = lz4.block.decompress(
                compressed_block, uncompressed_size=max_uncompressed_size
            )
        except Exception as e:
            LOGGER.error(f"Failed to decompress LZ4 legacy data: {e}")
            raise RuntimeError(f"LZ4 legacy decompression failed: {e}")

        await resource.create_child(
            tags=(GenericBinary,),
            data=decompressed_data,
        )


@dataclass
class Lz4PackerConfig(ComponentConfig):
    """
    Configuration for LZ4 packer.

    compression_level: Compression level to use (default: 0).
        - Negative values: Fast acceleration (faster, less compression)
        - 0-2: Minimum compression (default, all produce same output)
        - 3: Minimum high-compression mode
        - 4-16: Higher compression levels (16 is maximum)
    """

    compression_level: int = 0


class Lz4Packer(Packer[Lz4PackerConfig]):
    """
    Pack data into a compressed LZ4 file using modern frame format.

    Implementation repacks modern frame format preserving frame metadata.
    Compression level can be specified via config (default: 0).
    """

    targets = (Lz4ModernData,)

    async def pack(self, resource: Resource, config: Lz4PackerConfig = None):
        """
        Pack data into `Lz4ModernData` format.

        :param resource: The LZ4 resource to pack
        :param config: Optional configuration specifying compression level
        """
        if config is None:
            config = Lz4PackerConfig()

        lz4_child = await resource.get_only_child()
        child_data = await lz4_child.get_data()

        # Use stored compression settings from the view
        lz4_view = await resource.view_as(Lz4ModernData)
        content_checksum = lz4_view.content_checksum
        block_checksum = lz4_view.block_checksum
        block_size = lz4_view.block_size
        store_size = lz4_view.content_size != 0

        lz4_compressed = lz4.frame.compress(
            child_data,
            compression_level=config.compression_level,
            content_checksum=content_checksum,
            block_checksum=block_checksum,
            block_size=block_size,
            store_size=store_size,
        )

        original_size = await resource.get_data_length()
        resource.queue_patch(Range(0, original_size), lz4_compressed)


class Lz4LegacyPacker(Packer[Lz4PackerConfig]):
    """
    Pack data into compressed LZ4 legacy format.

    Legacy format supports compression levels via lz4.block.compress():
    - Negative values: Fast mode with acceleration
    - 0: Default compression
    - 1-12: High compression mode
    """

    targets = (Lz4LegacyData,)

    async def pack(self, resource: Resource, config: Lz4PackerConfig = None):
        """
        Pack data into `Lz4LegacyData` format.

        :param resource: The LZ4 legacy resource to pack
        :param config: Optional configuration specifying compression level
        """
        if config is None:
            config = Lz4PackerConfig()

        lz4_child = await resource.get_only_child()
        child_data = await lz4_child.get_data()

        # Map compression_level to lz4.block.compress() parameters
        # This matches the lz4 CLI behavior for legacy format:
        # - Level < 0: fast mode with acceleration = -level
        if config.compression_level < 0:
            # Fast mode with acceleration
            compressed_block = lz4.block.compress(
                child_data,
                mode="fast",
                acceleration=abs(config.compression_level),
                store_size=False,
            )
        # - Level 0-2: fast mode with acceleration = 0
        elif config.compression_level < 3:
            # Fast mode with acceleration = 0 (levels 0, 1, 2)
            compressed_block = lz4.block.compress(
                child_data, mode="fast", acceleration=0, store_size=False
            )
        # - Level >= 3: high compression mode
        else:
            # High compression mode (3-12)
            compressed_block = lz4.block.compress(
                child_data,
                mode="high_compression",
                compression=config.compression_level,
                store_size=False,
            )

        # Build legacy header: magic (4 bytes) + compressed_block_size (4 bytes)
        compressed_block_size = len(compressed_block)
        header = LZ4_LEGACY_MAGIC + compressed_block_size.to_bytes(4, "little")

        # Combine header + compressed block
        lz4_compressed = header + compressed_block

        original_size = await resource.get_data_length()
        resource.queue_patch(Range(0, original_size), lz4_compressed)


def match_lz4_modern_magic(data: bytes) -> bool:
    if len(data) < 4:
        return False
    return data[:4] == LZ4_MODERN_MAGIC


def match_lz4_legacy_magic(data: bytes) -> bool:
    if len(data) < 4:
        return False
    return data[:4] == LZ4_LEGACY_MAGIC


def match_lz4_skippable_magic(data: bytes) -> bool:
    if len(data) < 4:
        return False
    # Format: 0x5X 0x2A 0x4D 0x18 where X is 0-F
    return data[1:4] == b"\x2a\x4d\x18" and 0x50 <= data[0] <= 0x5F


RawMagicPattern.register(Lz4ModernData, match_lz4_modern_magic)
RawMagicPattern.register(Lz4LegacyData, match_lz4_legacy_magic)
RawMagicPattern.register(Lz4SkippableData, match_lz4_skippable_magic)
