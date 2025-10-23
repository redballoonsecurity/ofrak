import logging
from dataclasses import dataclass

import lz4.frame  # type: ignore
import lz4.block  # type: ignore

from ofrak.component.identifier import Identifier
from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.core.binary import GenericBinary
from ofrak.core.magic import MagicDescriptionPattern, MagicMimePattern
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
    LZ4 modern frame format (default).

    The modern LZ4 frame format includes:
    - Frame descriptor with flags
    - Optional content size and dictionary ID
    - Block independence flags
    - Optional checksums (content and block)
    - End mark
    """


@dataclass
class Lz4LegacyData(Lz4Data):
    """
    LZ4 legacy frame format.

    Older LZ4 format predating the frame specification:
    - Simpler structure
    - No checksums or metadata
    - Fixed 8MB max block size
    - Deprecated but still encountered in the wild
    """


@dataclass
class Lz4SkippableData(Lz4Data):
    """
    LZ4 skippable frame.

    Special frame type for embedding metadata or application-specific data:
    - Not compressed data
    - Contains arbitrary bytes
    - LZ4 parsers can safely skip these frames
    - Typically used alongside regular frames
    """


class Lz4Identifier(Identifier):
    """
    Identify LZ4 compressed data by checking magic bytes.

    Recognizes all LZ4 frame types:
    - Modern/default frames (0x184D2204)
    - Legacy frames (0x184C2102)
    - Skippable frames (0x184D2A50-0x184D2A5F)
    """

    id = b"Lz4Identifier"
    targets = (GenericBinary,)

    async def identify(self, resource: Resource, config=None) -> None:
        data = await resource.get_data(Range(0, 4))

        if len(data) < 4:
            return

        # Check for modern frame
        if data == LZ4_MODERN_MAGIC:
            resource.add_tag(Lz4ModernData)
            return

        # Check for legacy frame
        if data == LZ4_LEGACY_MAGIC:
            resource.add_tag(Lz4LegacyData)
            return

        # Check for skippable frames
        # Format: 0x5X 0x2A 0x4D 0x18 where X is 0-F
        if data[1:4] == b"\x2a\x4d\x18" and 0x50 <= data[0] <= 0x5F:
            resource.add_tag(Lz4SkippableData)
            return


class Lz4Unpacker(Unpacker[None]):
    """
    Unpack (decompress) LZ4 files of all frame types.

    Supports:
    - Modern frame format (most common)
    - Legacy frame format (deprecated)
    - Skippable frames (metadata containers)
    """

    id = b"Lz4Unpacker"
    targets = (Lz4ModernData, Lz4LegacyData, Lz4SkippableData)
    children = (GenericBinary,)

    async def unpack(self, resource: Resource, config=None):
        """
        Unpack LZ4 data.

        :param resource: The LZ4 resource to unpack
        :param config: Optional unpacker configuration

        :raises RuntimeError: if the data is not valid LZ4 format
        """
        resource_data = await resource.get_data()

        try:
            decompressed_data = lz4.frame.decompress(resource_data)
        except RuntimeError as e:
            LOGGER.error(f"Failed to decompress LZ4 data: {e}")
            raise

        await resource.create_child(
            tags=(GenericBinary,),
            data=decompressed_data,
        )


class Lz4Packer(Packer[None]):
    """
        Pack data into a compressed LZ4 file using modern frame format.

    Note: Only creates modern frame format. Legacy frames and skippable frames
    cannot be repacked:
    - Legacy format is deprecated and not supported by the Python lz4 library
    - Skippable frames are metadata containers and don't make semantic sense to pack

    If you unpack a legacy or skippable frame and repack, it will be converted
    to modern frame format.
    """

    targets = (Lz4ModernData,)

    async def pack(self, resource: Resource, config=None):
        """
        Pack data into LZ4 modern frame format.

        :param resource: The LZ4 resource to pack
        :param config: Optional packer configuration
        """
        lz4_child = await resource.get_only_child()
        child_data = await lz4_child.get_data()

        lz4_compressed = lz4.frame.compress(child_data)

        original_size = await resource.get_data_length()
        resource.queue_patch(Range(0, original_size), lz4_compressed)


# Register magic patterns for automatic identification
MagicMimePattern.register(Lz4Data, "application/x-lz4")
MagicDescriptionPattern.register(Lz4Data, lambda s: s.lower().startswith("lz4 compressed data"))
