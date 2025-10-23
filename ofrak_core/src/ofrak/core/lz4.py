import logging
from dataclasses import dataclass

import lz4.frame

from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.core.binary import GenericBinary
from ofrak.core.magic import MagicDescriptionPattern, MagicMimePattern
from ofrak.resource import Resource
from ofrak_type.range import Range

LOGGER = logging.getLogger(__name__)


@dataclass
class Lz4Data(GenericBinary):
    """
    An LZ4 binary blob.

    LZ4 is a high-speed lossless compression algorithm supporting multiple frame formats:
    - Modern frame format (default)
    - Legacy frame format
    - Skippable frames
    """


class Lz4Unpacker(Unpacker[None]):
    """
    Unpack (decompress) an LZ4 file.

    Supports all LZ4 frame formats:
    - LZ4 default frame (modern format with metadata)
    - LZ4 legacy frame (older format for backward compatibility)
    - LZ4 skippable frames (metadata containers)
    """

    id = b"Lz4Unpacker"
    targets = (Lz4Data,)
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
    Pack data into a compressed LZ4 file.

    Creates LZ4 files using the modern frame format.
    """

    targets = (Lz4Data,)

    async def pack(self, resource: Resource, config=None):
        """
        Pack data into LZ4 format.

        :param resource: The LZ4 resource to pack
        :param config: Optional packer configuration
        """
        lz4_child = await resource.get_only_child()
        child_data = await lz4_child.get_data()

        lz4_compressed = lz4.frame.compress(child_data)

        original_size = await resource.get_data_length()
        resource.queue_patch(Range(0, original_size), lz4_compressed)


MagicMimePattern.register(Lz4Data, "application/x-lz4")
MagicDescriptionPattern.register(Lz4Data, lambda s: s.lower().startswith("lz4 compressed data"))
