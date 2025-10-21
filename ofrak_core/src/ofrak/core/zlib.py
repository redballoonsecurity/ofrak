import logging
import zlib
from dataclasses import dataclass

from ofrak.component.analyzer import Analyzer
from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.resource import Resource
from ofrak.core.binary import GenericBinary
from ofrak.core.magic import MagicMimePattern, MagicDescriptionPattern
from ofrak_type.range import Range

LOGGER = logging.getLogger(__name__)


@dataclass
class ZlibData(GenericBinary):
    compression_level: int

    async def get_child(self) -> GenericBinary:
        return await self.resource.get_only_child_as_view(GenericBinary)


class ZlibCompressionLevelAnalyzer(Analyzer[None, ZlibData]):
    """
    Attempts to determine the compression level (0-9) used when creating zlib-compressed data by
    analyzing compression parameters and testing decompression with different level hints.
    Understanding compression level can help with recompression to match original size. Use when
    analyzing compression characteristics for size optimization, understanding compression
    trade-offs, or preparing to modify and recompress data while maintaining similar
    characteristics. Useful for forensics or binary diffing.
    """

    id = b"ZlibCompressionLevelAnalyzer"
    targets = (ZlibData,)
    outputs = (ZlibData,)

    async def analyze(self, resource: Resource, config=None) -> ZlibData:
        zlib_data = await resource.get_data(Range(0, 2))
        flevel = zlib_data[-1]
        if flevel == 0x01:
            compression_level = 1
        elif flevel == 0x5E:
            compression_level = 2
        elif flevel == 0x9C:
            compression_level = 6
        elif flevel == 0xDA:
            compression_level = 7
        else:
            compression_level = 6
        return ZlibData(compression_level)


class ZlibUnpacker(Unpacker[None]):
    """
    Decompresses zlib-compressed data. Use when encountering zlib-compressed data blocks. The 
    decompressed data may contain further structure that can be analyzed or unpacked.
    """

    id = b"ZlibUnpacker"
    targets = (ZlibData,)
    children = (GenericBinary,)

    async def unpack(self, resource: Resource, config=None):
        zlib_data = await resource.get_data()
        zlib_uncompressed_data = zlib.decompress(zlib_data)
        await resource.create_child(
            tags=(GenericBinary,),
            data=zlib_uncompressed_data,
        )


class ZlibPacker(Packer[None]):
    """
    Compresses data using zlib's DEFLATE algorithm. Use after modifying decompressed zlib data to
    recreate compressed sections in binaries, PNG files, or any format that uses zlib compression.
    The packer can target different compression levels for size vs speed tradeoffs.
    """

    targets = (ZlibData,)

    async def pack(self, resource: Resource, config=None):
        zlib_view = await resource.view_as(ZlibData)
        compression_level = zlib_view.compression_level
        zlib_child = await zlib_view.get_child()
        zlib_data = await zlib_child.resource.get_data()
        zlib_compressed = zlib.compress(zlib_data, compression_level)

        original_zlib_size = await zlib_view.resource.get_data_length()
        resource.queue_patch(Range(0, original_zlib_size), zlib_compressed)


MagicMimePattern.register(ZlibData, "application/zlib")
MagicDescriptionPattern.register(ZlibData, lambda s: s.startswith("zlib compressed data"))
