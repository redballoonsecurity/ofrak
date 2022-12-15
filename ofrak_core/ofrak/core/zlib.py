import logging
import zlib
from dataclasses import dataclass

from ofrak.component.analyzer import Analyzer
from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.resource import Resource
from ofrak.core.binary import GenericBinary
from ofrak.core.magic import MagicMimeIdentifier, MagicDescriptionIdentifier
from ofrak_type.range import Range

LOGGER = logging.getLogger(__name__)


@dataclass
class ZlibData(GenericBinary):
    compression_level: int

    async def get_child(self) -> GenericBinary:
        return await self.resource.get_only_child_as_view(GenericBinary)


class ZlibCompressionLevelAnalyzer(Analyzer[None, ZlibData]):
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
    Decompress a blob of zlib data
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
    Pack a binary with zlib
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


MagicMimeIdentifier.register(ZlibData, "application/zlib")
MagicDescriptionIdentifier.register(ZlibData, lambda s: s.startswith("zlib compressed data"))
