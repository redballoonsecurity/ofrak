import bz2
import logging
from dataclasses import dataclass

from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.resource import Resource
from ofrak.core.binary import GenericBinary
from ofrak.core.magic import MagicDescriptionPattern, MagicMimePattern
from ofrak_type.range import Range

LOGGER = logging.getLogger(__name__)


@dataclass
class Bzip2Data(GenericBinary):
    """
    A bzip2 binary blob.
    """


class Bzip2Unpacker(Unpacker[None]):
    """
    Decompresses bzip2-compressed data, which uses Burrows-Wheeler transform and Huffman coding for
    compression. Use for .bz2 files or bzip2-compressed sections within larger binaries. Common in
    Linux systems for compressed tarballs (.tar.bz2) and firmware images. Results in a single child.
    """

    targets = (Bzip2Data,)
    children = (GenericBinary,)

    async def unpack(self, resource: Resource, config=None):
        """
        Unpack bzip2 data.

        :param resource:
        :param config:
        """
        resource_data = await resource.get_data()
        decompressed_data = bz2.decompress(resource_data)
        await resource.create_child(
            tags=(GenericBinary,),
            data=decompressed_data,
        )


class Bzip2Packer(Packer[None]):
    """
    Compresses data using the bzip2 algorithm. Use after modifying decompressed bzip2 data to
    recreate .bz2 files or bzip2-compressed sections within larger binaries. Common for compressed
    tarballs and firmware images.
    """

    targets = (Bzip2Data,)

    async def pack(self, resource: Resource, config=None):
        """
        Pack a resource into bzip2 data.

        :param resource:
        :param config:
        """
        bzip2_child = await resource.get_only_child()
        bzip2_compressed = bz2.compress(await bzip2_child.get_data())
        original_size = await resource.get_data_length()
        resource.queue_patch(Range(0, original_size), bzip2_compressed)


MagicMimePattern.register(Bzip2Data, "application/x-bzip2")
MagicDescriptionPattern.register(Bzip2Data, lambda s: s.startswith("BZip2 archive"))
