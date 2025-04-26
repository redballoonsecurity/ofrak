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
    Unpack bzip2 data.

    bzip2 binary blobs decompress into one child.
    """

    targets = (Bzip2Data,)
    children = (GenericBinary,)

    def unpack(self, resource: Resource, config=None):
        """
        Unpack bzip2 data.

        :param resource:
        :param config:
        """
        resource_data = resource.get_data()
        decompressed_data = bz2.decompress(resource_data)
        resource.create_child(
            tags=(GenericBinary,),
            data=decompressed_data,
        )


class Bzip2Packer(Packer[None]):
    """
    Pack a resource, compressing it into bzip2 data.
    """

    targets = (Bzip2Data,)

    def pack(self, resource: Resource, config=None):
        """
        Pack a resource into bzip2 data.

        :param resource:
        :param config:
        """
        bzip2_child = resource.get_only_child()
        bzip2_compressed = bz2.compress(bzip2_child.get_data())
        original_size = resource.get_data_length()
        resource.queue_patch(Range(0, original_size), bzip2_compressed)


MagicMimePattern.register(Bzip2Data, "application/x-bzip2")
MagicDescriptionPattern.register(Bzip2Data, lambda s: s.startswith("BZip2 archive"))
