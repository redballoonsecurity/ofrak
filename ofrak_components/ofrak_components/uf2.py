import logging
from uf2 import uf2conv
from dataclasses import dataclass

from ofrak.resource import Resource
from ofrak.component.unpacker import Unpacker
from ofrak.component.packer import Packer
from ofrak.component.identifier import Identifier
from ofrak.core.binary import GenericBinary
from ofrak_type.range import Range

LOGGER = logging.getLogger(__name__)


@dataclass
class Uf2Data(GenericBinary):
    """
    A UF2 binary blob
    """


class Uf2Unpacker(Unpacker[None]):
    """
    UF2 unpacker.

    Extracts the data from a UF2 packed file.
    """

    targets = (Uf2Data,)
    children = (GenericBinary,)

    async def unpack(self, resource: Resource, config=None):
        """
        Unpack a UF2 file.

        UF2 files contain blocks of binary data.
        """

        # TODO: technically there's multiple types of data. At least
        # investigate what they mean - sj

        resource_data = await resource.get_data()
        uf2_data = uf2conv.convert_from_uf2(resource_data)
        await resource.create_child(tags=(GenericBinary,), data=uf2_data)


class Uf2Packer(Packer[None]):
    """
    Pack a resource into the UF2 file format
    """

    targets = (Uf2Data,)

    async def pack(self, resource: Resource, config=None):
        """
        Pack a resource into a UF2 file

        :param resource:
        :param config:
        """
        uf2_child = await resource.get_only_child()
        uf2_packed = uf2conv.convert_to_uf2(await uf2_child.get_data())
        original_size = await resource.get_data_length()
        resource.queue_patch(Range(0, original_size), uf2_packed)


class Uf2Identifier(Identifier):
    id = b"Uf2FileIdentifier"
    targets = (GenericBinary,)

    async def identify(self, resource: Resource, config=None):
        resource_data = await resource.get_data()
        if uf2conv.is_uf2(resource_data):
            resource.add_tag(Uf2Data)
