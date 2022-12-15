import logging
import lzma
from io import BytesIO
from typing import Union

from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.resource import Resource
from ofrak.core.binary import GenericBinary
from ofrak.core.magic import MagicMimeIdentifier, MagicDescriptionIdentifier
from ofrak_type.range import Range

LOGGER = logging.getLogger(__name__)


class LzmaData(GenericBinary):
    """
    An lzma binary blob.
    """

    async def get_child(self) -> GenericBinary:
        return await self.resource.get_only_child_as_view(GenericBinary)


class XzData(GenericBinary):
    """
    An xz binary blob.
    """

    async def get_child(self) -> GenericBinary:
        return await self.resource.get_only_child_as_view(GenericBinary)


class LzmaUnpacker(Unpacker[None]):
    """
    Unpack (decompress) an LZMA | XZ file.
    """

    id = b"LzmaUnpacker"
    targets = (LzmaData, XzData)
    children = (GenericBinary,)

    async def unpack(self, resource: Resource, config=None):
        file_data = BytesIO(await resource.get_data())

        format = lzma.FORMAT_AUTO

        if resource.has_tag(XzData):
            format = lzma.FORMAT_XZ
        elif resource.has_tag(LzmaData):
            format = lzma.FORMAT_ALONE

        lzma_entry_data = lzma.decompress(file_data.read(), format)
        await resource.create_child(
            tags=(GenericBinary,),
            data=lzma_entry_data,
        )


class LzmaPacker(Packer[None]):
    """
    Pack data into a compressed LZMA | XZ file.
    """

    targets = (LzmaData, XzData)

    async def pack(self, resource: Resource, config=None):
        lzma_format, tag = await self._get_lzma_format_and_tag(resource)
        lzma_file: Union[XzData, LzmaData] = await resource.view_as(tag)

        lzma_child = await lzma_file.get_child()
        lzma_compressed = lzma.compress(await lzma_child.resource.get_data(), lzma_format)

        original_size = await lzma_file.resource.get_data_length()
        resource.queue_patch(Range(0, original_size), lzma_compressed)

    async def _get_lzma_format_and_tag(self, resource):
        if resource.has_tag(XzData):
            tag = XzData
            lzma_format = lzma.FORMAT_XZ
        elif resource.has_tag(LzmaData):
            tag = LzmaData
            lzma_format = lzma.FORMAT_ALONE
        else:
            raise TypeError(
                f"Expected target of {self.get_id().decode()} to be either XzFile or LzmaFile"
            )
        return lzma_format, tag


MagicMimeIdentifier.register(LzmaData, "application/x-lzma")
MagicMimeIdentifier.register(XzData, "application/x-xz")
MagicDescriptionIdentifier.register(LzmaData, lambda s: s.startswith("LZMA compressed data"))
MagicDescriptionIdentifier.register(XzData, lambda s: s.startswith("XZ compressed data"))
