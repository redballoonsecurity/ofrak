import asyncio
import logging
import zlib
from subprocess import CalledProcessError

from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.core.binary import GenericBinary
from ofrak.core.magic import MagicMimeIdentifier, MagicDescriptionIdentifier
from ofrak.model.component_model import ComponentExternalTool
from ofrak.resource import Resource
from ofrak_type.range import Range

LOGGER = logging.getLogger(__name__)

PIGZ = ComponentExternalTool(
    "pigz", "https://zlib.net/pigz/", "--help", apt_package="pigz", brew_package="pigz"
)


class GzipData(GenericBinary):
    """
    A gzip binary blob.
    """

    async def get_file(self) -> Resource:
        return await self.resource.get_only_child()


class GzipUnpacker(Unpacker[None]):
    """
    Unpack (decompress) a gzip file.
    """

    id = b"GzipUnpacker"
    targets = (GzipData,)
    children = (GenericBinary,)
    external_dependencies = (PIGZ,)

    async def unpack(self, resource: Resource, config=None):
        data = await resource.get_data()
        if len(data) >= 1024 * 1024 * 4 and await PIGZ.is_tool_installed():
            uncompressed_data = await self.unpack_with_pigz(data)
        else:
            uncompressed_data = await self.unpack_with_zlib_module(data)
        return await resource.create_child(tags=(GenericBinary,), data=uncompressed_data)

    @staticmethod
    async def unpack_with_zlib_module(data: bytes) -> bytes:
        chunks = []

        # wbits > 16 handles the gzip header and footer
        # We need to create a zlib.Decompress object in order to use this
        # parameter in Python < 3.11
        decompressor = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
        while data.startswith(b"\037\213"):
            chunks.append(decompressor.decompress(data))
            if decompressor.eof:
                break
            data = decompressor.unused_data.lstrip(b"\0")

        if not len(chunks):
            raise ValueError("Not a gzipped file")

        return b"".join(chunks)

    @staticmethod
    async def unpack_with_pigz(data: bytes) -> bytes:
        cmd = ["pigz", "-d"]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate(data)
        if proc.returncode:
            raise CalledProcessError(returncode=proc.returncode, cmd=cmd, stderr=stderr)

        return stdout


class GzipPacker(Packer[None]):
    """
    Pack data into a compressed gzip file.
    """

    targets = (GzipData,)

    async def pack(self, resource: Resource, config=None):
        gzip_view = await resource.view_as(GzipData)
        gzip_child_r = await gzip_view.get_file()
        gzip_data = await gzip_child_r.get_data()
        compressor = zlib.compressobj(wbits=16 + zlib.MAX_WBITS)
        result = compressor.compress(gzip_data)
        result += compressor.flush()
        original_gzip_size = await gzip_view.resource.get_data_length()
        resource.queue_patch(Range(0, original_gzip_size), result)


MagicMimeIdentifier.register(GzipData, "application/gzip")
MagicDescriptionIdentifier.register(GzipData, lambda s: s.startswith("gzip compressed data"))
