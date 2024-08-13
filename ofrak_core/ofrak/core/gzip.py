import asyncio
import logging
from typing import Optional
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


class PIGZInstalled:
    _pigz_installed: Optional[bool] = None

    @staticmethod
    async def is_pigz_installed() -> bool:
        if PIGZInstalled._pigz_installed is None:
            PIGZInstalled._pigz_installed = await PIGZ.is_tool_installed()
        return PIGZInstalled._pigz_installed


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
        if len(data) >= 1024 * 1024 * 4 and await PIGZInstalled.is_pigz_installed():
            unpacked_data = await self.unpack_with_pigz(data)
        else:
            try:
                unpacked_data = await self.unpack_with_zlib_module(data)
            except Exception:  # pragma: no cover
                if not PIGZInstalled.is_pigz_installed():
                    raise
                unpacked_data = await self.unpack_with_pigz(data)
        return await resource.create_child(tags=(GenericBinary,), data=unpacked_data)

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
        data = await gzip_child_r.get_data()

        if len(data) >= 1024 * 1024 and await PIGZInstalled.is_pigz_installed():
            packed_data = await self.pack_with_pigz(data)
        else:
            packed_data = await self.pack_with_zlib_module(data)

        original_gzip_size = await gzip_view.resource.get_data_length()
        resource.queue_patch(Range(0, original_gzip_size), data=packed_data)

    @staticmethod
    async def pack_with_zlib_module(data: bytes) -> bytes:
        compressor = zlib.compressobj(wbits=16 + zlib.MAX_WBITS)
        result = compressor.compress(data)
        result += compressor.flush()
        return result

    @staticmethod
    async def pack_with_pigz(data: bytes) -> bytes:
        cmd = ["pigz"]
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


MagicMimeIdentifier.register(GzipData, "application/gzip")
MagicDescriptionIdentifier.register(GzipData, lambda s: s.startswith("gzip compressed data"))
