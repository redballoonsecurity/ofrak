import asyncio
import logging
from typing import Optional
import zlib
from subprocess import CalledProcessError
import tempfile312 as tempfile

from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.core.binary import GenericBinary
from ofrak.core.magic import MagicMimeIdentifier, MagicDescriptionIdentifier
from ofrak.model.component_model import ComponentExternalTool
from ofrak.resource import Resource
from ofrak_type.range import Range

LOGGER = logging.getLogger(__name__)

# PIGZ provides significantly faster compression on multi core systems.
# It does not parallelize decompression, so we don't use it in GzipUnpacker.
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
        unpacked_data = await self.unpack_with_zlib_module(data)
        return await resource.create_child(tags=(GenericBinary,), data=unpacked_data)

    @staticmethod
    async def unpack_with_zlib_module(data: bytes) -> bytes:
        # We use zlib.decompressobj instead of the gzip module to decompress
        # because of a bug that causes gzip to raise BadGzipFile if there's
        # trailing garbage after a compressed file instead of correctly ignoring it
        # https://github.com/python/cpython/issues/68489

        # gzip files can consist of multiple members, so we need to read them in
        # a loop and concatenate them in the end. \037\213 are magic bytes
        # indicating the start of a gzip header.
        chunks = []
        while data.startswith(b"\037\213"):
            # wbits > 16 handles the gzip header and footer
            decompressor = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
            chunks.append(decompressor.decompress(data))
            if not decompressor.eof:
                raise ValueError("Incomplete gzip file")
            data = decompressor.unused_data.lstrip(b"\0")

        if not len(chunks):
            raise ValueError("Not a gzipped file")

        return b"".join(chunks)


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
        with tempfile.NamedTemporaryFile(delete_on_close=False) as uncompressed_file:
            uncompressed_file.write(data)
            uncompressed_file.close()

            cmd = [
                "pigz",
                "-c",
                uncompressed_file.name,
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode:
                raise CalledProcessError(returncode=proc.returncode, stderr=stderr, cmd=cmd)

            return stdout


MagicMimeIdentifier.register(GzipData, "application/gzip")
MagicDescriptionIdentifier.register(GzipData, lambda s: s.startswith("gzip compressed data"))
