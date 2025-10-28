import asyncio
import logging
import tempfile312 as tempfile
from subprocess import CalledProcessError

from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.core.binary import GenericBinary
from ofrak.core.magic import MagicDescriptionPattern, RawMagicPattern
from ofrak.model.component_model import ComponentExternalTool
from ofrak.resource import Resource
from ofrak_type.range import Range

LOGGER = logging.getLogger(__name__)

# Android sparse image magic bytes: 0xed26ff3a in little-endian
SPARSE_HEADER_MAGIC = b"\x3a\xff\x26\xed"


class _AndroidSparseImageTool(ComponentExternalTool):
    """
    Custom tool checker for Android sparse image tools.

    These tools don't support standard help flags and always return non-zero exit codes,
    so we check for the presence of usage output instead.
    """

    def __init__(self, tool: str, apt_package: str, brew_package: str):
        super().__init__(
            tool, "https://github.com/anestisb/android-simg2img", "", apt_package, brew_package
        )

    async def is_tool_installed(self) -> bool:
        """
        Check if the tool is installed by running it with no arguments and checking for usage output.

        :return: True if tool outputs usage information, False otherwise
        """
        try:
            cmd = [self.tool]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
        except FileNotFoundError:
            return False

        # Check if usage information is present in output (tool returns 255, but that's OK)
        if b"usage:" in stderr.lower():
            return True

        return False


SIMG2IMG = _AndroidSparseImageTool("simg2img", "android-sdk-libsparse-utils", "simg2img")
IMG2SIMG = _AndroidSparseImageTool("img2simg", "android-sdk-libsparse-utils", "simg2img")


class AndroidSparseImage(GenericBinary):
    """
    An Android sparse image format binary blob.

    Android sparse images are used to efficiently store and flash system images
    by only including blocks that contain data, skipping empty/unused blocks.
    """

    async def get_file(self) -> Resource:
        """
        Get the unpacked raw image resource.

        :return: The raw (non-sparse) image resource
        """
        return await self.resource.get_only_child()


class AndroidSparseImageUnpacker(Unpacker[None]):
    """
    Unpack (convert) an Android sparse image to raw image format using simg2img.
    """

    id = b"AndroidSparseImageUnpacker"
    targets = (AndroidSparseImage,)
    children = (GenericBinary,)
    external_dependencies = (SIMG2IMG,)

    async def unpack(self, resource: Resource, config=None):
        """
        Unpack the Android sparse image by converting it to raw format.

        :param resource: The sparse image resource to unpack
        """
        async with resource.temp_to_disk() as sparse_path:
            with tempfile.NamedTemporaryFile(
                suffix=".img", mode="rb", delete_on_close=False
            ) as raw_file:
                raw_file.close()

                cmd = [
                    "simg2img",
                    sparse_path,
                    raw_file.name,
                ]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await proc.communicate()

                if proc.returncode:
                    raise CalledProcessError(returncode=proc.returncode, cmd=cmd, stderr=stderr)

                with open(raw_file.name, "rb") as raw_fh:
                    raw_data = raw_fh.read()

                await resource.create_child(tags=(GenericBinary,), data=raw_data)


class AndroidSparseImagePacker(Packer[None]):
    """
    Pack (convert) a raw image back into Android sparse image format using img2simg.
    """

    id = b"AndroidSparseImagePacker"
    targets = (AndroidSparseImage,)
    external_dependencies = (IMG2SIMG,)

    async def pack(self, resource: Resource, config=None):
        """
        Pack the raw image back into sparse format.

        :param resource: The sparse image resource to pack
        """
        sparse_view = await resource.view_as(AndroidSparseImage)
        raw_child_r = await sparse_view.get_file()
        raw_data = await raw_child_r.get_data()

        with tempfile.NamedTemporaryFile(
            suffix=".img", mode="wb", delete_on_close=False
        ) as raw_file:
            raw_file.write(raw_data)
            raw_file.close()

            with tempfile.NamedTemporaryFile(
                suffix=".simg", mode="rb", delete_on_close=False
            ) as sparse_file:
                sparse_file.close()

                # TODO: detect block size in the unpacker rather than default to 4096
                # See https://github.com/redballoonsecurity/ofrak/issues/665
                cmd = [
                    "img2simg",
                    raw_file.name,
                    sparse_file.name,
                    "4096",
                ]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await proc.communicate()

                if proc.returncode:
                    raise CalledProcessError(returncode=proc.returncode, cmd=cmd, stderr=stderr)

                with open(sparse_file.name, "rb") as sparse_fh:
                    sparse_data = sparse_fh.read()

        original_size = await resource.get_data_length()
        resource.queue_patch(Range(0, original_size), sparse_data)
        await resource.save()


def _match_sparse_magic(data: bytes) -> bool:
    """
    Check if data starts with Android sparse image magic bytes.

    :param data: Binary data to check

    :return: True if data matches sparse image format
    """
    if len(data) < 4:
        return False
    return data[:4] == SPARSE_HEADER_MAGIC


# Register magic patterns for identification
MagicDescriptionPattern.register(AndroidSparseImage, lambda s: "Android sparse image" in s)
RawMagicPattern.register(AndroidSparseImage, _match_sparse_magic)
