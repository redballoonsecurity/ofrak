import asyncio
import logging
import os
import tempfile
from dataclasses import dataclass
from subprocess import CalledProcessError

from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.resource import Resource
from ofrak.core.binary import GenericBinary
from ofrak.core.filesystem import File, Folder, FilesystemRoot, SpecialFileType
from ofrak.core.magic import MagicMimeIdentifier, MagicDescriptionIdentifier

from ofrak.model.component_model import ComponentExternalTool
from ofrak_type.range import Range

LOGGER = logging.getLogger(__name__)

SEVEN_ZIP = ComponentExternalTool("7zz", "https://www.7-zip.org", "--help", brew_package="sevenzip")


@dataclass
class SevenZFilesystem(GenericBinary, FilesystemRoot):
    """
    Filesystem stored in a 7z archive.
    """


class SevenZUnpacker(Unpacker[None]):
    """
    Unpack (decompress) a 7z file.
    """

    targets = (SevenZFilesystem,)
    children = (File, Folder, SpecialFileType)
    external_dependencies = (SEVEN_ZIP,)

    async def unpack(self, resource: Resource, config=None):
        seven_zip_v = await resource.view_as(SevenZFilesystem)
        resource_data = await seven_zip_v.resource.get_data()
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(resource_data)
            temp_file.flush()
            with tempfile.TemporaryDirectory() as temp_flush_dir:
                cmd = [
                    "7zz",
                    "x",
                    f"-o{temp_flush_dir}",
                    temp_file.name,
                ]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                )
                returncode = await proc.wait()
                if proc.returncode:
                    raise CalledProcessError(returncode=returncode, cmd=cmd)
                await seven_zip_v.initialize_from_disk(temp_flush_dir)


class SevenzPacker(Packer[None]):
    """
    Pack files into a compressed 7z archive.
    """

    targets = (SevenZFilesystem,)
    external_dependencies = (SEVEN_ZIP,)

    async def pack(self, resource: Resource, config=None):
        seven_zip_v: SevenZFilesystem = await resource.view_as(SevenZFilesystem)
        temp_flush_dir = await seven_zip_v.flush_to_disk()
        temp_flush_dir = os.path.join(temp_flush_dir, ".")
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_name = os.path.join(temp_dir, "temp.7z")
            cmd = [
                "7zz",
                "a",
                temp_name,
                temp_flush_dir,
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
            )
            returncode = await proc.wait()
            if proc.returncode:
                raise CalledProcessError(returncode=returncode, cmd=cmd)
            with open(temp_name, "rb") as f:
                new_data = f.read()
            # Passing in the original range effectively replaces the original data with the new data
            resource.queue_patch(Range(0, await resource.get_data_length()), new_data)


MagicMimeIdentifier.register(SevenZFilesystem, "application/x-7z-compressed")
MagicDescriptionIdentifier.register(SevenZFilesystem, lambda s: s.startswith("7-zip archive"))
