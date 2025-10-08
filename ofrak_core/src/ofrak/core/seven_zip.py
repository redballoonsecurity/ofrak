import asyncio
import logging
import os
import tempfile312 as tempfile
from dataclasses import dataclass
from subprocess import CalledProcessError

from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.resource import Resource
from ofrak.core.binary import GenericBinary
from ofrak.core.filesystem import File, Folder, FilesystemRoot, SpecialFileType
from ofrak.core.magic import MagicMimePattern, MagicDescriptionPattern

from ofrak.model.component_model import ComponentExternalTool
from ofrak_type.range import Range

LOGGER = logging.getLogger(__name__)

SEVEN_ZIP = ComponentExternalTool(
    "7zz", "https://www.7-zip.org", "--help", brew_package="sevenzip", choco_package="7zip"
)


@dataclass
class SevenZFilesystem(GenericBinary, FilesystemRoot):
    """
    Filesystem stored in a 7z archive.
    """


class SevenZUnpacker(Unpacker[None]):
    """
    Extracts files and directories from 7-Zip (.7z) compressed archives. The 7z format supports multiple compression algorithms including LZMA, LZMA2, and others. Use when encountering 7z-packaged software distributions, firmware bundles, or data archives. After extraction, files can be analyzed individually and later repacked if needed.
    """

    targets = (SevenZFilesystem,)
    children = (File, Folder, SpecialFileType)
    external_dependencies = (SEVEN_ZIP,)

    async def unpack(self, resource: Resource, config=None):
        seven_zip_v = await resource.view_as(SevenZFilesystem)
        resource_data = await seven_zip_v.resource.get_data()
        async with resource.temp_to_disk(suffix=".7z") as temp_path:
            with tempfile.TemporaryDirectory() as temp_flush_dir:
                cmd = [
                    "7zz",
                    "x",
                    f"-o{temp_flush_dir}",
                    temp_path,
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
    Compresses and packages files into 7-Zip archive format using LZMA or LZMA2 compression. Use after modifying extracted 7z contents to recreate compressed archives. Supports various compression methods, encryption, and solid compression.
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


MagicMimePattern.register(SevenZFilesystem, "application/x-7z-compressed")
MagicDescriptionPattern.register(SevenZFilesystem, lambda s: s.startswith("7-zip archive"))
