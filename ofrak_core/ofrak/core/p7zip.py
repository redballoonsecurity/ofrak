import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass

from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.resource import Resource
from ofrak.core.binary import GenericBinary
from ofrak.core.filesystem import File, Folder, FilesystemRoot, SpecialFileType
from ofrak.core.magic import MagicMimeIdentifier, MagicDescriptionIdentifier

from ofrak.model.component_model import ComponentExternalTool
from ofrak_type.range import Range

LOGGER = logging.getLogger(__name__)

SEVEN_ZIP = ComponentExternalTool(
    "7z", "https://p7zip.sourceforge.net/", "--help", apt_package="p7zip-full", brew_package="p7zip"
)


@dataclass
class P7zFilesystem(GenericBinary, FilesystemRoot):
    """
    Filesystem stored in a 7z archive.
    """


class P7zUnpacker(Unpacker[None]):
    """
    Unpack (decompress) a 7z file.
    """

    targets = (P7zFilesystem,)
    children = (File, Folder, SpecialFileType)
    external_dependencies = (SEVEN_ZIP,)

    async def unpack(self, resource: Resource, config=None):
        p7zip_v = await resource.view_as(P7zFilesystem)
        resource_data = await p7zip_v.resource.get_data()
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(resource_data)
            temp_file.flush()
            with tempfile.TemporaryDirectory() as temp_flush_dir:
                command = ["7z", "x", f"-o{temp_flush_dir}", temp_file.name]
                subprocess.run(command, check=True, capture_output=True)
                await p7zip_v.initialize_from_disk(temp_flush_dir)


class P7zPacker(Packer[None]):
    """
    Pack files into a compressed 7z archive.
    """

    targets = (P7zFilesystem,)
    external_dependencies = (SEVEN_ZIP,)

    async def pack(self, resource: Resource, config=None):
        p7zip_v: P7zFilesystem = await resource.view_as(P7zFilesystem)
        temp_flush_dir = await p7zip_v.flush_to_disk()
        temp_flush_dir = os.path.join(temp_flush_dir, ".")
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_name = os.path.join(temp_dir, "temp.7z")
            command = ["7z", "a", temp_name, temp_flush_dir]
            subprocess.run(command, check=True, capture_output=True)
            with open(temp_name, "rb") as f:
                new_data = f.read()
            # Passing in the original range effectively replaces the original data with the new data
            resource.queue_patch(Range(0, await resource.get_data_length()), new_data)


MagicMimeIdentifier.register(P7zFilesystem, "application/x-7z-compressed")
MagicDescriptionIdentifier.register(P7zFilesystem, lambda s: s.startswith("7-zip archive"))
