import subprocess
import tempfile
from dataclasses import dataclass

from ofrak.component.unpacker import Unpacker
from ofrak.core.binary import GenericBinary
from ofrak.core.filesystem import FilesystemRoot, File, Folder, SpecialFileType

from ofrak.core.magic import MagicMimeIdentifier, MagicDescriptionIdentifier
from ofrak.model.component_model import CC, ComponentExternalTool
from ofrak.resource import Resource

UNAR = ComponentExternalTool(
    "unar",
    "https://theunarchiver.com/command-line",
    "--help",
    apt_package="unar",
    brew_package="unar",
)


@dataclass
class RarArchive(GenericBinary, FilesystemRoot):
    """
    Filesystem stored in a RAR archive.
    """


class RarUnpacker(Unpacker[None]):
    """
    Unpack RAR archives using the free `unrar` tool.
    """

    targets = (RarArchive,)
    children = (File, Folder, SpecialFileType)
    external_dependencies = (UNAR,)

    async def unpack(self, resource: Resource, config: CC):
        with tempfile.NamedTemporaryFile(
            suffix=".rar"
        ) as temp_archive, tempfile.TemporaryDirectory() as temp_dir:
            temp_archive.write(await resource.get_data())
            temp_archive.flush()

            command = ["unar", "-no-directory", "-no-recursion", temp_archive.name]
            subprocess.run(command, cwd=temp_dir, check=True, capture_output=True)

            rar_view = await resource.view_as(RarArchive)
            await rar_view.initialize_from_disk(temp_dir)


MagicMimeIdentifier.register(RarArchive, "application/x-rar-compressed")
MagicMimeIdentifier.register(RarArchive, "application/vnd.rar")
MagicDescriptionIdentifier.register(RarArchive, lambda s: "rar archive" in s.lower())
