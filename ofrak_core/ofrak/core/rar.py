import asyncio
import tempfile312 as tempfile
from dataclasses import dataclass
from subprocess import CalledProcessError

from ofrak.component.unpacker import Unpacker
from ofrak.core.binary import GenericBinary
from ofrak.core.filesystem import FilesystemRoot, File, Folder, SpecialFileType

from ofrak.core.magic import MagicMimeIdentifier, MagicDescriptionIdentifier
from ofrak.model.component_model import ComponentExternalTool
from ofrak.resource import Resource
from ofrak.model.component_model import ComponentConfig

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
    Unpack RAR archives using the free `unar` tool.
    """

    targets = (RarArchive,)
    children = (File, Folder, SpecialFileType)
    external_dependencies = (UNAR,)

    async def unpack(self, resource: Resource, config: ComponentConfig = None):
        async with resource.temp_to_disk(suffix=".rar") as temp_archive:
            with tempfile.TemporaryDirectory() as temp_dir:
                cmd = [
                    "unar",
                    "-no-directory",
                    "-no-recursion",
                    temp_archive,
                ]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    cwd=temp_dir,
                )
                returncode = await proc.wait()
                if proc.returncode:
                    raise CalledProcessError(returncode=returncode, cmd=cmd)

                rar_view = await resource.view_as(RarArchive)
                await rar_view.initialize_from_disk(temp_dir)


MagicMimeIdentifier.register(RarArchive, "application/x-rar-compressed")
MagicMimeIdentifier.register(RarArchive, "application/vnd.rar")
MagicDescriptionIdentifier.register(RarArchive, lambda s: "rar archive" in s.lower())
