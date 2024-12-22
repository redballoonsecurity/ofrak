import subprocess
from dataclasses import dataclass
from subprocess import CalledProcessError

import tempfile312 as tempfile

from ofrak.component.unpacker import Unpacker
from ofrak.core.binary import GenericBinary
from ofrak.core.filesystem import FilesystemRoot, File, Folder, SpecialFileType
from ofrak.core.magic import MagicMimeIdentifier, MagicDescriptionIdentifier
from ofrak.model.component_model import ComponentConfig
from ofrak.model.component_model import ComponentExternalTool
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
    Unpack RAR archives using the free `unar` tool.
    """

    targets = (RarArchive,)
    children = (File, Folder, SpecialFileType)
    external_dependencies = (UNAR,)

    def unpack(self, resource: Resource, config: ComponentConfig = None):
        with resource.temp_to_disk(suffix=".rar") as temp_archive:
            with tempfile.TemporaryDirectory() as temp_dir:
                cmd = [
                    "unar",
                    "-no-directory",
                    "-no-recursion",
                    temp_archive,
                ]
                proc = subprocess.run(cmd, cwd=temp_dir)
                if proc.returncode:
                    raise CalledProcessError(returncode=proc.returncode, cmd=cmd)

                rar_view = resource.view_as(RarArchive)
                rar_view.initialize_from_disk(temp_dir)


MagicMimeIdentifier.register(RarArchive, "application/x-rar-compressed")
MagicMimeIdentifier.register(RarArchive, "application/vnd.rar")
MagicDescriptionIdentifier.register(RarArchive, lambda s: "rar archive" in s.lower())
