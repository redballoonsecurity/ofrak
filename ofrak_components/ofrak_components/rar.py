import subprocess
import tempfile
from dataclasses import dataclass

from ofrak import Unpacker, Resource
from ofrak.component.unpacker import UnpackerError
from ofrak.core import (
    FilesystemRoot,
    File,
    Folder,
    format_called_process_error,
    SpecialFileType,
    GenericBinary,
    MagicMimeIdentifier,
    MagicDescriptionIdentifier,
)
from ofrak.model.component_model import CC


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

    async def unpack(self, resource: Resource, config: CC):
        with tempfile.NamedTemporaryFile(
            suffix=".rar"
        ) as temp_archive, tempfile.TemporaryDirectory() as temp_dir:
            temp_archive.write(await resource.get_data())
            temp_archive.flush()

            command = ["unar", "-no-directory", "-no-recursion", temp_archive.name]
            try:
                subprocess.run(command, cwd=temp_dir, check=True, capture_output=True)
            except subprocess.CalledProcessError as e:  # pragma: no cover
                raise UnpackerError(format_called_process_error(e))

            rar_view = await resource.view_as(RarArchive)
            await rar_view.initialize_from_disk(temp_dir)


MagicMimeIdentifier.register(RarArchive, "application/x-rar-compressed")
MagicMimeIdentifier.register(RarArchive, "application/vnd.rar")
MagicDescriptionIdentifier.register(RarArchive, lambda s: "rar archive" in s.lower())
