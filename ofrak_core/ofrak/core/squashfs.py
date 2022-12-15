import logging
import subprocess
import tempfile
from dataclasses import dataclass

from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.resource import Resource
from ofrak.core.filesystem import File, Folder, FilesystemRoot, SpecialFileType

from ofrak.core.magic import MagicMimeIdentifier, MagicDescriptionIdentifier

from ofrak.core.binary import GenericBinary
from ofrak.model.component_model import ComponentExternalTool
from ofrak_type.range import Range

LOGGER = logging.getLogger(__name__)

MKSQUASHFS = ComponentExternalTool(
    "mksquashfs", "https://github.com/plougher/squashfs-tools.git", "-help"
)


class _UnsquashfsV45Tool(ComponentExternalTool):
    def __init__(self):
        super().__init__("unsquashfs", "https://github.com/plougher/squashfs-tools.git", "")

    def is_tool_installed(self) -> bool:
        try:
            result = subprocess.run(
                ["unsquashfs", "-help"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            return False

        if 0 != result.returncode:
            return False

        if b"-no-exit" not in result.stdout:
            # Version 4.5+ has the required -no-exit option
            return False

        return True


UNSQUASHFS = _UnsquashfsV45Tool()


@dataclass
class SquashfsFilesystem(GenericBinary, FilesystemRoot):
    """
    Filesystem stored in a squashfs format.
    """


class SquashfsUnpacker(Unpacker[None]):
    """Unpack a SquashFS filesystem."""

    targets = (SquashfsFilesystem,)
    children = (File, Folder, SpecialFileType)
    external_dependencies = (UNSQUASHFS,)

    async def unpack(self, resource: Resource, config=None):
        with tempfile.NamedTemporaryFile() as temp_file:
            resource_data = await resource.get_data()
            temp_file.write(resource_data)
            temp_file.flush()

            with tempfile.TemporaryDirectory() as temp_flush_dir:
                command = [
                    "unsquashfs",
                    "-no-exit-code",  # Don't return failure status code on warnings
                    "-force",  # Overwrite files that already exist
                    "-dest",
                    temp_flush_dir,
                    temp_file.name,
                ]
                subprocess.run(command, check=True, capture_output=True)

                squashfs_view = await resource.view_as(SquashfsFilesystem)
                await squashfs_view.initialize_from_disk(temp_flush_dir)


class SquashfsPacker(Packer[None]):
    """
    Pack files into a compressed squashfs filesystem.
    """

    targets = (SquashfsFilesystem,)
    external_dependencies = (MKSQUASHFS,)

    async def pack(self, resource: Resource, config=None):
        squashfs_view: SquashfsFilesystem = await resource.view_as(SquashfsFilesystem)
        temp_flush_dir = await squashfs_view.flush_to_disk()
        with tempfile.NamedTemporaryFile(suffix=".sqsh", mode="rb") as temp:
            command = ["mksquashfs", temp_flush_dir, temp.name, "-noappend"]
            subprocess.run(command, check=True, capture_output=True)
            new_data = temp.read()
            # Passing in the original range effectively replaces the original data with the new data
            resource.queue_patch(Range(0, await resource.get_data_length()), new_data)


MagicMimeIdentifier.register(SquashfsFilesystem, "application/filesystem+sqsh")
MagicDescriptionIdentifier.register(
    SquashfsFilesystem, lambda s: s.startswith("Squashfs filesystem")
)
