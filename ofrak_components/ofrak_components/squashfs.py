import logging
import subprocess
import tempfile
from dataclasses import dataclass
from subprocess import CalledProcessError

from ofrak import Packer, Unpacker, Resource
from ofrak.component.packer import PackerError
from ofrak.core import (
    File,
    Folder,
    FilesystemRoot,
    format_called_process_error,
    unpack_with_command,
    SpecialFileType,
    MagicMimeIdentifier,
    MagicDescriptionIdentifier,
)
from ofrak.core.binary import GenericBinary
from ofrak_type.range import Range

LOGGER = logging.getLogger(__name__)


@dataclass
class SquashfsFilesystem(GenericBinary, FilesystemRoot):
    """
    Filesystem stored in a squashfs format.
    """


class SquashfsUnpacker(Unpacker[None]):
    """Unpack a SquashFS filesystem."""

    targets = (SquashfsFilesystem,)
    children = (File, Folder, SpecialFileType)

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
                await unpack_with_command(command)

                squashfs_view = await resource.view_as(SquashfsFilesystem)
                await squashfs_view.initialize_from_disk(temp_flush_dir)


class SquashfsPacker(Packer[None]):
    """
    Pack files into a compressed squashfs filesystem.
    """

    targets = (SquashfsFilesystem,)

    async def pack(self, resource: Resource, config=None):
        squashfs_view: SquashfsFilesystem = await resource.view_as(SquashfsFilesystem)
        temp_flush_dir = await squashfs_view.flush_to_disk()
        with tempfile.NamedTemporaryFile(suffix=".sqsh", mode="rb") as temp:
            command = ["mksquashfs", temp_flush_dir, temp.name, "-noappend"]
            try:
                subprocess.run(command, check=True, capture_output=True)
            except CalledProcessError as error:
                raise PackerError(format_called_process_error(error))
            new_data = temp.read()
            # Passing in the original range effectively replaces the original data with the new data
            resource.queue_patch(Range(0, await resource.get_data_length()), new_data)


MagicMimeIdentifier.register(SquashfsFilesystem, "application/filesystem+sqsh")
MagicDescriptionIdentifier.register(
    SquashfsFilesystem, lambda s: s.startswith("Squashfs filesystem")
)
