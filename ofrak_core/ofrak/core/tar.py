import os.path
import subprocess
import tempfile
from dataclasses import dataclass

from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker, UnpackerError
from ofrak.resource import Resource
from ofrak.core.binary import GenericBinary
from ofrak.core.filesystem import FilesystemRoot, Folder, File, SpecialFileType
from ofrak.core.magic import MagicMimeIdentifier, MagicDescriptionIdentifier

from ofrak.model.component_model import CC, ComponentExternalTool
from ofrak_type.range import Range


TAR = ComponentExternalTool("tar", "https://www.gnu.org/software/tar/", "--help", apt_package="tar")


@dataclass
class TarArchive(GenericBinary, FilesystemRoot):
    """
    Filesystem stored in a tar archive.
    """


class TarUnpacker(Unpacker[None]):
    """
    Unpack a tar archive.
    """

    targets = (TarArchive,)
    children = (File, Folder, SpecialFileType)
    external_dependencies = (TAR,)

    async def unpack(self, resource: Resource, config: CC) -> None:
        # Write the archive data to a file
        with tempfile.NamedTemporaryFile(suffix=".tar") as temp_archive:
            temp_archive.write(await resource.get_data())
            temp_archive.flush()

            # Check the archive member files to ensure none unpack to a parent directory
            command = ["tar", "-P", "-tf", temp_archive.name]
            output = subprocess.run(command, check=True, capture_output=True)
            for filename in output.stdout.decode().splitlines():
                # Handles relative parent paths and rooted paths, and normalizes paths like "./../"
                rel_filename = os.path.relpath(filename)
                if rel_filename.startswith("../"):
                    raise UnpackerError(
                        f"Tar archive contains a file {filename} that would extract to a parent "
                        f"directory {rel_filename}."
                    )

            # Unpack into a temporary directory using the temporary file
            with tempfile.TemporaryDirectory() as temp_dir:
                command = ["tar", "--xattrs", "-C", temp_dir, "-xf", temp_archive.name]
                subprocess.run(command, check=True, capture_output=True)

                # Initialize a filesystem from the unpacked/untarred temporary folder
                tar_view = await resource.view_as(TarArchive)
                await tar_view.initialize_from_disk(temp_dir)


class TarPacker(Packer[None]):
    """
    Pack files into a tar archive.
    """

    targets = (TarArchive,)
    external_dependencies = (TAR,)

    async def pack(self, resource: Resource, config: CC) -> None:
        # Flush the child files to the filesystem
        tar_view = await resource.view_as(TarArchive)
        flush_dir = await tar_view.flush_to_disk()

        # Pack it back into a temporary archive
        with tempfile.NamedTemporaryFile(suffix=".tar") as temp_archive:
            command = ["tar", "--xattrs", "-C", flush_dir, "-cf", temp_archive.name, "."]
            subprocess.run(command, check=True, capture_output=True)

            # Replace the original archive data
            resource.queue_patch(Range(0, await resource.get_data_length()), temp_archive.read())


MagicMimeIdentifier.register(TarArchive, "application/x-tar")
MagicDescriptionIdentifier.register(TarArchive, lambda s: "tar archive" in s.lower())
