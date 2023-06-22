import asyncio
import tempfile
from dataclasses import dataclass
from subprocess import CalledProcessError

from ofrak import Unpacker, Resource
from ofrak.core import (
    GenericBinary,
    FilesystemRoot,
    File,
    Folder,
    SpecialFileType,
    MagicDescriptionIdentifier,
)
from ofrak.model.component_model import ComponentExternalTool, CC

DEBUGFS = ComponentExternalTool(
    "debugfs", "https://e2fsprogs.sourceforge.net/", "-V", brew_package="e2fsprogs"
)


@dataclass
class Ext4Filesystem(GenericBinary, FilesystemRoot):
    """
    Linux EXT4 filesystem.
    """


class Ext4Unpacker(Unpacker[None]):
    """
    Unpack a Linux EXT4 filesystem.
    """

    targets = (Ext4Filesystem,)
    children = (File, Folder, SpecialFileType)
    external_dependencies = (DEBUGFS,)

    async def unpack(self, resource: Resource, config: CC = None) -> None:
        with tempfile.NamedTemporaryFile(suffix=".ext4") as temp_fs_file:
            temp_fs_file.write(await resource.get_data())
            temp_fs_file.flush()

            with tempfile.TemporaryDirectory() as temp_dir:
                command = [
                    "debugfs",
                    "-R",
                    f"rdump / {temp_dir}",
                    temp_fs_file.name,
                ]
                proc = await asyncio.create_subprocess_exec(
                    *command,
                )
                returncode = await proc.wait()
                if returncode:
                    raise CalledProcessError(returncode=returncode, cmd=command)

                fs_view = await resource.view_as(Ext4Filesystem)
                await fs_view.initialize_from_disk(temp_dir)


MagicDescriptionIdentifier.register(Ext4Filesystem, lambda s: "ext4 filesystem" in s.lower())
