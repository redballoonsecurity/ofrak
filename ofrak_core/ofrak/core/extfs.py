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
from ofrak.model.component_model import ComponentExternalTool, ComponentConfig

_DEBUGFS = ComponentExternalTool(
    "debugfs", "https://e2fsprogs.sourceforge.net/", "-V", brew_package="e2fsprogs"
)


@dataclass
class ExtFilesystem(GenericBinary, FilesystemRoot):
    pass


@dataclass
class Ext2Filesystem(ExtFilesystem):
    """
    Linux EXT2 filesystem.
    """


@dataclass
class Ext3Filesystem(ExtFilesystem):
    """
    Linux EXT3 filesystem.
    """


@dataclass
class Ext4Filesystem(ExtFilesystem):
    """
    Linux EXT4 filesystem.
    """


class ExtUnpacker(Unpacker[None]):
    """
    Unpack a Linux EXT filesystem.
    """

    targets = (ExtFilesystem,)
    children = (File, Folder, SpecialFileType)
    external_dependencies = (_DEBUGFS,)

    async def unpack(self, resource: Resource, config: ComponentConfig = None) -> None:
        with tempfile.NamedTemporaryFile(suffix=".extfs") as temp_fs_file:
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

                fs_view = await resource.view_as(ExtFilesystem)
                await fs_view.initialize_from_disk(temp_dir)


MagicDescriptionIdentifier.register(Ext2Filesystem, lambda s: "ext2 filesystem" in s.lower())
MagicDescriptionIdentifier.register(Ext3Filesystem, lambda s: "ext3 filesystem" in s.lower())
MagicDescriptionIdentifier.register(Ext4Filesystem, lambda s: "ext4 filesystem" in s.lower())
