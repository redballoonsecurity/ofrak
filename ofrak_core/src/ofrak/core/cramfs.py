import asyncio
import os
import tempfile312 as tempfile
from dataclasses import dataclass
from subprocess import CalledProcessError

from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.core.binary import GenericBinary
from ofrak.core.filesystem import File, Folder, SpecialFileType, FilesystemRoot
from ofrak.core.magic import MagicDescriptionPattern
from ofrak.model.component_model import ComponentExternalTool
from ofrak.resource import Resource
from ofrak_type.range import Range

# mkfs.cramfs from util-linux 2.38.1
FSCK_CRAMFS = ComponentExternalTool(
    "fsck.cramfs",
    "",
    "--help",
)
MKFS_CRAMFS = ComponentExternalTool(
    "mkfs.cramfs",
    "",
    "--help",
)


@dataclass
class Cramfs(GenericBinary, FilesystemRoot):
    """
    Filesystem stored in CramFS format.
    """


class CramfsUnpacker(Unpacker[None]):
    """
    Extract files and directories from a Linux Compressed ROM filesystems.
    """

    targets = (Cramfs,)
    children = (File, Folder, SpecialFileType)
    external_dependencies = (FSCK_CRAMFS,)

    async def unpack(self, resource: Resource, config=None):
        async with resource.temp_to_disk() as temp_path:
            with tempfile.TemporaryDirectory() as temp_parent:
                temp_flush_dir = os.path.join(temp_parent, "cramfs_extract")
                cmd = [
                    FSCK_CRAMFS.tool,
                    f"--extract={temp_flush_dir}",
                    temp_path,
                ]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                )
                returncode = await proc.wait()
                if proc.returncode:
                    raise CalledProcessError(returncode=returncode, cmd=cmd)

                cramfs_view = await resource.view_as(Cramfs)
                await cramfs_view.initialize_from_disk(temp_flush_dir)


class CramFSPacker(Packer[None]):
    """
    Compress and package files into a Linux Compressed ROM File System.
    """

    targets = (Cramfs,)
    external_dependencies = (MKFS_CRAMFS,)

    async def pack(self, resource: Resource, config=None):
        cramfs_view: Cramfs = await resource.view_as(Cramfs)
        temp_flush_dir = await cramfs_view.flush_to_disk()
        with tempfile.NamedTemporaryFile(mode="rb", delete_on_close=False) as temp:
            temp.close()
            cmd = [
                MKFS_CRAMFS.tool,
                temp_flush_dir,
                temp.name,
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
            )
            returncode = await proc.wait()
            if proc.returncode:
                raise CalledProcessError(returncode=returncode, cmd=cmd)
            with open(temp.name, "rb") as new_fh:
                new_data = new_fh.read()
            # Passing in the original range effectively replaces the original data with the new data
            resource.queue_patch(Range(0, await resource.get_data_length()), new_data)


MagicDescriptionPattern.register(
    Cramfs, lambda s: s.startswith("Linux Compressed ROM File System data")
)
