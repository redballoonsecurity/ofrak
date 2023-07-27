import asyncio
import logging
import tempfile
from dataclasses import dataclass
from subprocess import CalledProcessError

from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.resource import Resource
from ofrak.core.filesystem import File, Folder, FilesystemRoot, SpecialFileType

from ofrak.core.magic import MagicDescriptionIdentifier
from ofrak.core.binary import GenericBinary
from ofrak_type.range import Range
from ofrak.model.component_model import ComponentExternalTool

LOGGER = logging.getLogger(__name__)

JEFFERSON = ComponentExternalTool("jefferson", "https://pypi.org/project/jefferson/", "--help")

MKFS_JFFS2 = ComponentExternalTool(
    "mkfs.jffs2", "http://linux-mtd.infradead.org/", "-help", "mtd-utils"
)


@dataclass
class Jffs2Filesystem(GenericBinary, FilesystemRoot):
    """
    Filesystem stored in a JFFS2 format.
    """


class Jffs2Unpacker(Unpacker[None]):
    """Unpack a JFFS2 filesystem."""

    targets = (Jffs2Filesystem,)
    children = (File, Folder, SpecialFileType)
    external_dependencies = (JEFFERSON,)

    async def unpack(self, resource: Resource, config=None):
        with tempfile.NamedTemporaryFile() as temp_file:
            resource_data = await resource.get_data()
            temp_file.write(resource_data)
            temp_file.flush()

            with tempfile.TemporaryDirectory() as temp_flush_dir:
                cmd = [
                    "jefferson",
                    "--force",
                    "--dest",
                    temp_flush_dir,
                    temp_file.name,
                ]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                )
                returncode = await proc.wait()
                if proc.returncode:
                    raise CalledProcessError(returncode=returncode, cmd=cmd)

                jffs2_view = await resource.view_as(Jffs2Filesystem)
                await jffs2_view.initialize_from_disk(temp_flush_dir)


class Jffs2Packer(Packer[None]):
    """
    Pack files into a compressed JFFS2 filesystem.
    """

    targets = (Jffs2Filesystem,)
    external_dependencies = (MKFS_JFFS2,)

    async def pack(self, resource: Resource, config=None):
        jffs2_view: Jffs2Filesystem = await resource.view_as(Jffs2Filesystem)
        temp_flush_dir = await jffs2_view.flush_to_disk()
        with tempfile.NamedTemporaryFile(suffix=".sqsh", mode="rb") as temp:
            cmd = [
                "mkfs.jffs2",
                "-r",
                temp_flush_dir,
                "-o",
                temp.name,
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
            )
            returncode = await proc.wait()
            if proc.returncode:
                raise CalledProcessError(returncode=returncode, cmd=cmd)
            new_data = temp.read()
            # Passing in the original range effectively replaces the original data with the new data
            resource.queue_patch(Range(0, await resource.get_data_length()), new_data)


MagicDescriptionIdentifier.register(Jffs2Filesystem, lambda s: "jffs2 filesystem" in s.lower())
