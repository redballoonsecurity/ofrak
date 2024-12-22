import logging
import subprocess
from dataclasses import dataclass
from subprocess import CalledProcessError

import tempfile312 as tempfile

from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.core.binary import GenericBinary
from ofrak.core.filesystem import File, Folder, FilesystemRoot, SpecialFileType
from ofrak.core.magic import MagicDescriptionIdentifier
from ofrak.model.component_model import ComponentExternalTool
from ofrak.resource import Resource
from ofrak_type.range import Range

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

    def unpack(self, resource: Resource, config=None):
        with resource.temp_to_disk() as temp_path:
            with tempfile.TemporaryDirectory() as temp_flush_dir:
                cmd = [
                    "jefferson",
                    "--force",
                    "--dest",
                    temp_flush_dir,
                    temp_path,
                ]
                proc = subprocess.run(cmd)
                if proc.returncode:
                    raise CalledProcessError(returncode=proc.returncode, cmd=cmd)
                jffs2_view = resource.view_as(Jffs2Filesystem)
                jffs2_view.initialize_from_disk(temp_flush_dir)


class Jffs2Packer(Packer[None]):
    """
    Pack files into a compressed JFFS2 filesystem.
    """

    targets = (Jffs2Filesystem,)
    external_dependencies = (MKFS_JFFS2,)

    def pack(self, resource: Resource, config=None):
        jffs2_view: Jffs2Filesystem = resource.view_as(Jffs2Filesystem)
        temp_flush_dir = jffs2_view.flush_to_disk()
        with tempfile.NamedTemporaryFile(suffix=".sqsh", mode="rb", delete_on_close=False) as temp:
            temp.close()
            cmd = [
                "mkfs.jffs2",
                "-r",
                temp_flush_dir,
                "-o",
                temp.name,
            ]
            proc = subprocess.run(cmd)
            if proc.returncode:
                raise CalledProcessError(returncode=proc.returncode, cmd=cmd)
            with open(temp.name, "rb") as new_fh:
                new_data = new_fh.read()
            # Passing in the original range effectively replaces the original data with the new data
            resource.queue_patch(Range(0, resource.get_data_length()), new_data)


MagicDescriptionIdentifier.register(Jffs2Filesystem, lambda s: "jffs2 filesystem" in s.lower())
