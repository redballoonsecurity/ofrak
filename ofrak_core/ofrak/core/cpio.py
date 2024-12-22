import logging
import subprocess

import tempfile312 as tempfile
from dataclasses import dataclass
from enum import Enum
from subprocess import CalledProcessError

from ofrak.component.analyzer import Analyzer
from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.core.binary import GenericBinary
from ofrak.core.filesystem import File, Folder, FilesystemRoot, SpecialFileType
from ofrak.core.magic import MagicMimeIdentifier, MagicDescriptionIdentifier, Magic
from ofrak.model.component_model import ComponentExternalTool
from ofrak.resource import Resource
from ofrak_type.range import Range

LOGGER = logging.getLogger(__name__)

CPIO_TOOL = ComponentExternalTool(
    "cpio",
    "https://www.gnu.org/software/cpio/",
    install_check_arg="--help",
    apt_package="cpio",
    brew_package="cpio",
)


class CpioArchiveType(Enum):
    """
    CPIO has several unrelated, incompatible variants.
    They're described in the man page:
    https://linux.die.net/man/1/cpio
    """

    BINARY = "bin"
    OLD_ASCII = "odc"
    NEW_ASCII = "newc"
    CRC_ASCII = "crc"
    TAR = "tar"
    USTAR = "ustar"
    HPBIN = "hpbin"
    HPODC = "hpodc"


@dataclass
class CpioFilesystem(GenericBinary, FilesystemRoot):
    """
    Filesystem stored in a CPIO archive.
    """

    archive_type: CpioArchiveType


class CpioFilesystemAnalyzer(Analyzer[None, CpioFilesystem]):
    targets = (CpioFilesystem,)
    outputs = (CpioFilesystem,)

    def analyze(self, resource: Resource, config=None) -> CpioFilesystem:
        _magic = resource.analyze(Magic)
        magic_description = _magic.descriptor
        if magic_description.startswith("ASCII cpio archive (SVR4 with no CRC)"):
            archive_type = CpioArchiveType.NEW_ASCII
        elif magic_description.startswith("ASCII cpio archive (pre-SVR4 or odc)"):
            archive_type = CpioArchiveType.OLD_ASCII
        elif magic_description.startswith("ASCII cpio archive (SVR4 with CRC)"):
            archive_type = CpioArchiveType.CRC_ASCII
        elif magic_description.startswith("cpio archive"):
            archive_type = CpioArchiveType.BINARY
        else:
            raise NotImplementedError(
                f"Please add support for CPIO archive type {magic_description}"
            )

        return CpioFilesystem(archive_type)


class CpioUnpacker(Unpacker[None]):
    """
    Unpack a CPIO archive.
    """

    targets = (CpioFilesystem,)
    children = (File, Folder, SpecialFileType)
    external_dependencies = (CPIO_TOOL,)

    def unpack(self, resource: Resource, config=None):
        cpio_v = resource.view_as(CpioFilesystem)
        resource_data = cpio_v.resource.get_data()
        with tempfile.TemporaryDirectory() as temp_flush_dir:
            cmd = [
                "cpio",
                "-id",
            ]
            result = subprocess.run(cmd, capture_output=True, cwd=temp_flush_dir)
            if result.returncode:
                raise CalledProcessError(returncode=result.returncode, cmd=cmd)
            cpio_v.initialize_from_disk(temp_flush_dir)


class CpioPacker(Packer[None]):
    """
    Pack files into a CPIO archive.
    """

    targets = (CpioFilesystem,)
    external_dependencies = (CPIO_TOOL,)

    def pack(self, resource: Resource, config=None):
        cpio_v: CpioFilesystem = resource.view_as(CpioFilesystem)
        temp_flush_dir = cpio_v.flush_to_disk()
        cpio_format = cpio_v.archive_type.value
        list_files_cmd = [
            "find",
            "-print",
        ]

        list_files_proc = subprocess.run(
            list_files_cmd,
            capture_output=True,
            cwd=temp_flush_dir,
        )
        if list_files_proc.returncode:
            raise CalledProcessError(returncode=list_files_proc.returncode, cmd=list_files_cmd)

        cpio_pack_cmd = [
            "cpio",
            "-o",
            f"--format={cpio_format}",
        ]
        cpio_pack_proc = subprocess.run(
            cpio_pack_cmd,
            capture_output=True,
            cwd=temp_flush_dir,
        )
        if cpio_pack_proc.returncode:
            raise CalledProcessError(returncode=cpio_pack_proc.returncode, cmd=cpio_pack_cmd)
        # Passing in the original range effectively replaces the original data with the new data
        resource.queue_patch(Range(0, resource.get_data_length()), cpio_pack_proc.stdout)


MagicMimeIdentifier.register(CpioFilesystem, "application/x-cpio")
MagicDescriptionIdentifier.register(CpioFilesystem, lambda s: "cpio archive" in s)
