import logging
import subprocess
import tempfile
from dataclasses import dataclass
from enum import Enum
from subprocess import CalledProcessError

from ofrak import Analyzer, Packer, Unpacker, Resource
from ofrak.component.packer import PackerError
from ofrak.component.unpacker import UnpackerError
from ofrak.core import (
    GenericBinary,
    File,
    Folder,
    FilesystemRoot,
    format_called_process_error,
    SpecialFileType,
    MagicMimeIdentifier,
    MagicDescriptionIdentifier,
    Magic,
)
from ofrak_type.range import Range

LOGGER = logging.getLogger(__name__)


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

    async def analyze(self, resource: Resource, config=None) -> CpioFilesystem:
        _magic = await resource.analyze(Magic)
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

    async def unpack(self, resource: Resource, config=None):
        cpio_v = await resource.view_as(CpioFilesystem)
        resource_data = await cpio_v.resource.get_data()
        with tempfile.NamedTemporaryFile() as temp_file:
            temp_file.write(resource_data)
            temp_file.flush()
            with tempfile.TemporaryDirectory() as temp_flush_dir:
                # Use subshell to handle relative paths and avoid changing directories back and
                # forth
                command = f"(cd {temp_flush_dir} && cpio -id < {temp_file.name})"
                try:
                    subprocess.run(command, check=True, capture_output=True, shell=True)
                except subprocess.CalledProcessError as error:
                    raise UnpackerError(format_called_process_error(error))
                await cpio_v.initialize_from_disk(temp_flush_dir)


class CpioPacker(Packer[None]):
    """
    Pack files into a CPIO archive.
    """

    targets = (CpioFilesystem,)

    async def pack(self, resource: Resource, config=None):
        cpio_v: CpioFilesystem = await resource.view_as(CpioFilesystem)
        temp_flush_dir = await cpio_v.flush_to_disk()
        cpio_format = cpio_v.archive_type.value
        with tempfile.NamedTemporaryFile(suffix=".cpio", mode="rb") as temp:
            # Use subshell to handle relative paths and avoid changing directories back and forth
            command = f"(cd {temp_flush_dir} && find . -print | cpio -o --format={cpio_format} > {temp.name})"
            try:
                subprocess.run(command, check=True, capture_output=True, shell=True)
            except CalledProcessError as error:
                raise PackerError(format_called_process_error(error))
            new_data = temp.read()
            # Passing in the original range effectively replaces the original data with the new data
            resource.queue_patch(Range(0, await resource.get_data_length()), new_data)


MagicMimeIdentifier.register(CpioFilesystem, "application/x-cpio")
MagicDescriptionIdentifier.register(CpioFilesystem, lambda s: "cpio archive" in s)
