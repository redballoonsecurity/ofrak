import os
import asyncio
import logging
import tempfile312 as tempfile
from dataclasses import dataclass
from subprocess import CalledProcessError

from ofrak.component.unpacker import Unpacker
from ofrak.resource import Resource
from ofrak.core.filesystem import File, Folder, FilesystemRoot, SpecialFileType


from ofrak.model.component_model import ComponentExternalTool
from ofrak.core.pe.model import Pe

LOGGER = logging.getLogger(__name__)

UEFIEXTRACT = ComponentExternalTool("uefiextract", "https://github.com/LongSoft/UEFITool", "--help")


@dataclass
class Uefi(FilesystemRoot, Pe):
    """
    Filesystem extracted from a UEFI binary.
    """


class UefiUnpacker(Unpacker[None]):
    """
    Extracts components from UEFI (Unified Extensible Firmware Interface) firmware binaries, which
    contain multiple nested firmware volumes, files, and sections. Note that current limitations
    prevent repacking after modification. Use when analyzing UEFI firmware for security research,
    examining firmware updates, or extracting embedded drivers and applications.
    """

    targets = (Uefi,)
    children = (File, Folder, SpecialFileType)
    external_dependencies = (UEFIEXTRACT,)

    async def unpack(self, resource: Resource, config=None):
        ROM_FILE = "uefi.rom"

        with tempfile.TemporaryDirectory() as temp_flush_dir:
            # uefiextract always outputs to the CWD, so we must run this command from the temp dir to not leave behind artifacts
            os.chdir(temp_flush_dir)
            await resource.flush_data_to_disk(ROM_FILE)
            cmd = [
                "uefiextract",
                ROM_FILE,
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
            )
            returncode = await proc.wait()
            if proc.returncode:
                raise CalledProcessError(returncode=returncode, cmd=cmd)

            uefi_view = await resource.view_as(Uefi)
            await uefi_view.initialize_from_disk(os.path.join(temp_flush_dir, f"{ROM_FILE}.dump"))
