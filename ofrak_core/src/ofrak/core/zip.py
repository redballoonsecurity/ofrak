import asyncio
import logging
import os
import tempfile312 as tempfile
from dataclasses import dataclass
from subprocess import CalledProcessError

from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.resource import Resource
from ofrak.core.filesystem import File, Folder, FilesystemRoot, SpecialFileType
from ofrak.core.magic import MagicMimePattern, MagicDescriptionPattern
from ofrak.core.binary import GenericBinary

from ofrak.model.component_model import ComponentConfig, ComponentExternalTool
from ofrak_type.range import Range

LOGGER = logging.getLogger(__name__)

ZIP_TOOL = ComponentExternalTool(
    "zip",
    "https://linux.die.net/man/1/zip",
    install_check_arg="--help",
    apt_package="zip",
    brew_package="zip",
    choco_package="zip",
)
UNZIP_TOOL = ComponentExternalTool(
    "unzip",
    "https://linux.die.net/man/1/unzip",
    install_check_arg="--help",
    apt_package="unzip",
    brew_package="unzip",
    choco_package="unzip",
)


@dataclass
class ZipArchive(GenericBinary, FilesystemRoot):
    """
    Filesystem stored in a zip archive.
    """


class ZipUnpacker(Unpacker[None]):
    """
    Extracts files and directories from ZIP compressed archives using standard ZIP decompression.
    Use for any ZIP-packaged software distributions, firmware bundles, or data archives. After
    extraction, individual files can be analyzed, modified, and later repacked with ZipPacker.
    """

    targets = (ZipArchive,)
    children = (File, Folder, SpecialFileType)
    external_dependencies = (UNZIP_TOOL,)

    async def unpack(self, resource: Resource, config: ComponentConfig = None) -> None:
        zip_view = await resource.view_as(ZipArchive)
        async with resource.temp_to_disk(suffix=".zip") as temp_path:
            with tempfile.TemporaryDirectory() as temp_dir:
                cmd = [
                    "unzip",
                    temp_path,
                    "-d",
                    temp_dir,
                ]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                )
                returncode = await proc.wait()
                if proc.returncode:
                    raise CalledProcessError(returncode=returncode, cmd=cmd)
                await zip_view.initialize_from_disk(temp_dir)


@dataclass
class ZipPackerConfig(ComponentConfig):
    """
    Configuration for ZipPacker.

    :param compression_level: ZIP compression level from 0 (store, no compression) to 9 (maximum
        compression). Higher levels produce smaller archives at the cost of longer packing times.
        Defaults to 6, which balances compression ratio and speed.
    """

    compression_level: int = 6


class ZipPacker(Packer[ZipPackerConfig]):
    """
    Compresses and packages files into a ZIP archive format with standard compression algorithms.
    Use after modifying extracted ZIP contents to recreate the archive for distribution or
    deployment. The packer preserves directory structure and file attributes during compression.
    """

    targets = (ZipArchive,)
    external_dependencies = (ZIP_TOOL,)

    async def pack(self, resource: Resource, config: ZipPackerConfig = None) -> None:
        if config is None:
            config = ZipPackerConfig()
        if not 0 <= config.compression_level <= 9:
            raise ValueError("compression_level must be an integer from 0-9")

        zip_view: ZipArchive = await resource.view_as(ZipArchive)
        flush_dir = await zip_view.flush_to_disk()

        with tempfile.NamedTemporaryFile(suffix=".zip", delete_on_close=False) as temp_archive:
            temp_archive.close()
            os.unlink(
                temp_archive.name
            )  # zip fails if the output path exists but isn't a valid zip
            cmd = [
                "zip",
                f"-{config.compression_level}",
                "-r",
                temp_archive.name,
                ".",
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=flush_dir,
            )
            returncode = await proc.wait()
            if proc.returncode:
                raise CalledProcessError(returncode=returncode, cmd=cmd)

            with open(temp_archive.name, "rb") as fh:
                resource.queue_patch(Range(0, await resource.get_data_length()), fh.read())


MagicMimePattern.register(ZipArchive, "application/zip")
MagicDescriptionPattern.register(
    ZipArchive, lambda desc: any([("Zip archive data" in s) for s in desc.split(", ")])
)
