import asyncio
from dataclasses import dataclass
from typing import Optional
from subprocess import CalledProcessError

from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.core.binary import GenericBinary
from ofrak.core.magic import MagicMimePattern, MagicDescriptionPattern
from ofrak.model.component_model import ComponentConfig, ComponentExternalTool
from ofrak.resource import Resource
from ofrak_type.range import Range

ZSTD = ComponentExternalTool(
    "zstd",
    "http://facebook.github.io/zstd/",
    "--help",
    apt_package="zstd",
    brew_package="zstd",
    choco_package="zstd",
)


class ZstdData(GenericBinary):
    """
    A zstd binary blob.
    """

    async def get_child(self) -> GenericBinary:
        return await self.resource.get_only_child_as_view(GenericBinary)


@dataclass
class ZstdPackerConfig(ComponentConfig):
    """
    Config for zstd compression packer.

    :var compression_level: Zstandard compression level (1-22, higher = better compression but slower)
    """

    compression_level: int


class ZstdUnpacker(Unpacker[None]):
    """
    Decompresses Zstandard (zstd) compressed data. Use when encountering .zst files or
    zstd-compressed sections within larger binaries. After decompression, the resulting data can be
    further analyzed or unpacked if it contains additional structure.
    """

    id = b"ZstdUnpacker"
    targets = (ZstdData,)
    children = (GenericBinary,)
    external_dependencies = (ZSTD,)

    async def unpack(self, resource: Resource, config: ComponentConfig = None) -> None:
        cmd = ["zstd", "-d", "-k"]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE
        )
        result, _ = await proc.communicate(await resource.get_data())
        if proc.returncode:
            raise CalledProcessError(returncode=proc.returncode, cmd=cmd)

        await resource.create_child(tags=(GenericBinary,), data=result)


class ZstdPacker(Packer[ZstdPackerConfig]):
    """
    Compresses data using the Zstandard algorithm. Use after modifying decompressed zstd data to
    recreate .zst files or zstd-compressed sections.
    """

    targets = (ZstdData,)
    external_dependencies = (ZSTD,)

    async def pack(self, resource: Resource, config: Optional[ZstdPackerConfig] = None):
        if config is None:
            config = ZstdPackerConfig(compression_level=19)
        zstd_view = await resource.view_as(ZstdData)
        child_file = await zstd_view.get_child()
        uncompressed_data = await child_file.resource.get_data()

        command = ["zstd", "-T0", f"-{config.compression_level}"]
        if config.compression_level > 19:
            command.append("--ultra")
        proc = await asyncio.create_subprocess_exec(
            *command, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE
        )
        result, _ = await proc.communicate(uncompressed_data)
        if proc.returncode:
            raise CalledProcessError(returncode=proc.returncode, cmd=command)

        compressed_data = result
        original_size = await zstd_view.resource.get_data_length()
        resource.queue_patch(Range(0, original_size), compressed_data)


MagicMimePattern.register(ZstdData, "application/x-zstd")
MagicDescriptionPattern.register(
    ZstdData, lambda s: s.lower().startswith("zstandard compressed data")
)
