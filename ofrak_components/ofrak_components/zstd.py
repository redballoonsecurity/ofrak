import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional

from ofrak import Packer, Unpacker, Resource
from ofrak.component.packer import PackerError
from ofrak.component.unpacker import UnpackerError
from ofrak.core import (
    GenericBinary,
    format_called_process_error,
    MagicMimeIdentifier,
    MagicDescriptionIdentifier,
)
from ofrak.model.component_model import CC, ComponentConfig
from ofrak_type.range import Range


class ZstdData(GenericBinary):
    """
    A zstd binary blob.
    """

    async def get_child(self) -> GenericBinary:
        return await self.resource.get_only_child_as_view(GenericBinary)


@dataclass
class ZstdPackerConfig(ComponentConfig):
    compression_level: int


class ZstdUnpacker(Unpacker[None]):
    """
    Unpack (decompress) a zstd file.
    """

    id = b"ZstdUnpacker"
    targets = (ZstdData,)
    children = (GenericBinary,)

    async def unpack(self, resource: Resource, config: CC) -> None:
        with tempfile.NamedTemporaryFile(suffix=".zstd") as compressed_file:
            compressed_file.write(await resource.get_data())
            compressed_file.flush()
            output_filename = tempfile.mktemp()

            command = ["zstd", "-d", "-k", compressed_file.name, "-o", output_filename]
            try:
                subprocess.run(command, check=True)
                with open(output_filename, "rb") as f:
                    result = f.read()
            except subprocess.CalledProcessError as e:
                raise UnpackerError(format_called_process_error(e))

            await resource.create_child(tags=(GenericBinary,), data=result)


class ZstdPacker(Packer[ZstdPackerConfig]):
    """
    Pack data into a compressed zstd file.
    """

    targets = (ZstdData,)

    async def pack(self, resource: Resource, config: Optional[ZstdPackerConfig] = None):
        if config is None:
            config = ZstdPackerConfig(compression_level=19)
        zstd_view = await resource.view_as(ZstdData)
        child_file = await zstd_view.get_child()
        uncompressed_data = await child_file.resource.get_data()

        with tempfile.NamedTemporaryFile() as uncompressed_file:
            uncompressed_file.write(uncompressed_data)
            uncompressed_file.flush()
            output_filename = tempfile.mktemp()

            command = ["zstd", "-T0", f"-{config.compression_level}"]
            if config.compression_level > 19:
                command.append("--ultra")
            command.extend([uncompressed_file.name, "-o", output_filename])
            try:
                subprocess.run(command, check=True)
                with open(output_filename, "rb") as f:
                    result = f.read()
            except subprocess.CalledProcessError as e:
                raise PackerError(format_called_process_error(e))

            compressed_data = result
            original_size = await zstd_view.resource.get_data_length()
            resource.queue_patch(Range(0, original_size), compressed_data)


MagicMimeIdentifier.register(ZstdData, "application/x-zstd")
MagicDescriptionIdentifier.register(
    ZstdData, lambda s: s.lower().startswith("zstandard compressed data")
)
