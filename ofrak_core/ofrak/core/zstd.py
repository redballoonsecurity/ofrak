import subprocess
from dataclasses import dataclass
from typing import Optional
from subprocess import CalledProcessError

from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.core.binary import GenericBinary
from ofrak.core.magic import MagicMimeIdentifier, MagicDescriptionIdentifier
from ofrak.model.component_model import ComponentConfig, ComponentExternalTool
from ofrak.resource import Resource
from ofrak_type.range import Range

ZSTD = ComponentExternalTool(
    "zstd", "http://facebook.github.io/zstd/", "--help", apt_package="zstd", brew_package="zstd"
)


class ZstdData(GenericBinary):
    """
    A zstd binary blob.
    """

    def get_child(self) -> GenericBinary:
        return self.resource.get_only_child_as_view(GenericBinary)


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
    external_dependencies = (ZSTD,)

    def unpack(self, resource: Resource, config: ComponentConfig = None) -> None:
        cmd = ["zstd", "-d", "-k"]
        proc = subprocess.run(cmd, input=resource.get_data(), capture_output=True)
        if proc.returncode:
            raise CalledProcessError(returncode=proc.returncode, cmd=cmd)

        resource.create_child(tags=(GenericBinary,), data=proc.stdout)


class ZstdPacker(Packer[ZstdPackerConfig]):
    """
    Pack data into a compressed zstd file.
    """

    targets = (ZstdData,)
    external_dependencies = (ZSTD,)

    def pack(self, resource: Resource, config: Optional[ZstdPackerConfig] = None):
        if config is None:
            config = ZstdPackerConfig(compression_level=19)
        zstd_view = resource.view_as(ZstdData)
        child_file = zstd_view.get_child()
        uncompressed_data = child_file.resource.get_data()

        command = ["zstd", "-T0", f"-{config.compression_level}"]
        if config.compression_level > 19:
            command.append("--ultra")
        proc = subprocess.run(
            command,
            input=uncompressed_data,
            capture_output=True,
        )
        if proc.returncode:
            raise CalledProcessError(returncode=proc.returncode, cmd=command)

        compressed_data = proc.stdout
        original_size = zstd_view.resource.get_data_length()
        resource.queue_patch(Range(0, original_size), compressed_data)


MagicMimeIdentifier.register(ZstdData, "application/x-zstd")
MagicDescriptionIdentifier.register(
    ZstdData, lambda s: s.lower().startswith("zstandard compressed data")
)
