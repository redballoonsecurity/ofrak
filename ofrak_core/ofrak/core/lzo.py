import subprocess
from subprocess import CalledProcessError

from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.core.binary import GenericBinary
from ofrak.core.magic import MagicMimePattern, MagicDescriptionPattern
from ofrak.model.component_model import ComponentConfig
from ofrak.model.component_model import ComponentExternalTool
from ofrak.resource import Resource
from ofrak_type.range import Range

LZOP = ComponentExternalTool(
    "lzop", "https://www.lzop.org/", "--help", apt_package="lzop", brew_package="lzop"
)


class LzoData(GenericBinary):
    """
    An lzo binary blob.
    """

    def get_child(self) -> GenericBinary:
        return self.resource.get_only_child_as_view(GenericBinary)


class LzoUnpacker(Unpacker[None]):
    """
    Unpack (decompress) an LZO file.
    """

    id = b"LzoUnpacker"
    targets = (LzoData,)
    children = (GenericBinary,)
    external_dependencies = (LZOP,)

    def unpack(self, resource: Resource, config: ComponentConfig = None) -> None:
        cmd = ["lzop", "-d", "-f"]
        proc = subprocess.run(
            cmd,
            input=resource.get_data(),
            capture_output=True,
        )
        if proc.returncode:
            raise CalledProcessError(returncode=proc.returncode, cmd=cmd)

        resource.create_child(tags=(GenericBinary,), data=proc.stdout)


class LzoPacker(Packer[None]):
    """
    Pack data into a compressed LZO file.
    """

    targets = (LzoData,)
    external_dependencies = (LZOP,)

    def pack(self, resource: Resource, config: ComponentConfig = None):
        lzo_view = resource.view_as(LzoData)
        child_file = lzo_view.get_child()
        uncompressed_data = child_file.resource.get_data()

        cmd = ["lzop", "-f"]
        proc = subprocess.run(
            cmd,
            input=uncompressed_data,
            capture_output=True,
        )
        if proc.returncode:
            raise CalledProcessError(returncode=proc.returncode, cmd=cmd)

        compressed_data = proc.stdout
        original_size = lzo_view.resource.get_data_length()
        resource.queue_patch(Range(0, original_size), compressed_data)


MagicMimePattern.register(LzoData, "application/x-lzop")
MagicDescriptionPattern.register(LzoData, lambda s: s.lower().startswith("lzop compressed data"))
