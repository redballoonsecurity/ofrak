import subprocess
import tempfile

from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.resource import Resource
from ofrak.core.binary import GenericBinary
from ofrak.core.magic import MagicMimeIdentifier, MagicDescriptionIdentifier

from ofrak.model.component_model import CC, ComponentExternalTool
from ofrak_type.range import Range

LZOP = ComponentExternalTool(
    "lzop", "https://www.lzop.org/", "--help", apt_package="lzop", brew_package="lzop"
)


class LzoData(GenericBinary):
    """
    An lzo binary blob.
    """

    async def get_child(self) -> GenericBinary:
        return await self.resource.get_only_child_as_view(GenericBinary)


class LzoUnpacker(Unpacker[None]):
    """
    Unpack (decompress) an LZO file.
    """

    id = b"LzoUnpacker"
    targets = (LzoData,)
    children = (GenericBinary,)
    external_dependencies = (LZOP,)

    async def unpack(self, resource: Resource, config: CC) -> None:
        with tempfile.NamedTemporaryFile(suffix=".lzo") as compressed_file:
            compressed_file.write(await resource.get_data())
            compressed_file.flush()

            command = ["lzop", "-d", "-f", "-c", compressed_file.name]
            result = subprocess.run(command, check=True, capture_output=True)

            await resource.create_child(tags=(GenericBinary,), data=result.stdout)


class LzoPacker(Packer[None]):
    """
    Pack data into a compressed LZO file.
    """

    targets = (LzoData,)
    external_dependencies = (LZOP,)

    async def pack(self, resource: Resource, config=None):
        lzo_view = await resource.view_as(LzoData)
        child_file = await lzo_view.get_child()
        uncompressed_data = await child_file.resource.get_data()

        with tempfile.NamedTemporaryFile(suffix=".lzo") as uncompressed_file:
            uncompressed_file.write(uncompressed_data)
            uncompressed_file.flush()

            command = ["lzop", "-f", "-c", uncompressed_file.name]
            result = subprocess.run(command, check=True, capture_output=True)

            compressed_data = result.stdout
            original_size = await lzo_view.resource.get_data_length()
            resource.queue_patch(Range(0, original_size), compressed_data)


MagicMimeIdentifier.register(LzoData, "application/x-lzop")
MagicDescriptionIdentifier.register(LzoData, lambda s: s.lower().startswith("lzop compressed data"))
