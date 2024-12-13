import asyncio
from subprocess import CalledProcessError

from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.resource import Resource
from ofrak.core.binary import GenericBinary
from ofrak.core.magic import MagicMimeIdentifier, MagicDescriptionIdentifier

from ofrak.model.component_model import ComponentExternalTool
from ofrak.model.component_model import ComponentConfig
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

    async def unpack(self, resource: Resource, config: ComponentConfig = None) -> None:
        cmd = ["lzop", "-d", "-f"]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        with await resource.get_data_memoryview() as data:
            stdout, stderr = await proc.communicate(data)
        if proc.returncode:
            raise CalledProcessError(returncode=proc.returncode, cmd=cmd)

        await resource.create_child(tags=(GenericBinary,), data=stdout)


class LzoPacker(Packer[None]):
    """
    Pack data into a compressed LZO file.
    """

    targets = (LzoData,)
    external_dependencies = (LZOP,)

    async def pack(self, resource: Resource, config: ComponentConfig = None):
        lzo_view = await resource.view_as(LzoData)

        cmd = ["lzop", "-f"]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        child_file = await lzo_view.get_child()
        with await child_file.resource.get_data_memoryview() as data:
            stdout, stderr = await proc.communicate(data)
        if proc.returncode:
            raise CalledProcessError(returncode=proc.returncode, cmd=cmd)

        compressed_data = stdout
        original_size = await lzo_view.resource.get_data_length()
        resource.queue_patch(Range(0, original_size), compressed_data)


MagicMimeIdentifier.register(LzoData, "application/x-lzop")
MagicDescriptionIdentifier.register(LzoData, lambda s: s.lower().startswith("lzop compressed data"))
