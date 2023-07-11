import logging
from dataclasses import dataclass
from io import StringIO, BytesIO
from re import match
from typing import List, Union, Dict

try:
    from intelhex import IntelHex

    INTELHEX_INSTALLED = True
except ImportError:
    INTELHEX_INSTALLED = False

from ofrak import Identifier, Analyzer, Packer, Unpacker
from ofrak.component.unpacker import UnpackerError
from ofrak.core import MemoryRegion
from ofrak.core.binary import GenericBinary, GenericText
from ofrak.resource import Resource
from ofrak_type.range import Range

LOGGER = logging.getLogger(__name__)


@dataclass
class Ihex(GenericBinary):
    """
    Intel HEX is a binary blob packaging format encoded in ASCII. It splits binary data into records,
    which are lines of ASCII representing in hex the byte count, address, type, checksums of stored data.
    It is typically used for flashing firmware.

    # printf "Hello world!" | bin2hex.py -
    :0C00000048656C6C6F20776F726C642197
    :00000001FF
    """

    address_limits: Range
    start_addr: Union[None, Dict[str, int]]
    segments: List[Range]


class IhexAnalyzer(Analyzer[None, Ihex]):
    """
    Extract Intel HEX parameters
    """

    targets = (Ihex,)
    outputs = (Ihex,)

    async def analyze(self, resource: Resource, config=None) -> Ihex:
        ihex_data = (await resource.get_data()).decode("utf-8")
        ihex_obj = IntelHex(StringIO(ihex_data))

        return Ihex(
            # 0x0, (await resource.get_data_length()),
            Range(ihex_obj.minaddr(), ihex_obj.maxaddr()),
            ihex_obj.start_addr,
            [Range(*segment) for segment in ihex_obj.segments()],
        )


class IhexUnpacker(Unpacker[None]):
    """
    Extract the Intel Hex image into a GenericBinary
    """

    targets = (Ihex,)
    children = (GenericBinary, MemoryRegion)

    async def unpack(self, resource: Resource, config=None):
        ihex_data = (await resource.get_data()).decode("utf-8")
        ihex_obj = IntelHex(StringIO(ihex_data))
        bin_view = await resource.view_as(GenericBinary)
        ihex_view = await resource.view_as(Ihex)
        with BytesIO() as bin_io:
            ihex_obj.tofile(bin_io, format="bin")
            child = await resource.create_child_from_view(bin_view, data=bin_io.getvalue())

        for seg in ihex_view.segments:
            segment_data_range = seg.translate(-ihex_view.address_limits.start)
            await child.create_child_from_view(
                MemoryRegion(seg.start, seg.length()), data_range=segment_data_range
            )


class IhexPacker(Packer[None]):
    """
    Generate an Intel HEX file from an Ihex view
    """

    targets = (Ihex,)

    async def pack(self, resource: Resource, config=None) -> None:
        ihex_view: Ihex = await resource.view_as(Ihex)
        if ihex_view.start_addr is None or ihex_view.start_addr.get("EIP") is None:
            raise UnpackerError("Packing without an EIP not supported")
        bin_resource = await resource.get_only_child()
        bin_data = await bin_resource.get_data()
        ihex_obj = IntelHex()
        ihex_obj.loadbin(BytesIO(bin_data))
        with StringIO() as ihex_io:
            ihex_obj.tofile(
                ihex_io,
                format="hex",
                memory_offset=ihex_view.address_limits.start,
                pc_address=ihex_view.start_addr["EIP"],
            )
            resource.queue_patch(
                Range(0, await resource.get_data_length()), str.encode(ihex_io.getvalue())
            )


class IhexIdentifier(Identifier):
    """
    Regex-test the entire resource to check if it satisfies intel-hex formatting
    """

    targets = (GenericText,)

    async def identify(self, resource: Resource, config=None) -> None:
        datalength = await resource.get_data_length()
        if datalength >= 10:
            data = await resource.get_data()
            if match(r"(\:([0-9A-F]{2}){5,})(\n|\r\n)+", data.decode("utf-8")):
                resource.add_tag(Ihex)
