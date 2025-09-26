import logging
import re
import sys
from dataclasses import dataclass
from typing import Any, List, Tuple, Union

from bincopy import BinFile

from ofrak.component.analyzer import Analyzer
from ofrak.component.identifier import Identifier
from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.core.binary import GenericBinary, GenericText
from ofrak.core.program import Program
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceFilter
from ofrak_type.range import Range
from ofrak.core import CodeRegion

LOGGER = logging.getLogger(__name__)


@dataclass
class Ihex(Program):
    """
    Intel HEX is a binary blob packaging format encoded in ASCII. It splits binary data into records,
    which are lines of ASCII representing in hex the byte count, address, type, checksums of stored data.
    It is typically used for flashing firmware.

    # printf "Hello world!" | bin2hex.py -
    :0C00000048656C6C6F20776F726C642197
    :00000001FF
    """
    start_addr: Union[None, int]


class IhexAnalyzer(Analyzer[None, Ihex]):
    """
    Extract Intel HEX parameters
    """

    targets = (Ihex,)
    outputs = (Ihex,)

    async def analyze(self, resource: Resource, config: None = None) -> Ihex:
        ihex, _ = _binfile_analysis(await resource.get_data(), self)
        return ihex


class IhexUnpacker(Unpacker[None]):
    """
    Unpack the individual segments from an Intel HEX Program's binary blob.
    """

    targets = (Ihex,)
    children = (CodeRegion,)

    async def unpack(self, resource: Resource, config=None):
        _, binfile = _binfile_analysis(await resource.get_data(), self)

        for segment in binfile.segments:
            segment_data = bytes(binfile.as_binary())[segment.minimum_address-binfile.minimum_address:segment.maximum_address-binfile.minimum_address]
            await resource.create_child_from_view(
                CodeRegion(segment.minimum_address, segment.maximum_address-segment.minimum_address),
                data=segment_data,
            )


class IhexPacker(Packer[None]):
    """
    Pack the segments of an Intel HEX program back into a binary blob. Recomputes segment size and
    program address range based on the actual segments at the time of packing.
    """

    targets = (Ihex,)

    async def pack(self, resource: Resource, config=None) -> None:
        ihex = await resource.view_as(Ihex)
        binfile = BinFile()
        segments = await resource.get_children_as_view(
            CodeRegion, r_filter=ResourceFilter.with_tags(CodeRegion)
        )
        if len(segments) == 0: # probably means that the ihex was never unpacked
            raw_ihex = await resource.get_data()
            binfile.add_ihex(raw_ihex.decode("utf-8"))
        else:
            for segment_r in segments:
                seg_data = await segment_r.resource.get_data()
                binfile.add_binary(seg_data, segment_r.virtual_address)

        binfile.execution_start_address = ihex.start_addr
        new_data = binfile.as_ihex()
        if new_data.endswith("\n"):
            new_data = new_data[:-1]
        new_data = new_data.encode("utf-8")
        old_data_len = await resource.get_data_length()
        resource.queue_patch(Range(0, old_data_len), new_data)


class IhexIdentifier(Identifier):
    """
    Regex-test the entire resource to check if it satisfies intel-hex formatting.

    This identifier tags any Resource whose first two lines match the ihex format.
    """

    targets = (GenericText,)

    # Matches on 2 lines that match ihex format
    _INTEL_HEX_PATTERN = re.compile(rb"((\:([0-9A-F]{2}){5,})(\n|\r\n)+){2}")

    async def identify(self, resource: Resource, config=None) -> None:
        matched_ihex = await resource.search_data(self._INTEL_HEX_PATTERN, 0, 0x2000, max_matches=1)
        if matched_ihex:
            offset, bytes = matched_ihex[0]
            # Only tag if pattern starts at offset 0 of resource
            if offset == 0:
                resource.add_tag(Ihex)


def _binfile_analysis(raw_ihex: bytes, component) -> Tuple[Ihex, Any]:
    binfile = BinFile()
    binfile.add_ihex(raw_ihex.decode("utf-8"))
    return Ihex(start_addr=binfile.execution_start_address), binfile


