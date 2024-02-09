import logging
import re
import sys
from dataclasses import dataclass
from typing import List, Union, Tuple, Any

from ofrak.component.abstract import ComponentMissingDependencyError

try:
    from bincopy import BinFile

    BINCOPY_INSTALLED = True
except ImportError:
    BINCOPY_INSTALLED = False

from ofrak.component.analyzer import Analyzer
from ofrak.component.identifier import Identifier
from ofrak.component.packer import Packer
from ofrak.component.unpacker import Unpacker
from ofrak.core.binary import GenericBinary, GenericText
from ofrak.core.program_section import ProgramSection
from ofrak.core.program import Program
from ofrak.model.component_model import ComponentExternalTool
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceFilter
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


@dataclass
class IhexProgram(Program):
    address_limits: Range
    start_addr: Union[None, int]
    segments: List[Range]


_BINCOPY_TOOL = ComponentExternalTool(
    "bincopy",
    "https://github.com/eerimoq/bincopy",
    "--help",
)


class IhexAnalyzer(Analyzer[None, IhexProgram]):
    """
    Extract Intel HEX parameters
    """

    targets = (IhexProgram,)
    outputs = (IhexProgram,)

    external_dependencies = (_BINCOPY_TOOL,)

    async def analyze(self, resource: Resource, config: None = None) -> IhexProgram:
        raw_ihex = await resource.get_parent()
        ihex_program, _ = _binfile_analysis(await raw_ihex.get_data(), self)
        return ihex_program


class IhexUnpacker(Unpacker[None]):
    """
    Unpack an Intel HEX file, converting into raw bytes with padding bytes added to fill the gaps
    between segments. The result is a Program made up of a binary blob representing the entire
    memory space that the ihex file would load.
    """

    targets = (Ihex,)
    children = (IhexProgram,)

    external_dependencies = (_BINCOPY_TOOL,)

    async def unpack(self, resource: Resource, config=None):
        ihex_program, binfile = _binfile_analysis(await resource.get_data(), self)

        await resource.create_child_from_view(ihex_program, data=bytes(binfile.as_binary()))


class IhexProgramUnpacker(Unpacker[None]):
    """
    Unpack the individual segments from an Intel HEX Program's binary blob.
    """

    targets = (IhexProgram,)
    children = (ProgramSection,)

    async def unpack(self, resource: Resource, config=None):
        ihex_program = await resource.view_as(IhexProgram)
        for seg_vaddr_range in ihex_program.segments:
            # Segment is mapped into the program at an offset starting at the difference between
            # the segment's vaddr range and the program's base address
            segment_data_range = seg_vaddr_range.translate(-ihex_program.address_limits.start)
            await resource.create_child_from_view(
                ProgramSection(seg_vaddr_range.start, seg_vaddr_range.length()),
                data_range=segment_data_range,
            )


class IhexProgramPacker(Packer[None]):
    """
    Pack the segments of an Intel HEX program back into a binary blob. Recomputes segment size and
    program address range based on the actual segments at the time of packing.
    """

    targets = (IhexProgram,)

    async def pack(self, resource: Resource, config=None) -> None:
        updated_segments = []
        min_vaddr = sys.maxsize
        max_vaddr = 0
        for segment_r in await resource.get_children_as_view(
            ProgramSection, r_filter=ResourceFilter.with_tags(ProgramSection)
        ):
            seg_length = await segment_r.resource.get_data_length()
            seg_start = segment_r.virtual_address
            updated_segments.append(Range.from_size(seg_start, seg_length))
            min_vaddr = min(min_vaddr, seg_start)
            max_vaddr = max(max_vaddr, seg_start + seg_length)
        ihex_prog = await resource.view_as(IhexProgram)
        ihex_prog.segments = updated_segments
        ihex_prog.address_limits = Range(min_vaddr, max_vaddr)
        resource.add_view(ihex_prog)


class IhexPacker(Packer[None]):
    """
    Pack a binary blob representation of an Intel HEX program back into an Intel HEX file.
    """

    targets = (Ihex,)

    external_dependencies = (_BINCOPY_TOOL,)

    async def pack(self, resource: Resource, config=None) -> None:
        if not BINCOPY_INSTALLED:
            raise ComponentMissingDependencyError(self, _BINCOPY_TOOL)

        program_child = await resource.get_only_child_as_view(IhexProgram)
        vaddr_offset = -program_child.address_limits.start
        binfile = BinFile()
        binfile.execution_start_address = program_child.start_addr
        for seg in program_child.segments:
            seg_data = await program_child.resource.get_data(seg.translate(vaddr_offset))
            binfile.add_binary(seg_data, seg.start)

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
        matched_ihex = await resource.search_data(self._INTEL_HEX_PATTERN, max_matches=1)
        if matched_ihex:
            offset, bytes = matched_ihex[0]
            # Only tag if pattern starts at offset 0 of resource
            if offset == 0:
                resource.add_tag(Ihex)


def _binfile_analysis(raw_ihex: bytes, component) -> Tuple[IhexProgram, Any]:
    if not BINCOPY_INSTALLED:
        raise ComponentMissingDependencyError(component, _BINCOPY_TOOL)
    binfile = BinFile()
    binfile.add_ihex(raw_ihex.decode("utf-8"))

    ihex_program = IhexProgram(
        Range(binfile.minimum_address, binfile.maximum_address),
        binfile.execution_start_address,
        [Range(segment.minimum_address, segment.maximum_address) for segment in binfile.segments],
    )
    return ihex_program, binfile
