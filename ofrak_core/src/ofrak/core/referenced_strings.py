"""
Derive which functions reference which C strings from the function→data cross-references that a
disassembler backend provides.

Only the Ghidra and Binary Ninja backends implement a
[ReferencedDataAnalyzer][ofrak.core.program.ReferencedDataAnalyzer], so this module raises a
[ReferencedDataUnavailableError][ofrak.core.referenced_strings.ReferencedDataUnavailableError] on
any other backend rather than silently finding no strings.
"""
import bisect
import logging
from typing import Dict, List, Optional, Sequence, Set, Tuple

from ofrak.core.architecture import ProgramAttributes
from ofrak.core.basic_block import BasicBlock
from ofrak.core.complex_block import ComplexBlock
from ofrak.core.data import DataWord, ReferencedDataAttributes, ReferencedStringsAttributes
from ofrak.core.elf.model import ElfSection, ElfSectionFlag, ElfSegment
from ofrak.core.instruction import Instruction
from ofrak.core.memory_region import MemoryRegion
from ofrak.core.program import Program, ReferencedStringsAnalyzer
from ofrak.model.component_filters import (
    AnalyzerOutputFilter,
    ComponentAndMetaFilter,
    ComponentTargetFilter,
)
from ofrak.resource import Resource, ResourceFactory
from ofrak.service.component_locator_i import ComponentLocatorInterface
from ofrak.service.data_service_i import DataServiceInterface
from ofrak.service.resource_service_i import ResourceFilter, ResourceServiceInterface
from ofrak_type.endianness import Endianness
from ofrak_type.error import NotFoundError
from ofrak_type.range import Range

LOGGER = logging.getLogger(__name__)

# Shortest string kept, in bytes, not counting the NUL terminator: shorter data is too often not
# text (e.g. a small integer constant), and too common to identify a function
MIN_STRING_LENGTH = 2
# Data without a NUL terminator within this many bytes is not treated as a C string
MAX_STRING_LENGTH = 4096
# Characters other than printable ones that commonly appear in string literals
_ALLOWED_WHITESPACE = frozenset("\t\n\r")
# Memory regions that make up the structure of code, inside code regions: their bytes are read from
# the code region instead
_CODE_STRUCTURE_TAGS = (ComplexBlock, BasicBlock, Instruction, DataWord)


class ReferencedDataUnavailableError(RuntimeError):
    """
    Raised when a component needs function→data cross-references
    ([ReferencedDataAttributes][ofrak.core.data.ReferencedDataAttributes]) but no analyzer able to
    produce them is available for the resource.
    """


class DerivedReferencedStringsAnalyzer(ReferencedStringsAnalyzer):
    """
    Finds which functions reference which C strings, derived from the function→data cross-references
    computed by the disassembler backend. Every referenced data address whose bytes decode as a
    printable, NUL-terminated UTF-8 string of `MIN_STRING_LENGTH` to `MAX_STRING_LENGTH` bytes
    becomes a referenced string, and every function
    ([ComplexBlock][ofrak.core.complex_block.ComplexBlock]) containing an address that references it
    gets an edge to that string. Use as the substrate for locating functions by the strings they
    use, e.g. for anchor-based or portable markup.

    The program is unpacked into code regions, and its code regions into complex blocks, if that
    has not been done already. In the resulting
    [ReferencedStringsAttributes][ofrak.core.data.ReferencedStringsAttributes],
    `referencing_functions` are complex block virtual addresses and each of `referenced_strings`
    is the virtual address range of the string's bytes, excluding the NUL terminator, both at the
    backend's addresses. Use
    [get_function_string_references][ofrak.core.referenced_strings.get_function_string_references]
    to get the decoded text.

    Bytes are only read from memory regions loaded in memory: not from ELF sections without the
    `SHF_ALLOC` flag, such as debug information, and strings are never inside a function. When the
    backend has moved the code of a position-independent ELF to other addresses than the file's,
    as Ghidra does, the referenced addresses are translated back to those of the file. A string
    short enough to fit in a pointer, at a pointer-aligned address, is taken for a pointer (an
    entry of a pointer or jump table, or of a literal pool) rather than text if the backend found
    a reference at its address, or if its bytes are an address the backend found references to,
    the start of a function, or an address of the program's memory (including memory without data
    in the file, like `.bss`). Only the references the backend found count: a string reached only
    through a pointer table in data is not attributed to the function that reads the table.

    This analyzer only runs when requested, e.g. with `resource.run`, by
    [get_function_string_references][ofrak.core.referenced_strings.get_function_string_references]
    or by the markup components: it is not part of blanket analysis such as
    `Resource.analyze_recursively`, since it requires a backend that provides function→data
    cross-references (Ghidra or Binary Ninja), and raises
    [ReferencedDataUnavailableError][ofrak.core.referenced_strings.ReferencedDataUnavailableError]
    otherwise.
    """

    id = b"DerivedReferencedStringsAnalyzer"
    # No targets, so that analysis of every analyzer targeting a program does not include this one
    targets = ()

    def __init__(
        self,
        resource_factory: ResourceFactory,
        data_service: DataServiceInterface,
        resource_service: ResourceServiceInterface,
        component_locator: ComponentLocatorInterface,
    ):
        super().__init__(resource_factory, data_service, resource_service)
        self._component_locator = component_locator

    async def analyze(self, resource: Resource, config=None) -> Tuple[ReferencedStringsAttributes]:
        data_refs = await get_referenced_data(resource, self._component_locator)
        program = await resource.view_as(Program)
        functions = await _FunctionIndex.create(program)
        memory = await _VirtualMemory.create(program, data_refs, functions)

        # Referenced data address -> range of the C string there, or None if it is not one
        string_ranges: Dict[int, Optional[Range]] = dict()
        edges: Set[Tuple[int, int]] = set()
        for referencing_address, data_vaddrs in data_refs.get_xrefs_from().items():
            function_vaddr = functions.get_function_containing(referencing_address)
            if function_vaddr is None:
                # The reference comes from data (e.g. a pointer table) or unanalyzed code
                continue
            for data_vaddr in data_vaddrs:
                if data_vaddr not in string_ranges:
                    string_ranges[data_vaddr] = await memory.find_c_string(data_vaddr)
                if string_ranges[data_vaddr] is not None:
                    edges.add((function_vaddr, data_vaddr))

        strings_by_vaddr = {
            vaddr: string_range
            for vaddr, string_range in string_ranges.items()
            if string_range is not None
        }
        # If the backend's addresses are not the program's, references point outside of it
        outside = sum(1 for vaddr in string_ranges if not memory.contains(vaddr))
        log = LOGGER.warning if string_ranges and outside == len(string_ranges) else LOGGER.debug
        log(
            f"{outside} of the {len(string_ranges)} data addresses referenced by the functions of "
            f"{resource.get_id().hex()} are outside of its memory regions"
        )

        function_vaddrs = sorted({function_vaddr for function_vaddr, _ in edges})
        string_vaddrs = sorted(strings_by_vaddr.keys())
        function_index = {vaddr: i for i, vaddr in enumerate(function_vaddrs)}
        string_index = {vaddr: i for i, vaddr in enumerate(string_vaddrs)}
        return (
            ReferencedStringsAttributes(
                referencing_functions=tuple(function_vaddrs),
                referenced_strings=tuple(strings_by_vaddr[vaddr] for vaddr in string_vaddrs),
                references=tuple(
                    sorted(
                        (function_index[function_vaddr], string_index[data_vaddr])
                        for function_vaddr, data_vaddr in edges
                    )
                ),
            ),
        )


async def get_referenced_data(
    resource: Resource, component_locator: ComponentLocatorInterface
) -> ReferencedDataAttributes:
    """
    Get the function→data cross-references of a program, analyzing them if needed.

    :param resource: A program resource
    :param component_locator: Used to check that some analyzer can produce the cross-references

    :raises ReferencedDataUnavailableError: if the references are not already present and no
    registered analyzer can produce them for this resource

    :return: The program's data cross-references
    """
    if not resource.has_attributes(ReferencedDataAttributes):
        producers = component_locator.get_components_matching_filter(
            ComponentAndMetaFilter(
                AnalyzerOutputFilter(ReferencedDataAttributes),
                ComponentTargetFilter(*resource.get_tags()),
            )
        )
        if not producers:
            raise ReferencedDataUnavailableError(
                f"Resource {resource.get_id().hex()} has no function→data cross-references "
                f"(ReferencedDataAttributes) and no registered analyzer can produce them. Only "
                f"the Ghidra (ofrak_ghidra) and Binary Ninja (ofrak_binary_ninja) backends "
                f"provide them; discover one of those packages, e.g. "
                f"`ofrak.discover(ofrak_ghidra)`."
            )
    return await resource.analyze(ReferencedDataAttributes)


async def get_function_string_references(program: Program) -> Dict[int, Tuple[str, ...]]:
    """
    Get the decoded text of the strings each function in a program references, running
    [the derived strings analyzer][ofrak.core.referenced_strings.DerivedReferencedStringsAnalyzer]
    if the program does not have
    [ReferencedStringsAttributes][ofrak.core.data.ReferencedStringsAttributes] yet, or if one of
    its strings changed since (the program was patched).

    :param program: The program to inspect

    :raises ReferencedDataUnavailableError: if no backend can provide data cross-references

    :return: A mapping from the virtual address of each function that references at least one
    string to the texts of those strings, sorted and without duplicates
    """
    resource = program.resource
    if resource.has_attributes(ReferencedStringsAttributes) and not await _are_strings_unchanged(
        program
    ):
        # OFRAK does not run an analyzer again on its own, so forget the outdated analysis
        resource.remove_component(
            DerivedReferencedStringsAnalyzer.get_id(), ReferencedStringsAttributes
        )
        resource.remove_attributes(ReferencedStringsAttributes)
        await resource.save()
    if not resource.has_attributes(ReferencedStringsAttributes):
        await resource.run(DerivedReferencedStringsAnalyzer)
    strings_attributes = resource.get_attributes(ReferencedStringsAttributes)
    memory = await _get_memory(program)
    texts: List[str] = []
    for string_range in strings_attributes.referenced_strings:
        texts.append((await memory.read(string_range)).decode("utf-8"))

    strings_by_function: Dict[int, Set[str]] = dict()
    for function_idx, string_idx in strings_attributes.references:
        function_vaddr = strings_attributes.referencing_functions[function_idx]
        strings_by_function.setdefault(function_vaddr, set()).add(texts[string_idx])
    return {
        function_vaddr: tuple(sorted(function_strings))
        for function_vaddr, function_strings in strings_by_function.items()
    }


async def _are_strings_unchanged(program: Program) -> bool:
    """
    OFRAK does not know that the program's
    [ReferencedStringsAttributes][ofrak.core.data.ReferencedStringsAttributes] depend on the bytes
    of the strings, which patching the program can change.

    :return: Whether each string of the attributes is still the C string at its address
    """
    memory = await _get_memory(program)
    attributes = program.resource.get_attributes(ReferencedStringsAttributes)
    for string_range in attributes.referenced_strings:
        if await memory.find_c_string(string_range.start) != string_range:
            return False
    return True


async def _get_memory(program: Program) -> "_VirtualMemory":
    """
    :return: The memory of a program whose referenced strings were analyzed
    """
    functions = await _FunctionIndex.create(program)
    data_refs = await program.resource.analyze(ReferencedDataAttributes)
    return await _VirtualMemory.create(program, data_refs, functions)


def _is_c_string_text(text: str) -> bool:
    """
    :return: True if every character of `text` is printable or common whitespace (tab, newline,
    carriage return)
    """
    return all(character.isprintable() or character in _ALLOWED_WHITESPACE for character in text)


class _FunctionIndex:
    """
    Map addresses to the complex block (function) containing them.
    """

    def __init__(self, complex_blocks: Sequence[ComplexBlock]):
        self._blocks = sorted(complex_blocks, key=lambda block: block.virtual_address)
        self.function_vaddrs = [block.virtual_address for block in self._blocks]

    @staticmethod
    async def create(program: Program) -> "_FunctionIndex":
        """
        Index the functions of a program, unpacking it into code regions and its code regions into
        complex blocks first if that has not been done already, so that no function is left out
        of an analysis (which would be kept as is).
        """
        if not list(await program.get_code_regions()):
            await program.resource.unpack()
        await _unpack_code_regions(program)
        complex_blocks = await program.resource.get_descendants_as_view(
            ComplexBlock, r_filter=ResourceFilter.with_tags(ComplexBlock)
        )
        return _FunctionIndex(list(complex_blocks))

    def get_function_containing(self, vaddr: int) -> Optional[int]:
        """
        :return: The virtual address of the complex block containing `vaddr`, if there is one
        """
        idx = bisect.bisect_right(self.function_vaddrs, vaddr) - 1
        if idx >= 0 and self._blocks[idx].contains(vaddr):
            return self._blocks[idx].virtual_address
        return None


async def _unpack_code_regions(program: Program):
    """
    Unpack the program's code regions into complex blocks, unless that has already been done.
    """
    for code_region in await program.get_code_regions():
        complex_blocks = await code_region.resource.get_children(
            r_filter=ResourceFilter.with_tags(ComplexBlock)
        )
        if not any(True for _ in complex_blocks):
            await code_region.resource.unpack()


async def _is_program_memory(region: MemoryRegion) -> bool:
    """
    :return: Whether the region is some of the program's memory: it is not an ELF section left out
    of memory (without `SHF_ALLOC`), and not part of the structure of code, like a complex block,
    which is in the code region around it
    """
    if any(region.resource.has_tag(tag) for tag in _CODE_STRUCTURE_TAGS):
        return False
    if region.resource.has_tag(ElfSection):
        header = await (await region.resource.view_as(ElfSection)).get_header()
        return header.has_flag(ElfSectionFlag.ALLOC)
    return True


async def _get_code_offsets(program: Program) -> Dict[bytes, int]:
    """
    A backend may load a position-independent ELF at a higher address than the file's (Ghidra adds
    0x100000), and move OFRAK's code regions to its addresses, to match its functions, but not the
    other memory regions. Its cross-references, to code and data alike, are then at its addresses.

    :return: For each ELF section or segment that is a code region, by resource ID, how much higher
    its address is than in the file
    """
    offsets: Dict[bytes, int] = dict()
    for code_region in await program.get_code_regions():
        code_region_id = code_region.resource.get_id()
        if code_region.resource.has_tag(ElfSection):
            section_header = await (await code_region.resource.view_as(ElfSection)).get_header()
            offsets[code_region_id] = code_region.virtual_address - section_header.sh_addr
        elif code_region.resource.has_tag(ElfSegment):
            program_header = await (await code_region.resource.view_as(ElfSegment)).get_header()
            offsets[code_region_id] = code_region.virtual_address - program_header.p_vaddr
    return offsets


class _VirtualMemory:
    """
    Read the bytes of a program at the addresses of the backend's cross-references. Each address is
    resolved to the largest memory region containing it, as in
    [Program.get_memory_region_for_vaddr][ofrak.core.program.Program.get_memory_region_for_vaddr],
    among the regions of the program's memory (see `_is_program_memory`), and the regions are only
    looked up once for all reads.

    :param regions: The memory regions, largest first, each with its virtual address in the file
    :param backend_offset: How much higher the backend placed the program than the file does
    :param program_attributes: The architecture of the program, for the format of its pointers
    :param reference_sources: The addresses the backend found references at
    :param known_addresses: The addresses the backend found references to, and those of functions
    :param functions: The program's functions
    """

    def __init__(
        self,
        regions: Sequence[Tuple[int, MemoryRegion]],
        backend_offset: int,
        program_attributes: ProgramAttributes,
        reference_sources: Set[int],
        known_addresses: Set[int],
        functions: "_FunctionIndex",
    ):
        self._regions = regions
        # A region without data (like .bss) cannot hold a string literal
        self._data_regions = [
            (vaddr, region) for vaddr, region in regions if region.resource.get_data_id()
        ]
        self._backend_offset = backend_offset
        self._pointer_size = program_attributes.bit_width.get_word_size()
        self._little_endian = program_attributes.endianness is Endianness.LITTLE_ENDIAN
        self._reference_sources = reference_sources
        self._known_addresses = known_addresses
        self._functions = functions
        self._region_data: Dict[bytes, bytes] = dict()

    @staticmethod
    async def create(
        program: Program, data_refs: ReferencedDataAttributes, functions: "_FunctionIndex"
    ) -> "_VirtualMemory":
        code_offsets = await _get_code_offsets(program)
        regions: List[Tuple[int, MemoryRegion]] = []
        # Sorting in the resource service query would skip regions (like most ELF sections) that
        # have the MemoryRegion tag but have not been analyzed yet, and so are not in the size
        # index. Getting them as views analyzes them; then sort locally, largest first.
        for region in await program.resource.get_descendants_as_view(
            MemoryRegion, r_filter=ResourceFilter.with_tags(MemoryRegion)
        ):
            if await _is_program_memory(region):
                offset = code_offsets.get(region.resource.get_id(), 0)
                regions.append((region.virtual_address - offset, region))
        regions.sort(key=lambda vaddr_and_region: vaddr_and_region[1].size, reverse=True)
        xrefs_from = data_refs.get_xrefs_from()
        # The backend moved the whole program by one offset, which OFRAK applied to the code
        # regions it could match with the backend's
        return _VirtualMemory(
            regions,
            max(code_offsets.values(), default=0),
            await program.resource.analyze(ProgramAttributes),
            set(xrefs_from),
            {vaddr for vaddrs in xrefs_from.values() for vaddr in vaddrs}
            | set(functions.function_vaddrs),
            functions,
        )

    @staticmethod
    def _find(
        regions: Sequence[Tuple[int, MemoryRegion]], file_vaddr: int
    ) -> Optional[Tuple[int, MemoryRegion]]:
        """
        :return: The first of `regions` containing the address of the file, with its address in
        the file, if there is one
        """
        for region_vaddr, region in regions:
            if region_vaddr <= file_vaddr < region_vaddr + region.size:
                return region_vaddr, region
        return None

    def contains(self, vaddr: int) -> bool:
        """
        :param vaddr: An address of the backend's

        :return: Whether the address is in some of the program's memory, with or without data
        """
        return self._find(self._regions, vaddr - self._backend_offset) is not None

    async def _locate(self, vaddr: int) -> Tuple[int, int, bytes]:
        """
        :param vaddr: An address of the backend's

        :raises NotFoundError: if `vaddr` is in none of the program's memory regions with data

        :return: The address in the file, the offset of `vaddr` in the data of the region
        containing it, and that data
        """
        file_vaddr = vaddr - self._backend_offset
        found = self._find(self._data_regions, file_vaddr)
        if found is None:
            raise NotFoundError(f"No memory region of the program has data at {hex(vaddr)}")
        region_vaddr, region = found
        region_id = region.resource.get_id()
        if region_id not in self._region_data:
            self._region_data[region_id] = await region.resource.get_data()
        return file_vaddr, file_vaddr - region_vaddr, self._region_data[region_id]

    def _is_pointer(
        self, vaddr: int, file_vaddr: int, data: bytes, start: int, length: int
    ) -> bool:
        """
        :return: Whether the `length` bytes at `start` in `data`, at `vaddr` (or `file_vaddr` in the
        file), fit in a pointer-aligned pointer that the backend found a reference at, or whose
        value is an address the backend knows or of the program's memory: an entry of a pointer
        or jump table, or of a literal pool
        """
        size = self._pointer_size
        if length > size or file_vaddr % size != 0 or start + size > len(data):
            return False
        # A pointer in the program's data is an address of the file's
        value = int.from_bytes(
            data[start : start + size], "little" if self._little_endian else "big"
        )
        return (
            vaddr in self._reference_sources
            or value + self._backend_offset in self._known_addresses
            or self._find(self._regions, value) is not None
        )

    async def find_c_string(self, vaddr: int) -> Optional[Range]:
        """
        Check whether the bytes at `vaddr` are a NUL-terminated, printable UTF-8 string.

        :return: The virtual address range of the string's bytes (without the terminator), or
        None if the data there is not such a string
        """
        if self._functions.get_function_containing(vaddr) is not None:
            return None
        try:
            file_vaddr, start, data = await self._locate(vaddr)
        except NotFoundError:
            return None
        terminator = data.find(b"\x00", start, start + MAX_STRING_LENGTH + 1)
        if terminator < 0 or terminator - start < MIN_STRING_LENGTH:
            return None
        try:
            text = data[start:terminator].decode("utf-8")
        except UnicodeDecodeError:
            return None
        if not _is_c_string_text(text) or self._is_pointer(
            vaddr, file_vaddr, data, start, terminator + 1 - start
        ):
            return None
        return Range(vaddr, vaddr + terminator - start)

    async def read(self, vaddr_range: Range) -> bytes:
        """
        :raises NotFoundError: if the range does not start in one of the program's memory regions
        with data

        :return: The bytes in the virtual address range
        """
        _, start, data = await self._locate(vaddr_range.start)
        return data[start : start + vaddr_range.length()]
