import io
import logging
from typing import Optional, TypeVar

from ofrak.component.analyzer import Analyzer
from ofrak.core import NamedProgramSection
from ofrak.core.architecture import ProgramAttributes
from ofrak.core.elf.model import (
    ElfSectionHeader,
    Elf,
    ElfHeader,
    ElfBasicHeader,
    ElfProgramHeader,
    ElfProgramHeaderType,
    ElfType,
    ElfSegmentStructure,
    ElfSegment,
    ElfSectionStructure,
    ElfSection,
    ElfSymbol,
    ElfSymbolStructure,
    ElfRelaEntry,
    ElfDynamicEntry,
    ElfVirtualAddress,
    SECTION_NAME_PATTERN,
)
from ofrak.core.memory_region import MemoryRegion
from ofrak.model.component_model import ComponentConfig
from ofrak.model.resource_model import ResourceAttributes
from ofrak.model.viewable_tag_model import AttributesType
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceFilter
from ofrak_io.deserializer import BinaryDeserializer

LOGGER = logging.getLogger(__name__)

RA = TypeVar("RA", bound=ResourceAttributes)


class ElfBasicHeaderAttributesAnalyzer(Analyzer[None, ElfBasicHeader]):
    """
    Deserialize the [ElfBasicHeader][ofrak.core.elf.model.ElfBasicHeader], which contains the
    first 7 fields of the ELF header. These fields are all endianness- & word-size-agnostic,
    and in fact define the endianness and word size for the remainder of the header.

    The remaining fields are deserialized as part of the
    [ElfHeader][ofrak.core.elf.model.ElfHeader]. See "ELF header (Ehdr)" in
    <https://man7.org/linux/man-pages/man5/elf.5.html> for details.
    """

    targets = (ElfBasicHeader,)
    outputs = (ElfBasicHeader,)

    async def analyze(self, resource: Resource, config=None) -> ElfBasicHeader:
        tmp = await resource.get_data()
        deserializer = BinaryDeserializer(io.BytesIO(tmp))
        (
            ei_magic,
            ei_class,
            ei_data,
            ei_version,
            ei_osabi,
            ei_abiversion,
            ei_pad,
        ) = deserializer.unpack_multiple("4sBBBBB7s")
        assert ei_magic == b"\x7fELF"
        return ElfBasicHeader(
            ei_magic, ei_class, ei_data, ei_version, ei_osabi, ei_abiversion, ei_pad
        )


class ElfHeaderAttributesAnalyzer(Analyzer[None, ElfHeader]):
    """
    Deserialize the [ElfHeader][ofrak.core.elf.model.ElfHeader], which contains all of the
    ELF header fields except the first 7. The first 7 fields are deserialized as part of the
    [ElfBasicHeader][ofrak.core.elf.model.ElfBasicHeader]. The remaining fields locate all
    other ELF structures. Use to understand ELF structure details, find program and section
    headers for unpacking, extract entry point for execution analysis, or validate ELF structure
    integrity.
    """

    id = b"ElfHeaderAttributesAnalyzer"
    targets = (ElfHeader,)
    outputs = (ElfHeader,)

    async def analyze(self, resource: Resource, config=None) -> ElfHeader:
        deserializer = await _create_deserializer(resource)
        return self.deserialize(deserializer)

    @classmethod
    def deserialize(cls, deserializer: BinaryDeserializer) -> ElfHeader:
        (
            e_type,
            e_machine,
            e_version,
            e_entry,
            e_phoff,
            e_shoff,
            e_flags,
            e_ehsize,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        ) = deserializer.unpack_multiple(f"HHIQQQIHHHHHH", auto_bitwidth=True)

        return ElfHeader(
            e_type,
            e_machine,
            e_version,
            e_entry,
            e_phoff,
            e_shoff,
            e_flags,
            e_ehsize,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        )


class ElfProgramHeaderAttributesAnalyzer(Analyzer[None, ElfProgramHeader]):
    """
    Deserializes ELF program header (Phdr) structures to extract segment type (LOAD, DYNAMIC,
    INTERP, etc.), file offset, virtual address where segment is loaded, physical address, file
    size, memory size (may be larger if includes .bss), segment flags (readable, writable,
    executable), and alignment requirements. Program headers define how the ELF is loaded into
    memory. Use when analyzing specific segments to understand ELF memory layout, determine loading
    behavior, find executable or data regions, or prepare for memory-based modifications. Critical
    for understanding runtime memory organization.
    """

    id = b"ElfProgramHeaderAttributesAnalyzer"
    targets = (ElfProgramHeader,)
    outputs = (ElfProgramHeader,)

    async def analyze(self, resource: Resource, config=None) -> ElfProgramHeader:
        segment_structure = await resource.view_as(ElfSegmentStructure)
        deserializer = await _create_deserializer(resource)
        return self.deserialize(deserializer, segment_structure.segment_index)

    @classmethod
    def deserialize(cls, deserializer: BinaryDeserializer, elf_index: int) -> ElfProgramHeader:
        p_flags = 0
        p_type = deserializer.unpack_uint()
        if deserializer.get_word_size() == 8:
            p_flags = deserializer.unpack_uint()
        p_offset, p_vaddr, p_paddr, p_filesz, p_memsz = deserializer.unpack_multiple(
            "QQQQQ", auto_bitwidth=True
        )
        if deserializer.get_word_size() == 4:
            p_flags = deserializer.unpack_uint()
        p_align = deserializer.unpack_ulong()
        return ElfProgramHeader(
            elf_index, p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align
        )


class ElfSegmentAnalyzer(Analyzer[None, ElfSegment]):
    """
    Extracts and analyzes detailed attributes from ELF program segments (from program headers),
    including segment type classification, memory protection flags, size information, alignment
    requirements, and relationships to sections. Segments define how the binary is loaded and
    mapped in memory. Use when analyzing specific program segments to understand memory layout,
    determine what code/data regions are loaded where, find segment boundaries for modifications,
    or understand memory protection and access patterns. Critical for memory-based binary analysis.
    """

    id = b"ElfSegmentAnalyzer"
    targets = (ElfSegment,)
    outputs = (ElfSegment,)

    async def analyze(self, resource: Resource, config=None) -> ElfSegment:
        segment = await resource.view_as(ElfSegmentStructure)
        segment_header = await segment.get_header()
        return ElfSegment(
            segment_index=segment_header.segment_index,
            virtual_address=segment_header.p_vaddr,
            size=segment_header.p_memsz,
        )


class ElfSectionHeaderAttributesAnalyzer(Analyzer[None, ElfSectionHeader]):
    """
    Deserializes ELF section header (Shdr) structures to extract section name index (into string
    table), section type (PROGBITS, SYMTAB, STRTAB, etc.), section flags (writable, allocatable,
    executable), virtual address, file offset, section size, link to related section, additional
    info field, address alignment, and entry size for fixed-size entry sections. Section headers
    describe the file's organization. Use when analyzing specific sections to understand their
    properties, find particular sections like .text or .data, determine section attributes, or
    navigate ELF file structure.
    """

    id = b"ElfSectionHeaderAttributesAnalyzer"
    targets = (ElfSectionHeader,)
    outputs = (ElfSectionHeader,)

    async def analyze(self, resource: Resource, config=None) -> ElfSectionHeader:
        section_structure = await resource.view_as(ElfSectionStructure)
        deserializer = await _create_deserializer(resource)
        return self.deserialize(deserializer, section_structure.section_index)

    @classmethod
    def deserialize(cls, deserializer: BinaryDeserializer, elf_index: int) -> ElfSectionHeader:
        (
            sh_name,
            sh_type,
            sh_flags,
            sh_addr,
            sh_offset,
            sh_size,
            sh_link,
            sh_info,
            sh_addralign,
            sh_entsize,
        ) = deserializer.unpack_multiple("IIQQQQIIQQ", auto_bitwidth=True)
        return ElfSectionHeader(
            elf_index,
            sh_name,
            sh_type,
            sh_flags,
            sh_addr,
            sh_offset,
            sh_size,
            sh_link,
            sh_info,
            sh_addralign,
            sh_entsize,
        )


class ElfSymbolAttributesAnalyzer(Analyzer[None, ElfSymbol]):
    """
    Deserializes and extracts detailed attributes from ELF symbol table entries including symbol
    name (as an index into the string table), value/address, size in bytes, binding type (local,
    global, weak), symbol type (function, object, section), visibility, and section index. These
    attributes reflect what the ELF header claims, which might not match what's actually in the
    binary. Use when you need to examine or modify the symbol metadata that the OS loader will
    read, but don't rely on these for discovering actual symbols in the binary.
    """

    targets = (ElfSymbol,)
    outputs = (ElfSymbol,)

    async def analyze(self, resource: Resource, config=None) -> ElfSymbol:
        symbol_structure = await resource.view_as(ElfSymbolStructure)
        deserializer = await _create_deserializer(resource)

        return self.deserialize(deserializer, symbol_structure.symbol_index)

    @classmethod
    def deserialize(cls, deserializer: BinaryDeserializer, elf_index: int) -> ElfSymbol:
        if deserializer.get_word_size() == 8:
            st_name, st_info, st_other, st_shndx, st_value, st_size = deserializer.unpack_multiple(
                "IBBHQQ"
            )
        else:
            st_name, st_value, st_size, st_info, st_other, st_shndx = deserializer.unpack_multiple(
                "IIIBBH"
            )
        return ElfSymbol(elf_index, st_name, st_value, st_size, st_info, st_other, st_shndx)


class ElfDynamicSectionAnalyzer(Analyzer[None, ElfDynamicEntry]):
    """
    If an object file participates in dynamic linking, its program header table will have an element
    of type PT_DYNAMIC. This segment contains the .dynamic section.

    Descriptions of the Dynamic Table entries may be found herein:
    https://docs.oracle.com/cd/E19683-01/817-3677/chapter6-42444/index.html
    """

    id = b"ElfDynamicSectionAnalyzer"
    targets = (ElfDynamicEntry,)
    outputs = (ElfDynamicEntry,)

    async def analyze(self, resource: Resource, config=None) -> ElfDynamicEntry:
        deserializer = await _create_deserializer(resource)
        return self.deserialize(deserializer)

    @classmethod
    def deserialize(cls, deserializer: BinaryDeserializer) -> ElfDynamicEntry:
        if deserializer.get_word_size() == 8:
            d_tag, d_un = deserializer.unpack_multiple("QQ")
        else:
            d_tag, d_un = deserializer.unpack_multiple("II")
        return ElfDynamicEntry(d_tag, d_un)


class ElfPointerAnalyzer(Analyzer[None, ElfVirtualAddress]):
    """
    Extracts and deserializes virtual address pointer values from ELF pointer array sections,
    converting raw bytes to addresses based on the binary's word size and endianness. Pointers
    reference functions or data locations in memory. Use when analyzing specific pointer entries
    in .init_array, .fini_array, .ctors, .dtors, or other pointer arrays to determine what
    addresses they reference, understand initialization order, or prepare to modify pointer
    targets. Each pointer entry is analyzed individually.
    """

    id = b"ElfPointerAnalyzer"
    targets = (ElfVirtualAddress,)
    outputs = (ElfVirtualAddress,)

    async def analyze(self, resource: Resource, config=None) -> ElfVirtualAddress:
        deserializer = await _create_deserializer(resource)
        return self.deserialize(deserializer)

    @classmethod
    def deserialize(cls, deserializer: BinaryDeserializer) -> ElfVirtualAddress:
        value = deserializer.unpack_ulong()
        return ElfVirtualAddress(value)


class ElfRelaAnalyzer(Analyzer[None, ElfRelaEntry]):
    """
    Deserializes [ElfRelaEntry][ofrak.core.elf.model.ElfRelaEntry] entries with addends
    (Elf32_Rela or Elf64_Rela structures) to extract offset (where to apply relocation), symbol
    index (which symbol is involved), relocation type (how to compute the value), and addend
    (constant to add to the symbol value). Relocations specify how addresses should be adjusted
    during linking or loading. Use when debugging linking issues, preparing for code relocation,
    understanding dynamic symbol resolution, or analyzing specific relocation entries to understand
    how position-independent code works. Each entry describes one address adjustment.

    http://sourceware.org/git/?p=glibc.git;a=blob_plain;f=elf/elf.h
    """

    id = b"ElfRelaAnalyzer"
    targets = (ElfRelaEntry,)
    outputs = (ElfRelaEntry,)

    async def analyze(self, resource: Resource, config=None) -> ElfRelaEntry:
        deserializer = await _create_deserializer(resource)
        return self.deserialize(deserializer)

    @classmethod
    def deserialize(cls, deserializer: BinaryDeserializer) -> ElfRelaEntry:
        if deserializer.get_word_size() == 8:
            r_offset, r_info, r_addend = deserializer.unpack_multiple("QQq")
        else:
            r_offset, r_info, r_addend = deserializer.unpack_multiple("IIi")
        return ElfRelaEntry(r_offset, r_info, r_addend)


class ElfSectionNameAnalyzer(Analyzer[None, AttributesType[NamedProgramSection]]):
    """
    Resolves ELF section names from the section header string table (.shstrtab) using the sh_name
    field from section headers as an index. Section names like ".text", ".data", ".bss", ".rodata"
    are stored as NULL-terminated strings in a dedicated string section. Use to identify sections
    by their symbolic names rather than numeric indexes, find specific sections for analysis (like
    finding .text for code), understand section purposes, or display human-readable section
    information. Makes ELF navigation much more intuitive.
    """

    id = b"ElfSectionNameAnalyzer"
    targets = (ElfSection,)
    outputs = (AttributesType[NamedProgramSection],)

    async def analyze(self, resource: Resource, config=None) -> AttributesType[NamedProgramSection]:
        section = await resource.view_as(ElfSectionStructure)
        section_header = await section.get_header()
        elf_r = await section.get_elf()
        string_section = await elf_r.get_section_name_string_section()
        try:
            ((_, raw_section_name),) = await string_section.resource.search_data(
                SECTION_NAME_PATTERN, start=section_header.sh_name, max_matches=1
            )
            section_name = raw_section_name.rstrip(b"\x00").decode("ascii")
        except ValueError as e:
            LOGGER.info("String section is empty! Using '<no-strings>' as section name")
            section_name = "<no-strings>"  # This is what readelf returns in this situation
        return AttributesType[NamedProgramSection](
            name=section_name,
        )


class ElfSectionMemoryRegionAnalyzer(Analyzer[None, MemoryRegion]):
    """
    Extracts memory region information for ELF sections by reading the virtual address and size
    fields from section headers, determining where each section will be located in memory when the
    ELF is loaded. Sections may or may not be allocated in memory (depending on SHF_ALLOC flag).
    Use to understand where ELF sections are loaded in memory, map file offsets to virtual
    addresses, plan memory-based modifications, or understand memory layout for debugging. Bridges
    file-based and memory-based views of sections.
    """

    id = b"ElfSectionMemoryRegionAnalyzer"
    targets = (ElfSection,)
    outputs = (MemoryRegion,)

    async def analyze(self, resource: Resource, config=None) -> MemoryRegion:
        section = await resource.view_as(ElfSectionStructure)
        section_header = await section.get_header()
        return MemoryRegion(
            virtual_address=section_header.sh_addr,
            size=section_header.sh_size,
        )


class ElfProgramAttributesAnalyzer(Analyzer[None, ProgramAttributes]):
    """
    Extracts `ProgramAttributes` from the ELF header's machine type field and flags, determining
    the instruction set architecture (x86, ARM, MIPS, PowerPC, etc.), bit width (16/32/64-bit),
    endianness, and processor-specific flags. This information defines what kind of CPU can
    execute the binary. Use to understand the target platform for an ELF binary, verify
    compatibility with target systems, determine what disassembler or emulator to use, or check
    architectural assumptions before analysis. Critical for setting up proper analysis tools.
    """

    id = b"ElfProgramAttributesAnalyzer"
    targets = (Elf,)
    outputs = (ProgramAttributes,)

    async def analyze(
        self, resource: Resource, config: Optional[ComponentConfig] = None
    ) -> ProgramAttributes:
        elf = await resource.view_as(Elf)
        elf_header = await resource.get_only_descendant_as_view(
            ElfHeader, r_filter=ResourceFilter.with_tags(ElfHeader)
        )
        elf_basic_header = await resource.get_only_descendant_as_view(
            ElfBasicHeader, r_filter=ResourceFilter.with_tags(ElfBasicHeader)
        )

        # e_entry is meaningless for relocatable objects (ET_REL); always 0
        if elf_header.e_type == ElfType.ET_REL.value:
            entry_points: tuple = ()
        else:
            entry_points = (elf_header.e_entry,)

        # Base address from first PT_LOAD segment (None for relocatable objects)
        base_address: Optional[int] = None
        program_headers = await elf.get_program_headers()
        for phdr in program_headers:
            if phdr.p_type == ElfProgramHeaderType.LOAD.value:
                base_address = phdr.p_vaddr
                break

        return ProgramAttributes(
            elf_header.get_isa(),
            None,
            elf_basic_header.get_bitwidth(),
            elf_basic_header.get_endianness(),
            None,
            entry_points=entry_points,
            base_address=base_address,
        )


async def _create_deserializer(resource: Resource) -> BinaryDeserializer:
    elf_r = await resource.get_only_ancestor(ResourceFilter(tags=(Elf,)))
    e_basic_header = await elf_r.get_only_child_as_view(
        ElfBasicHeader, ResourceFilter.with_tags(ElfBasicHeader)
    )
    deserializer = BinaryDeserializer(
        io.BytesIO(await resource.get_data()),
        endianness=e_basic_header.get_endianness(),
        word_size=int(e_basic_header.get_bitwidth().get_word_size()),
    )
    return deserializer
