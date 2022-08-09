import io
import logging
from typing import Optional, TypeVar

from ofrak.component.analyzer import Analyzer
from ofrak.core.architecture import ProgramAttributes
from ofrak.model.component_model import ComponentConfig
from ofrak.model.resource_model import ResourceAttributes
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceFilter
from ofrak.core.elf.model import (
    ElfSectionHeader,
    Elf,
    ElfHeader,
    ElfBasicHeader,
    ElfProgramHeader,
    ElfSegmentStructure,
    ElfSegment,
    ElfSectionStructure,
    ElfSection,
    UnanalyzedElfSection,
    ElfSymbol,
    ElfSymbolStructure,
    ElfRelaEntry,
    ElfDynamicEntry,
    ElfVirtualAddress,
    ElfPointerArraySection,
    UnanalyzedElfSegment,
)
from ofrak_io.deserializer import BinaryDeserializer
from ofrak_type.range import Range

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

    id = b"ElfHeaderMetadataAttributesAnalyzer"
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
    [ElfBasicHeader][ofrak.core.elf.model.ElfBasicHeader].
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


class ElfSegmentStructureIndexAnalyzer(Analyzer[None, ElfSegmentStructure]):
    targets = (ElfProgramHeader, ElfSegment)
    outputs = (ElfSegmentStructure,)

    async def analyze(self, resource: Resource, config=None) -> ElfSegmentStructure:
        elf = await resource.get_only_ancestor_as_view(Elf, ResourceFilter.with_tags(Elf))
        elf_header = await elf.get_header()

        if resource.has_tag(ElfProgramHeader):
            segment_index = _calculate_elf_index(
                entry_offset=(await resource.get_data_range_within_parent()).start,
                table_offset=elf_header.e_phoff,
                table_entry_size=elf_header.e_phentsize,
            )

            return ElfSegmentStructure(segment_index)
        else:
            raise TypeError(f"Resource did not have expected tags {ElfProgramHeader.__name__}")


class ElfProgramHeaderAttributesAnalyzer(Analyzer[None, ElfProgramHeader]):
    """
    Deserialize an [ElfProgramHeader][ofrak.core.elf.model.ElfProgramHeader].
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
    Analyze an ElfSegment.
    """

    id = b"ElfSegmentAnalyzer"
    targets = (ElfSegment,)
    outputs = (ElfSegment,)

    async def analyze(self, resource: Resource, config=None) -> ElfSegment:
        unnamed_segment = await resource.view_as(UnanalyzedElfSegment)
        segment_header = await unnamed_segment.get_header()
        return ElfSegment(
            segment_index=segment_header.segment_index,
            virtual_address=segment_header.p_vaddr,
            size=segment_header.p_memsz,
        )


class ElfSectionStructureIndexAnalyzer(Analyzer[None, ElfSectionStructure]):
    targets = (ElfSectionHeader, ElfSection)
    outputs = (ElfSectionStructure,)

    async def analyze(self, resource: Resource, config=None) -> ElfSectionStructure:
        elf = await resource.get_only_ancestor_as_view(Elf, ResourceFilter.with_tags(Elf))
        elf_header = await elf.get_header()
        resource_start_offset = (await resource.get_data_range_within_parent()).start

        if resource.has_tag(ElfSectionHeader):
            segment_index = _calculate_elf_index(
                entry_offset=resource_start_offset,
                table_offset=elf_header.e_shoff,
                table_entry_size=elf_header.e_shentsize,
            )

            return ElfSectionStructure(segment_index)
        elif resource.has_tag(ElfSection):
            for section_header in await elf.get_section_headers():
                if section_header.sh_offset == resource_start_offset:
                    return ElfSectionStructure(section_header.section_index)
            raise ValueError(
                f"No header found for section starting at offset {hex(resource_start_offset)}"
            )
        else:
            raise TypeError(f"Resource did not have expected tags {ElfSectionHeader.__name__}")


class ElfSectionHeaderAttributesAnalyzer(Analyzer[None, ElfSectionHeader]):
    """
    Deserialize an [ElfSectionHeader][ofrak.core.elf.model.ElfSectionHeader].
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


class ElfSymbolStructureIndexAnalyzer(Analyzer[None, ElfSymbolStructure]):
    targets = (ElfSymbol,)
    outputs = (ElfSymbolStructure,)

    async def analyze(self, resource: Resource, config=None) -> ElfSymbolStructure:
        elf = await resource.get_only_ancestor_as_view(Elf, ResourceFilter(tags=(Elf,)))
        deserializer = await _create_deserializer(resource)
        symbol_index = _calculate_elf_index(
            entry_offset=(await resource.get_data_range_within_parent()).start,
            # The entry offset is from the section start, not the ELF start. Match that
            table_offset=0,
            table_entry_size=24 if deserializer.get_word_size() == 8 else 16,
        )

        return ElfSymbolStructure(symbol_index)


class ElfSymbolAttributesAnalyzer(Analyzer[None, ElfSymbol]):
    """
    Deserialize an [ElfSymbol][ofrak.core.elf.model.ElfSymbol], an entry in the ELF symbol
    table.
    """

    id = b"ElfSymbolAnalyzer"
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


class ElfPointerArraySectionAnalyzer(Analyzer[None, ElfPointerArraySection]):
    id = b"ElfPointerArraySectionAnalyzer"
    targets = (UnanalyzedElfSection,)
    outputs = (ElfPointerArraySection,)

    async def analyze(self, resource: Resource, config=None) -> ElfPointerArraySection:
        unnamed_section = await resource.view_as(UnanalyzedElfSection)
        section_header = await unnamed_section.get_header()
        elf_r = await unnamed_section.get_elf()
        elf_basic_header = await elf_r.get_basic_header()
        num_pointers = section_header.sh_size // elf_basic_header.get_bitwidth().value // 8  # bits
        return ElfPointerArraySection(
            section_index=section_header.section_index, num_pointers=num_pointers
        )


class ElfPointerAnalyzer(Analyzer[None, ElfVirtualAddress]):
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
    Deserialize an [ElfRelaEntry][ofrak.core.elf.model.ElfRelaEntry], an entry in a rela.*
    table.

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


class ElfSectionNameAnalyzer(Analyzer[None, ElfSection]):
    """
    Get the name of an ELF section. ELF section names are stored as null-terminated strings in
    dedicated string section, and each ELF section header's `sh_name` field is an offset in this
    section.
    """

    id = b"ElfSectionNameAnalyzer"
    targets = (ElfSection,)
    outputs = (ElfSection,)

    async def analyze(self, resource: Resource, config=None) -> ElfSection:
        unnamed_section = await resource.view_as(UnanalyzedElfSection)
        section_header = await unnamed_section.get_header()
        elf_r = await unnamed_section.get_elf()
        string_section = await elf_r.get_section_name_string_section()
        try:
            string_section_data = await string_section.resource.get_data(
                Range(section_header.sh_name, Range.MAX)
            )
            name_string_end = string_section_data.find(b"\x00")
            raw_section_name = await string_section.resource.get_data(
                Range(section_header.sh_name, section_header.sh_name + name_string_end)
            )
            section_name = raw_section_name.decode("ascii")
        except ValueError:
            LOGGER.info("String section is empty! Using '<no-strings>' as section name")
            section_name = "<no-strings>"  # This is what readelf returns in this situation
        return ElfSection(
            section_index=section_header.section_index,
            name=section_name,
            virtual_address=section_header.sh_addr,
            size=section_header.sh_size,
        )


class ElfProgramAttributesAnalyzer(Analyzer[None, ProgramAttributes]):
    """
    Analyze the `ProgramAttributes` of an ELF, which are part of the information stored in the ELF
    header.
    """

    id = b"ElfProgramAttributesAnalyzer"
    targets = (Elf,)
    outputs = (ProgramAttributes,)

    async def analyze(
        self, resource: Resource, config: Optional[ComponentConfig] = None
    ) -> ProgramAttributes:
        elf_header = await resource.get_only_descendant_as_view(
            ElfHeader, r_filter=ResourceFilter.with_tags(ElfHeader)
        )
        elf_basic_header = await resource.get_only_descendant_as_view(
            ElfBasicHeader, r_filter=ResourceFilter.with_tags(ElfBasicHeader)
        )

        return ProgramAttributes(
            elf_header.get_isa(),
            None,
            elf_basic_header.get_bitwidth(),
            elf_basic_header.get_endianness(),
            None,
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


def _calculate_elf_index(
    entry_offset: int,
    table_offset: int,
    table_entry_size: int,
) -> int:
    """
    Helper for calculating index of an entry in a table. `entry_offset` and `table_offset` should
    be relative to the same point, such as the start of the ELF.
    """
    entry_offset_in_table = entry_offset - table_offset
    if 0 > entry_offset_in_table:
        raise ValueError(
            f"Elf structure "
            f"{hex(entry_offset)} bytes into the ELF cannot be in "
            f"the table which starts {hex(table_offset)} bytes in"
        )
    if 0 != (entry_offset_in_table % table_entry_size):
        raise ValueError(
            f"Elf structure is {hex(entry_offset_in_table)} bytes into the table which starts at "
            f"{hex(table_offset)}, which does not divide evenly into a table entry size of "
            f"{hex(table_entry_size)}"
        )
    return int(entry_offset_in_table / table_entry_size)
