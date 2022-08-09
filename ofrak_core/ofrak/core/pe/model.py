from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Optional

from ofrak.core.program import Program
from ofrak.core.program_section import NamedProgramSection
from ofrak.model.resource_model import index
from ofrak.resource_view import ResourceView
from ofrak.service.resource_service_i import (
    ResourceAttributeValueFilter,
    ResourceFilter,
)
from ofrak.core.magic import MagicDescriptionIdentifier
from ofrak_type.error import NotFoundError


@dataclass
class PeMsDosHeader(ResourceView):
    """PE MS-DOS header"""

    e_magic: int
    e_cblp: int
    e_cp: int
    e_crlc: int
    e_cparhdr: int
    e_minalloc: int
    e_maxalloc: int
    e_ss: int
    e_sp: int
    e_csum: int
    e_ip: int
    e_cs: int
    e_lfarlc: int
    e_ovno: int
    e_res: bytes
    e_oemid: int
    e_oeminfo: int
    e_res2: bytes
    e_lfanew: int


@dataclass
class PeFileHeader(ResourceView):
    """PE file header, a.k.a. COFF file header"""

    machine: int
    number_of_sections: int
    time_date_stamp: int
    pointer_to_symbol_table: int
    number_of_symbols: int
    size_of_optional_header: int
    characteristics: int


class PeOptionalHeaderMagic(Enum):
    """
    Magic values for the PE optional header
    """

    IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B
    IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B
    IMAGE_ROM_OPTIONAL_HDR_MAGIC = 0x107


@dataclass
class PeOptionalHeader(ResourceView):
    """
    PE optional header. Includes NT-specific attributes.

    Required for image files; object files don't have it.
    """

    magic: int
    major_linker_version: int
    minor_linker_version: int
    size_of_code: int
    size_of_initialized_data: int
    size_of_uninitialized_data: int
    address_of_entry_point: int
    base_of_code: int
    base_of_data: int
    image_base: int
    section_alignment: int
    file_alignment: int
    major_operating_system_version: int
    minor_operating_system_version: int
    major_image_version: int
    minor_image_version: int
    major_subsystem_version: int
    minor_subsystem_version: int
    size_of_image: int
    size_of_headers: int
    checksum: int
    subsystem: int
    dll_characteristics: int
    size_of_stack_reserve: int
    size_of_stack_commit: int
    size_of_heap_reserve: int
    size_of_heap_commit: int
    loader_flags: int
    number_of_rva_and_sizes: int


@dataclass
class PeDataDirectory(ResourceView):
    """PE data directory (image only)"""

    name: str
    virtual_address: int
    size: int


@dataclass
class PeSectionStructure(ResourceView):
    """Superclass for both the section headers and the sections themselves, linking them via the section index."""

    # Index of the section in the section table. Used to associate a section header with its section.
    section_index: int

    @index
    def SectionIndex(self) -> int:
        return self.section_index


@dataclass
class PeSection(PeSectionStructure, NamedProgramSection):
    """PE section"""

    async def get_header(self) -> "PeSectionHeader":
        return await self.resource.get_only_sibling_as_view(
            PeSectionHeader,
            ResourceFilter(
                tags=(PeSectionHeader,),
                attribute_filters=[
                    ResourceAttributeValueFilter(
                        PeSectionStructure.SectionIndex, self.section_index
                    )
                ],
            ),
        )


class PeSectionFlag(Enum):
    """
    Flags making up ``PeSectionHeader.m_characteristics``.

    Refer to https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags
    for documentation.
    """

    IMAGE_SCN_TYPE_NO_PAD = 0x00000008
    IMAGE_SCN_CNT_CODE = 0x00000020
    IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
    IMAGE_SCN_LNK_OTHER = 0x00000100
    IMAGE_SCN_LNK_INFO = 0x00000200
    IMAGE_SCN_LNK_REMOVE = 0x00000800
    IMAGE_SCN_LNK_COMDAT = 0x00001000
    IMAGE_SCN_GPREL = 0x00008000
    IMAGE_SCN_MEM_PURGEABLE = 0x00020000
    IMAGE_SCN_MEM_16BIT = 0x00020000
    IMAGE_SCN_MEM_LOCKED = 0x00040000
    IMAGE_SCN_MEM_PRELOAD = 0x00080000
    IMAGE_SCN_ALIGN_1BYTES = 0x00100000
    IMAGE_SCN_ALIGN_2BYTES = 0x00200000
    IMAGE_SCN_ALIGN_4BYTES = 0x00300000
    IMAGE_SCN_ALIGN_8BYTES = 0x00400000
    IMAGE_SCN_ALIGN_16BYTES = 0x00500000
    IMAGE_SCN_ALIGN_32BYTES = 0x00600000
    IMAGE_SCN_ALIGN_64BYTES = 0x00700000
    IMAGE_SCN_ALIGN_128BYTES = 0x00800000
    IMAGE_SCN_ALIGN_256BYTES = 0x00900000
    IMAGE_SCN_ALIGN_512BYTES = 0x00A00000
    IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000
    IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000
    IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000
    IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000
    IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000
    IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
    IMAGE_SCN_MEM_NOT_CACHED = 0x04000000
    IMAGE_SCN_MEM_NOT_PAGED = 0x08000000
    IMAGE_SCN_MEM_SHARED = 0x10000000
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_MEM_READ = 0x40000000
    IMAGE_SCN_MEM_WRITE = 0x80000000


@dataclass
class PeSectionHeader(PeSectionStructure):
    """PE section header"""

    m_name: bytes
    m_virtual_size: int
    m_virtual_address: int
    m_size_of_raw_data: int
    m_pointer_to_raw_data: int
    m_pointer_to_relocations: int
    m_pointer_to_linenumbers: int
    m_number_of_relocations: int
    m_number_of_linenumbers: int
    m_characteristics: int

    @property
    def name(self) -> str:
        """The section name as a string, e.g. ".text" for b".text\x00\x00\x00"."""
        return self.m_name.rstrip(b"\x00").decode("ascii")

    def has_flag(self, flag: PeSectionFlag) -> bool:
        return self.m_characteristics & flag.value != 0

    def get_flags(self) -> Iterable[PeSectionFlag]:
        for flag in PeSectionFlag:
            if self.has_flag(flag):
                yield flag

    async def get_body(self) -> PeSection:
        """Get the PeSection associated with this section header."""
        return await self.resource.get_only_sibling_as_view(
            PeSection,
            ResourceFilter(
                tags=(PeSection,),
                attribute_filters=[
                    ResourceAttributeValueFilter(
                        PeSectionStructure.SectionIndex, self.section_index
                    )
                ],
            ),
        )


@dataclass
class Pe(Program):
    """PE file"""

    async def get_sections(self) -> Iterable[PeSection]:
        """Return the children ``PeSection``s."""
        return await self.resource.get_children_as_view(
            PeSection,
            ResourceFilter(
                tags=(PeSection,),
            ),
        )

    async def get_section_by_name(self, name: str) -> PeSection:
        # Force analyzing the name of all sections
        await self.get_sections()

        return await self.resource.get_only_child_as_view(
            PeSection,
            ResourceFilter(
                tags=(PeSection,),
                attribute_filters=(ResourceAttributeValueFilter(PeSection.SectionName, name),),
            ),
        )

    async def get_optional_header(self) -> Optional[PeOptionalHeader]:
        """Return the optional header of the PE file, or None if there isn't one."""
        try:
            return await self.resource.get_only_child_as_view(
                PeOptionalHeader,
                ResourceFilter(
                    tags=(PeOptionalHeader,),
                ),
            )
        except NotFoundError:
            return None


MagicDescriptionIdentifier.register(Pe, lambda s: s.startswith("PE32 "))
