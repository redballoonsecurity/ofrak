from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Optional

from ofrak_type.architecture import InstructionSet
from ofrak.core.program import Program
from ofrak.core.program_section import NamedProgramSection, ProgramSegment
from ofrak.model.resource_model import index
from ofrak.resource_view import ResourceView
from ofrak.service.resource_service_i import (
    ResourceFilter,
    ResourceAttributeValueFilter,
    ResourceSortDirection,
    ResourceSort,
    ResourceAttributeRangeFilter,
)
from ofrak.core.magic import MagicDescriptionIdentifier
from ofrak_type.bit_width import BitWidth
from ofrak_type.endianness import Endianness
from ofrak_type.range import Range


##################################################################################
#                           ELF BASIC HEADER
##################################################################################


@dataclass
class ElfBasicHeader(ResourceView):
    """
    See "e_ident" in <https://man7.org/linux/man-pages/man5/elf.5.html> for details.
    """

    ei_magic: bytes
    ei_class: int
    ei_data: int
    ei_version: int
    ei_osabi: int
    ei_abiversion: int
    ei_pad: bytes

    def get_endianness(self) -> Endianness:
        if self.ei_data == 1:
            return Endianness.LITTLE_ENDIAN
        elif self.ei_data == 2:
            return Endianness.BIG_ENDIAN
        else:
            raise ValueError("Invalid endianness value in the ELF header ")

    def get_bitwidth(self) -> BitWidth:
        if self.ei_class == 1:
            return BitWidth.BIT_32
        elif self.ei_class == 2:
            return BitWidth.BIT_64
        else:
            raise ValueError("Invalid bit width  value in the ELF header ")

    async def get_parent(self) -> "Elf":
        return await self.resource.get_parent_as_view(Elf)


##################################################################################
#                           ELF HEADER
##################################################################################


class ElfMachine(Enum):
    EM_NONE = 0  # No machine
    EM_M32 = 1  # AT&T WE 32100
    EM_SPARC = 2  # SPARC
    EM_386 = 3  # Intel 80386
    EM_68K = 4  # Motorola 68000
    EM_88K = 5  # Motorola 88000
    EM_860 = 7  # Intel 80860
    EM_MIPS = 8  # MIPS I Architecture
    EM_S370 = 9  # IBM System/370 Processor
    EM_MIPS_RS3_LE = 10  # MIPS RS3000 Little-endian
    EM_PARISC = 15  # Hewlett-Packard PA-RISC
    EM_VPP500 = 17  # Fujitsu VPP500
    EM_SPARC32PLUS = 18  # Enhanced instruction set SPARC
    EM_960 = 19  # Intel 80960
    EM_PPC = 20  # PowerPC
    EM_PPC64 = 21  # 64-bit PowerPC
    EM_S390 = 22  # IBM System/390 Processor
    EM_V800 = 36  # NEC V800
    EM_FR20 = 37  # Fujitsu FR20
    EM_RH32 = 38  # TRW RH-32
    EM_RCE = 39  # Motorola RCE
    EM_ARM = 40  # Advanced RISC Machines ARM
    EM_ALPHA = 41  # Digital Alpha
    EM_SH = 42  # Hitachi SH
    EM_SPARCV9 = 43  # SPARC Version 9
    EM_TRICORE = 44  # Siemens TriCore embedded processor
    EM_ARC = 45  # Argonaut RISC Core, Argonaut Technologies Inc.
    EM_H8_300 = 46  # Hitachi H8/300
    EM_H8_300H = 47  # Hitachi H8/300H
    EM_H8S = 48  # Hitachi H8S
    EM_H8_500 = 49  # Hitachi H8/500
    EM_IA_64 = 50  # Intel IA-64 processor architecture
    EM_MIPS_X = 51  # Stanford MIPS-X
    EM_COLDFIRE = 52  # Motorola ColdFire
    EM_68HC12 = 53  # Motorola M68HC12
    EM_MMA = 54  # Fujitsu MMA Multimedia Accelerator
    EM_PCP = 55  # Siemens PCP
    EM_NCPU = 56  # Sony nCPU embedded RISC processor
    EM_NDR1 = 57  # Denso NDR1 microprocessor
    EM_STARCORE = 58  # Motorola Star*Core processor
    EM_ME16 = 59  # Toyota ME16 processor
    EM_ST100 = 60  # STMicroelectronics ST100 processor
    EM_TINYJ = 61  # Advanced Logic Corp. TinyJ embedded processor family
    EM_X86_64 = 62  # AMD x86-64 architecture
    EM_PDSP = 63  # Sony DSP Processor
    EM_PDP10 = 64  # Digital Equipment Corp. PDP-10
    EM_PDP11 = 65  # Digital Equipment Corp. PDP-11
    EM_FX66 = 66  # Siemens FX66 microcontroller
    EM_ST9PLUS = 67  # STMicroelectronics ST9+ 8/16 bit microcontroller
    EM_ST7 = 68  # STMicroelectronics ST7 8-bit microcontroller
    EM_68HC16 = 69  # Motorola MC68HC16 Microcontroller
    EM_68HC11 = 70  # Motorola MC68HC11 Microcontroller
    EM_68HC08 = 71  # Motorola MC68HC08 Microcontroller
    EM_68HC05 = 72  # Motorola MC68HC05 Microcontroller
    EM_SVX = 73  # Silicon Graphics SVx
    EM_ST19 = 74  # STMicroelectronics ST19 8-bit microcontroller
    EM_VAX = 75  # Digital VAX
    EM_CRIS = 76  # Axis Communications 32-bit embedded processor
    EM_JAVELIN = 77  # Infineon Technologies 32-bit embedded processor
    EM_FIREPATH = 78  # Element 14 64-bit DSP Processor
    EM_ZSP = 79  # LSI Logic 16-bit DSP Processor
    EM_MMIX = 80  # Donald Knuth's educational 64-bit processor
    EM_HUANY = 81  # Harvard University machine-independent object files
    EM_PRISM = 82  # SiTera Prism
    EM_AVR = 83  # Atmel AVR 8-bit microcontroller
    EM_FR30 = 84  # Fujitsu FR30
    EM_D10V = 85  # Mitsubishi D10V
    EM_D30V = 86  # Mitsubishi D30V
    EM_V850 = 87  # NEC v850
    EM_M32R = 88  # Mitsubishi M32R
    EM_MN10300 = 89  # Matsushita MN10300
    EM_MN10200 = 90  # Matsushita MN10200
    EM_PJ = 91  # picoJava
    EM_OPENRISC = 92  # OpenRISC 32-bit embedded processor
    EM_ARC_A5 = 93  # ARC Cores Tangent-A5
    EM_XTENSA = 94  # Tensilica Xtensa Architecture
    EM_VIDEOCORE = 95  # Alphamosaic VideoCore processor
    EM_TMM_GPP = 96  # Thompson Multimedia General Purpose Processor
    EM_NS32K = 97  # National Semiconductor 32000 series
    EM_TPC = 98  # Tenor Network TPC processor
    EM_SNP1K = 99  # Trebia SNP 1000 processor
    EM_ST200 = 100  # STMicroelectronics (www.st.com) ST200 microcontroller
    EM_MAXQ30 = 169  # Dallas Semiconductor MAXQ30 Core Micro-controllers
    EM_AARCH64 = 183  # 64-bit Advanced RISC Machines ARM

    @staticmethod
    def get_isa(e_machine: int) -> InstructionSet:
        MACHINE_TO_ISA = {
            ElfMachine.EM_386.value: InstructionSet.X86,
            ElfMachine.EM_MIPS.value: InstructionSet.MIPS,
            ElfMachine.EM_MIPS_RS3_LE.value: InstructionSet.MIPS,
            ElfMachine.EM_PPC.value: InstructionSet.PPC,
            ElfMachine.EM_PPC64.value: InstructionSet.PPC,
            ElfMachine.EM_ARM.value: InstructionSet.ARM,
            ElfMachine.EM_X86_64.value: InstructionSet.X86,
            ElfMachine.EM_AARCH64.value: InstructionSet.AARCH64,
            ElfMachine.EM_68K.value: InstructionSet.M68K,
            ElfMachine.EM_COLDFIRE.value: InstructionSet.M68K,
            ElfMachine.EM_AVR.value: InstructionSet.AVR,
            # While there is an assembler for MaxQ (
            # https://www.maximintegrated.com/content/dam/files/design/tools/tech-docs/4465
            # /AN4465-dev-tools-guide.pdf), in practice PPC is quite similar.
            ElfMachine.EM_MAXQ30.value: InstructionSet.PPC,
        }

        if e_machine not in MACHINE_TO_ISA:
            raise KeyError(
                f"ELF header e_machine value corresponds to unimplemented ISA:" f" {e_machine}"
            )
        return MACHINE_TO_ISA[e_machine]


class ElfType(Enum):
    ET_NONE = 0  # No file type
    ET_REL = 1  # Relocatable file
    ET_EXEC = 2  # Executable file
    ET_DYN = 3  # Shared object file
    ET_CORE = 4  # Core file
    ET_LOOS = 0xFE00  # Operating system-specific
    ET_HIOS = 0xFEFF  # Operating system-specific
    ET_LOPROC = 0xFF00  # Processor-specific
    ET_HIPROC = 0xFFFF  # Processor-specific


@dataclass
class ElfHeader(ResourceView):
    """
    See "ELF header (Ehdr)" in <https://man7.org/linux/man-pages/man5/elf.5.html> for details.
    """

    e_type: int
    e_machine: int
    e_version: int
    e_entry: int
    e_phoff: int
    e_shoff: int
    e_flags: int
    e_ehsize: int
    e_phentsize: int
    e_phnum: int
    e_shentsize: int
    e_shnum: int
    e_shstrndx: int

    def get_isa(self) -> InstructionSet:
        return ElfMachine.get_isa(self.e_machine)

    async def get_parent(self) -> "Elf":
        return await self.resource.get_parent_as_view(Elf)


##################################################################################
#                           ELF SEGMENT STRUCTURE
##################################################################################


@dataclass
class ElfSegmentStructure(ResourceView):
    segment_index: int

    @index
    def SegmentIndex(self) -> int:
        return self.segment_index

    async def get_elf(self) -> "Elf":
        return await self.resource.get_only_ancestor_as_view(Elf, ResourceFilter.with_tags(Elf))


##################################################################################
#                           ELF PROGRAM HEADER
##################################################################################


class ElfProgramHeaderType(Enum):
    UNKNOWN = -1
    NULL = 0
    LOAD = 1
    DYNAMIC = 2
    INTERP = 3
    NOTE = 4
    SHLIB = 5
    PHDR = 6
    TLS = 7


class ElfProgramHeaderPermission(Enum):
    EXECUTE = 0x1
    WRITE = 0x2
    READ = 0x4


@dataclass
class ElfProgramHeader(ElfSegmentStructure):
    """
    See "Program header (Phdr)" in <https://man7.org/linux/man-pages/man5/elf.5.html> for details.

    """

    p_type: int
    p_offset: int
    p_vaddr: int
    p_paddr: int
    p_filesz: int
    p_memsz: int
    p_flags: int
    p_align: int

    def get_file_range(self) -> Range:
        return Range.from_size(self.p_offset, self.p_filesz)

    def segment_memory_contains(self, vaddr: int) -> bool:
        return Range.from_size(self.p_vaddr, self.p_memsz).contains_value(vaddr)

    def get_type(self) -> ElfProgramHeaderType:
        try:
            return ElfProgramHeaderType(self.p_type)
        except ValueError:
            return ElfProgramHeaderType.UNKNOWN

    def is_writable(self) -> bool:
        write_bit = self.p_flags & ElfProgramHeaderPermission.WRITE.value
        return write_bit == ElfProgramHeaderPermission.WRITE.value

    def is_executable(self) -> bool:
        execute_bit = self.p_flags & ElfProgramHeaderPermission.EXECUTE.value
        return execute_bit == ElfProgramHeaderPermission.EXECUTE.value

    async def get_parent(self) -> "Elf":
        return await self.resource.get_parent_as_view(Elf)

    async def get_body(self) -> "ElfSegment":
        return await self.resource.get_only_sibling_as_view(
            ElfSegment,
            ResourceFilter(
                tags=(ElfSegment,),
                attribute_filters=(
                    ResourceAttributeValueFilter(
                        ElfSegmentStructure.SegmentIndex, self.segment_index
                    ),
                ),
            ),
        )


##################################################################################
#                           ELF SEGMENT
##################################################################################


@dataclass
class UnanalyzedElfSegment(ElfSegmentStructure):
    """
    An unanalyzed ELF Segment
    """

    async def get_parent(self) -> "Elf":
        return await self.resource.get_parent_as_view(Elf)

    async def get_header(self) -> "ElfProgramHeader":
        return await self.resource.get_only_sibling_as_view(
            ElfProgramHeader,
            ResourceFilter(
                tags=(ElfProgramHeader,),
                attribute_filters=(
                    ResourceAttributeValueFilter(
                        ElfSegmentStructure.SegmentIndex, self.segment_index
                    ),
                ),
            ),
        )


@dataclass
class ElfSegment(UnanalyzedElfSegment, ProgramSegment):
    """
    An analyzed ELF Segment
    """


##################################################################################
#                           ELF SECTION STRUCTURE
##################################################################################
@dataclass
class ElfSectionStructure(ResourceView):
    section_index: int

    @index
    def SectionIndex(self) -> int:
        return self.section_index

    async def get_elf(self) -> "Elf":
        return await self.resource.get_only_ancestor_as_view(Elf, ResourceFilter.with_tags(Elf))


##################################################################################
#                           ELF SECTION HEADER
##################################################################################


class ElfSectionType(Enum):
    UNKNOWN_OS_SPECIFIC = -0x1
    NULL = 0x0
    PROGBITS = 0x1
    SYMTAB = 0x2
    STRTAB = 0x3
    RELA = 0x4
    HASH = 0x5
    DYNAMIC = 0x6
    NOTE = 0x7
    NOBITS = 0x8
    REL = 0x9
    SHT_PREINIT_ARRAY = 0x10
    SHLIB = 0xA
    DYNSYM = 0xB
    INIT_ARRAY = 0xE
    FINI_ARRAY = 0xF

    HIPROC = 0x7FFFFFFF
    HIUSER = 0xFFFFFFFF
    LOPROC = 0x70000000
    LOUSER = 0x80000000

    GNU_HASH = 0x6FFFFFF6
    VERNEED = 0x6FFFFFFE
    VERSYM = 0x6FFFFFFF

    @classmethod
    def _missing_(cls, value):
        if value >= 0x60000000:
            return ElfSectionType.UNKNOWN_OS_SPECIFIC
        else:
            super()._missing_(value)


class ElfSectionFlag(Enum):
    WRITE = 0x1
    ALLOC = 0x2
    EXECINSTR = 0x4
    MERGE = 0x10
    STRINGS = 0x20
    INFO_LINK = 0x40
    LINK_ORDER = 0x80
    OS_NONCONFORMING = 0x100
    GROUP = 0x200
    TLS = 0x400
    MASKOS = 0x0FF00000
    ORDERED = 0x40000000
    EXCLUDE = 0x80000000
    MASKPROC = 0xF0000000


@dataclass
class ElfSectionHeader(ElfSectionStructure):
    """
    See "Section header (Shdr)" in <https://man7.org/linux/man-pages/man5/elf.5.html> for details.
    """

    sh_name: int
    sh_type: int
    sh_flags: int
    sh_addr: int
    sh_offset: int
    sh_size: int
    sh_link: int
    sh_info: int
    sh_addralign: int
    sh_entsize: int

    def has_flag(self, flag: ElfSectionFlag) -> bool:
        return self.sh_flags & flag.value > 0

    def get_flags(self) -> Iterable[ElfSectionFlag]:
        for flag in ElfSectionFlag:
            if self.has_flag(flag):
                yield flag

    def get_file_range(self) -> Range:
        return Range.from_size(self.sh_offset, self.sh_size)

    def get_file_end(self) -> int:
        return self.sh_offset + self.sh_size

    def get_type(self) -> ElfSectionType:
        return ElfSectionType(self.sh_type)

    async def get_parent(self) -> "Elf":
        return await self.resource.get_parent_as_view(Elf)

    async def get_body(self) -> "ElfSection":
        return await self.resource.get_only_sibling_as_view(
            ElfSection,
            ResourceFilter(
                tags=(ElfSection,),
                attribute_filters=(
                    ResourceAttributeValueFilter(
                        ElfSectionStructure.SectionIndex, self.section_index
                    ),
                ),
            ),
        )


##################################################################################
#                           ELF SYMBOL
##################################################################################


class ElfSymbolBinding(Enum):
    LOCAL = 0
    GLOBAL = 1
    WEAK = 2
    LOOS = 10
    HIOS = 12
    LOPROC = 13
    HIPROC = 15


class ElfSymbolType(Enum):
    NOTYPE = 0
    OBJECT = 1
    FUNC = 2
    SECTION = 3
    FILE = 4
    COMMON = 5
    TLS = 6
    LOOS = 10
    HIOS = 12
    LOPROC = 13
    HIPROC = 15


class ElfSymbolVisibility(Enum):
    DEFAULT = 0
    INTERNAL = 1
    HIDDEN = 2
    PROTECTED = 3


@dataclass
class ElfSymbolStructure(ResourceView):
    symbol_index: int

    @index
    def SymbolIndex(self) -> int:
        return self.symbol_index


@dataclass
class ElfSymbol(ElfSymbolStructure):
    """
    See "String and symbol tables" in <https://man7.org/linux/man-pages/man5/elf.5.html> for
    details.
    """

    st_name: int
    st_value: int
    st_size: int
    st_info: int
    st_other: int
    st_shndx: int

    def get_binding(self) -> ElfSymbolBinding:
        return ElfSymbolBinding(self.st_info >> 4)

    def get_type(self) -> ElfSymbolType:
        return ElfSymbolType(self.st_info & 0xF)

    def get_visibility(self) -> ElfSymbolVisibility:
        return ElfSymbolVisibility(self.st_other & 0x3)

    def get_section_index(self) -> Optional[int]:
        if self.get_type() in (
            ElfSymbolType.OBJECT,
            ElfSymbolType.FUNC,
            ElfSymbolType.SECTION,
        ):
            return self.st_shndx
        return None

    async def get_parent(self) -> "ElfSymbolSection":
        return await self.resource.get_parent_as_view(ElfSymbolSection)

    async def get_name(self) -> str:
        elf = await self.resource.get_only_ancestor_as_view(Elf, ResourceFilter.with_tags(Elf))
        string_section = await elf.get_string_section()
        string_section_data = await string_section.resource.get_data(Range(self.st_name, Range.MAX))
        name_string_end = string_section_data.find(b"\x00")
        raw_symbol_name = string_section_data[:name_string_end]
        return raw_symbol_name.decode("ascii")

    @index
    def SymbolValue(self) -> int:
        return self.st_value


##################################################################################
#                           ELF RELA
##################################################################################


class ElfRelaInfo(Enum):
    """
    An Enum for r_info in ElfRela

    Implemented in each respective arch model.py
    """

    @staticmethod
    def type_mask(value: int) -> int:
        raise NotImplementedError()


@dataclass
class ElfRelaEntry(ResourceView):
    """
    ElfRelaEntry describes relocation information within the program. Located in .rela.* sections.

    :var r_offset: vm offset information for each relocation entry
    :var r_info: Describes the type of relocation and sometimes the symbol related to the relocation
    :var r_addend: Describes the VM offset for each relocation itself
    """

    r_offset: int
    r_info: int
    r_addend: int


##################################################################################
#                           ELF DYNAMIC TABLE
##################################################################################


class ElfDynamicTableTag(Enum):
    DT_NULL = 0
    DT_NEEDED = 1
    DT_PLTRELSZ = 2
    DT_PLTGOT = 3
    DT_HASH = 4
    DT_STRTAB = 5
    DT_SYMTAB = 6
    DT_RELA = 7
    DT_RELASZ = 8
    DT_RELAENT = 9
    DT_STRSZ = 10
    DT_SYMENT = 11
    DT_INIT = 12
    DT_FINI = 13
    DT_SONAME = 14
    DT_RPATH = 15
    DT_SDMBOLIC = 16
    DT_REL = 17
    DT_RELSZ = 18
    DT_RELENT = 19
    DT_PLTREL = 20
    DT_DEBUG = 21
    DT_TEXTREL = 22
    DT_JMPREL = 23
    DT_INIT_ARRAY = 25
    DT_FINI_ARRAY = 26
    DT_INIT_ARRAYSZ = 27
    DT_FINI_ARRAYSZ = 28
    DT_ENCODING = 32
    OLD_DT_LOOS = 0x60000000
    DT_LOOS = 0x6000000D
    DT_HIOS = 0x6FFFF000
    DT_VALRNGLO = 0x6FFFFD00
    DT_VALRNGHI = 0x6FFFFDFF
    DT_ADDRRNGLO = 0x6FFFFE00
    DT_GNU_HASH = 0x6FFFFEF5
    DT_ADDRRNGHI = 0x6FFFFEFF
    DT_VERSYM = 0x6FFFFFF0
    DT_RELACOUNT = 0x6FFFFFF9
    DT_RELCOUNT = 0x6FFFFFFA
    DT_FLAGS_1 = 0x6FFFFFFB
    DT_VERDEF = 0x6FFFFFFC
    DT_VERDEFNUM = 0x6FFFFFFD
    DT_VERNEED = 0x6FFFFFFE
    DT_VERNEEDNUM = 0x6FFFFFFF
    OLD_DT_HIOS = 0x6FFFFFFF
    DT_LOPROC = 0x70000000
    DT_HIPROC = 0x7FFFFFFF


@dataclass
class ElfDynamicEntry(ResourceView):
    """
    ElfDynamicEntry describes a .dynamic table entry.

    https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-42444.html

    :var d_tag: one of ElfDynamicTableTag
    :var d_un: malleable word size value that changes meaning depending on d_tag
    """

    d_tag: int
    d_un: int  # either a pointer, value, or offset depending on the tag


@dataclass
class ElfVirtualAddress(ResourceView):
    """
    Wrapper for a virtual address

    :var value: an address
    """

    value: int


##################################################################################
#                           ELF SECTION
##################################################################################


@dataclass
class UnanalyzedElfSection(ElfSectionStructure):
    """
    An unanalyzed ELF Section
    """

    async def get_parent(self) -> "Elf":
        return await self.resource.get_parent_as_view(Elf)

    async def get_header(self) -> "ElfSectionHeader":
        return await self.resource.get_only_sibling_as_view(
            ElfSectionHeader,
            ResourceFilter(
                tags=(ElfSectionHeader,),
                attribute_filters=(
                    ResourceAttributeValueFilter(
                        ElfSectionStructure.SectionIndex, self.section_index
                    ),
                ),
            ),
        )


@dataclass
class ElfSection(UnanalyzedElfSection, NamedProgramSection):
    """
    An analyzed ELF Section
    """


@dataclass
class ElfPointerArraySection(UnanalyzedElfSection):
    """
    An ELF Section that can be interpreted as an array of pointers.

    TODO: Except in the case of .init_array and .fini_array, this tag must be added by hand
        as overlapping with other tags, like CodeRegion results in Data Node inconsistencies and
        errors.
    """

    num_pointers: int

    async def get_entries(self):
        await self.resource.unpack()
        return await self.resource.get_children_as_view(
            ElfVirtualAddress,
            ResourceFilter(tags=(ElfVirtualAddress,)),
        )


class ElfFiniArraySection(ElfPointerArraySection):
    pass


class ElfInitArraySection(ElfPointerArraySection):
    pass


class ElfDynamicSection(ElfSection):
    """
    The .dynamic ELF Section that appears in dynamically linked ELFs.
    """

    async def get_entries(self) -> Iterable[ElfDynamicEntry]:
        await self.resource.unpack()
        return await self.resource.get_children_as_view(
            ElfDynamicEntry,
            ResourceFilter(tags=(ElfDynamicEntry,)),
        )


class ElfRelaSection(ElfSection):
    """
    An ELF .rela.* section containing structs of type Elf{32, 64}_Rela
    """

    async def get_entries(self) -> Iterable[ElfRelaEntry]:
        await self.resource.unpack()

        return await self.resource.get_children_as_view(
            ElfRelaEntry,
            ResourceFilter(tags=(ElfRelaEntry,)),
        )


class ElfSymbolSection(ElfSection):
    """
    An ELF section containing structures of type Elf{32, 64}_Sym
    """

    async def get_symbols(self) -> Iterable[ElfSymbol]:
        await self.resource.unpack()

        return await self.resource.get_children_as_view(
            ElfSymbol,
            ResourceFilter(tags=(ElfSymbol,)),
            ResourceSort(ElfSymbol.SymbolIndex, ResourceSortDirection.ASCENDANT),
        )


class ElfDynSymbolSection(ElfSymbolSection):
    pass


class ElfStringSection(UnanalyzedElfSection):
    """
    A section with the STRTAB flag. There may be several of these in an ELF.
    """

    async def get_section(self) -> ElfSection:
        return await self.resource.view_as(ElfSection)


class ElfSectionNameStringSection(ElfStringSection):
    """
    A section with the STRTAB flag and named ".shstrtab". There should be at most one of these per
    ELF, and it contains only strings for the names of sections. Section headers' sh_name field
    is an index within this .shstrtab section.
    """


##################################################################################
#                           ELF
##################################################################################


@dataclass
class Elf(Program):
    """
    An Executable and Linking Format (ELF) file.

    See <https://man7.org/linux/man-pages/man5/elf.5.html> for details.
    """

    async def get_header(self) -> ElfHeader:
        return await self.resource.get_only_child_as_view(
            ElfHeader, ResourceFilter.with_tags(ElfHeader)
        )

    async def get_basic_header(self) -> ElfBasicHeader:
        return await self.resource.get_only_child_as_view(
            ElfBasicHeader, ResourceFilter.with_tags(ElfBasicHeader)
        )

    async def get_sections(self) -> Iterable[ElfSection]:
        return await self.resource.get_children_as_view(
            ElfSection,
            ResourceFilter(tags=(ElfSection,)),
            ResourceSort(ElfSectionStructure.SectionIndex, ResourceSortDirection.ASCENDANT),
        )

    async def get_section_by_index(self, index: int) -> ElfSection:
        return await self.resource.get_only_child_as_view(
            ElfSection,
            ResourceFilter(
                tags=(ElfSection,),
                attribute_filters=(
                    ResourceAttributeValueFilter(ElfSectionStructure.SectionIndex, index),
                ),
            ),
        )

    async def get_sections_after_index(self, index: int) -> Iterable[ElfSection]:
        return await self.resource.get_children_as_view(
            ElfSection,
            ResourceFilter(
                tags=(ElfSection,),
                attribute_filters=(
                    ResourceAttributeRangeFilter(ElfSectionStructure.SectionIndex, min=index + 1),
                ),
            ),
        )

    async def get_sections_before_index(self, index: int) -> Iterable[ElfSection]:
        return await self.resource.get_children_as_view(
            ElfSection,
            ResourceFilter(
                tags=(ElfSection,),
                attribute_filters=(
                    ResourceAttributeRangeFilter(ElfSectionStructure.SectionIndex, max=index + 1),
                ),
            ),
        )

    async def get_section_by_name(self, name: str) -> ElfSection:
        _ = await self.get_sections()  # Forces analyzing name of all sections
        return await self.resource.get_only_child_as_view(
            ElfSection,
            ResourceFilter(
                tags=(ElfSection,),
                attribute_filters=(ResourceAttributeValueFilter(ElfSection.SectionName, name),),
            ),
        )

    async def get_section_name_string_section(self) -> ElfSectionNameStringSection:
        return await self.resource.get_only_child_as_view(
            ElfSectionNameStringSection,
            ResourceFilter(
                tags=(ElfSectionNameStringSection,),
            ),
        )

    async def get_string_section(self) -> ElfStringSection:
        for string_section in await self.resource.get_children_as_view(
            ElfStringSection,
            ResourceFilter(
                tags=(ElfStringSection,),
            ),
        ):
            if string_section.resource.has_tag(ElfSectionNameStringSection):
                continue
            section = await string_section.get_section()
            if section.name != ".strtab":
                continue
            return string_section
        raise ValueError("Could not find string section!")

    async def get_symbol_section(self) -> ElfSymbolSection:
        return await self.resource.get_only_child_as_view(
            ElfSymbolSection,
            ResourceFilter(
                tags=(ElfSymbolSection,),
            ),
        )

    async def get_section_headers(self) -> Iterable[ElfSectionHeader]:
        return await self.resource.get_children_as_view(
            ElfSectionHeader,
            ResourceFilter(tags=(ElfSectionHeader,)),
            ResourceSort(ElfSectionStructure.SectionIndex, ResourceSortDirection.ASCENDANT),
        )

    async def get_section_header_by_index(self, index: int) -> ElfSectionHeader:
        return await self.resource.get_only_child_as_view(
            ElfSectionHeader,
            ResourceFilter(
                tags=(ElfSectionHeader,),
                attribute_filters=(
                    ResourceAttributeValueFilter(ElfSectionStructure.SectionIndex, index),
                ),
            ),
        )

    async def get_section_header_by_name(self, name: str) -> ElfSectionHeader:
        _ = await self.get_sections()  # Forces analyzing name of all sections
        return await self.resource.get_only_child_as_view(
            ElfSectionHeader,
            ResourceFilter(
                tags=(ElfSectionHeader,),
                attribute_filters=(ResourceAttributeValueFilter(ElfSection.SectionName, name),),
            ),
        )

    async def get_string_section_header(self) -> ElfSectionHeader:
        string_section_r = await self.get_string_section()
        return await string_section_r.get_header()

    async def get_program_headers(self) -> Iterable[ElfProgramHeader]:
        return await self.resource.get_children_as_view(
            ElfProgramHeader,
            ResourceFilter(tags=(ElfProgramHeader,)),
            ResourceSort(ElfProgramHeader.SegmentIndex, ResourceSortDirection.ASCENDANT),
        )

    async def get_program_header(self, index: int) -> ElfProgramHeader:
        return await self.resource.get_only_child_as_view(
            ElfProgramHeader,
            ResourceFilter(
                tags=(ElfProgramHeader,),
                attribute_filters=(
                    ResourceAttributeValueFilter(ElfProgramHeader.SegmentIndex, index),
                ),
            ),
        )


MagicDescriptionIdentifier.register(Elf, lambda s: s.startswith("ELF "))
