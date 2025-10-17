import io
from abc import abstractmethod, ABC
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional, Tuple, Union

from ofrak.component.modifier import Modifier
from ofrak.model.component_model import ComponentConfig
from ofrak.model.resource_model import ResourceAttributes
from ofrak.model.viewable_tag_model import AttributesType
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceFilter
from ofrak.core.elf.model import (
    ElfSectionHeader,
    Elf,
    ElfProgramHeader,
    ElfHeader,
    ElfSymbol,
    ElfSectionFlag,
    ElfRelaEntry,
    ElfDynamicEntry,
    ElfPointerArraySection,
    ElfVirtualAddress,
)
from ofrak_io.deserializer import BinaryDeserializer
from ofrak_io.serializer import BinarySerializer
from ofrak_type.range import Range


class AbstractElfAttributeModifier(ABC):
    @classmethod
    @abstractmethod
    def populate_serializer(cls, serializer: BinarySerializer, attributes: Any):
        raise NotImplementedError()

    async def serialize(self, elf_resource: Elf, updated_attributes: ResourceAttributes) -> bytes:
        e_basic_header_r = await elf_resource.get_basic_header()
        buf = io.BytesIO()
        serializer = BinarySerializer(
            buf,
            endianness=e_basic_header_r.get_endianness(),
            word_size=e_basic_header_r.get_bitwidth().get_word_size(),
        )
        self.populate_serializer(serializer, updated_attributes)
        return buf.getvalue()

    async def serialize_and_patch(
        self,
        resource: Resource,
        original_attributes: Any,
        modifier_config: ComponentConfig,
    ):
        elf_resource = await resource.get_only_ancestor_as_view(Elf, ResourceFilter.with_tags(Elf))
        new_attributes = ResourceAttributes.replace_updated(original_attributes, modifier_config)
        new_data = await self.serialize(elf_resource, new_attributes)
        patch_length = await resource.get_data_length()
        resource.queue_patch(Range.from_size(0, patch_length), new_data)
        resource.add_attributes(new_attributes)


@dataclass
class ElfHeaderModifierConfig(ComponentConfig):
    """
    Configuration for modifying ELF header fields that control binary interpretation and execution.

    :var e_type: ELF file type (executable, shared object, relocatable, core dump)
    :var e_machine: Target architecture/machine type (x86, ARM, MIPS, etc.)
    :var e_version: ELF format version number
    :var e_entry: Virtual address where execution begins
    :var e_phoff: File offset to program header table
    :var e_shoff: File offset to section header table
    :var e_flags: Architecture-specific processor flags
    :var e_ehsize: Size of the ELF header in bytes
    :var e_phentsize: Size of one program header table entry
    :var e_phnum: Number of program header entries
    :var e_shentsize: Size of one section header table entry
    :var e_shnum: Number of section header entries
    :var e_shstrndx: Section header table index of section name string table
    """

    e_type: Optional[int] = None
    e_machine: Optional[int] = None
    e_version: Optional[int] = None
    e_entry: Optional[int] = None
    e_phoff: Optional[int] = None
    e_shoff: Optional[int] = None
    e_flags: Optional[int] = None
    e_ehsize: Optional[int] = None
    e_phentsize: Optional[int] = None
    e_phnum: Optional[int] = None
    e_shentsize: Optional[int] = None
    e_shnum: Optional[int] = None
    e_shstrndx: Optional[int] = None


class ElfHeaderModifier(Modifier[ElfHeaderModifierConfig], AbstractElfAttributeModifier):
    """
    Modifies ELF header fields such as entry point address (where execution starts), program header
    table offset and count, section header table offset and count, processor flags, or header size.
    These fields control how the ELF file is interpreted and executed. Use for adjusting execution
    entry point, fixing header tables after modifications, changing architecture flags, updating
    counts after adding/removing headers, or repairing corrupted ELF files. Must be very careful as
    incorrect values can make the ELF unloadable.
    """

    id = b"ElfHeaderModifier"
    targets = (ElfHeader,)

    @classmethod
    def populate_serializer(
        cls, serializer: BinarySerializer, attributes: AttributesType[ElfHeader]
    ):
        serializer.pack_multiple(
            "HHIQQQIHHHHHH",
            attributes.e_type,
            attributes.e_machine,
            attributes.e_version,
            attributes.e_entry,
            attributes.e_phoff,
            attributes.e_shoff,
            attributes.e_flags,
            attributes.e_ehsize,
            attributes.e_phentsize,
            attributes.e_phnum,
            attributes.e_shentsize,
            attributes.e_shnum,
            attributes.e_shstrndx,
            auto_bitwidth=True,
        )

    async def modify(self, resource: Resource, config: ElfHeaderModifierConfig):
        original_attributes = await resource.analyze(AttributesType[ElfHeader])
        await self.serialize_and_patch(resource, original_attributes, config)


@dataclass
class ElfProgramHeaderModifierConfig(ComponentConfig):
    """
    Configuration for modifying ELF program header (Phdr) fields that control segment loading and memory mapping.

    :var p_type: Segment type (PT_LOAD, PT_DYNAMIC, PT_INTERP, etc.)
    :var p_offset: File offset where segment data begins
    :var p_vaddr: Virtual address where segment is loaded in memory
    :var p_paddr: Physical address (for systems where it matters)
    :var p_filesz: Size of segment in the file (bytes)
    :var p_memsz: Size of segment in memory (can be larger than filesz for BSS)
    :var p_flags: Segment permissions (PF_R=read, PF_W=write, PF_X=execute)
    :var p_align: Segment alignment in memory and file
    """

    p_type: Optional[int] = None
    p_offset: Optional[int] = None
    p_vaddr: Optional[int] = None
    p_paddr: Optional[int] = None
    p_filesz: Optional[int] = None
    p_memsz: Optional[int] = None
    p_flags: Optional[int] = None
    p_align: Optional[int] = None


class ElfProgramHeaderModifier(
    AbstractElfAttributeModifier, Modifier[ElfProgramHeaderModifierConfig]
):
    """
    Modifies ELF program header (Phdr) fields including segment type, file and memory addresses,
    sizes, protection flags (read/write/execute), and alignment requirements. Program headers define
    how segments are loaded into memory and their permissions. Use when adjusting ELF loading
    behavior, changing memory protection (making segments executable or writable), resizing
    segments, relocating segments in memory, or fixing up program headers after other modifications.
    Critical for controlling how the binary is loaded and mapped by the operating system.
    """

    targets = (ElfProgramHeader,)

    async def modify(self, resource: Resource, config: ElfProgramHeaderModifierConfig):
        original_attributes = await resource.analyze(AttributesType[ElfProgramHeader])
        await self.serialize_and_patch(resource, original_attributes, config)

    @classmethod
    def populate_serializer(
        cls, serializer: BinarySerializer, elf_program_header: ElfProgramHeader
    ):
        serializer.pack_uint(elf_program_header.p_type)
        if serializer.get_word_size() == 8:
            serializer.pack_uint(elf_program_header.p_flags)
        serializer.pack_multiple(
            "QQQQQ",
            elf_program_header.p_offset,
            elf_program_header.p_vaddr,
            elf_program_header.p_paddr,
            elf_program_header.p_filesz,
            elf_program_header.p_memsz,
            auto_bitwidth=True,
        )
        if serializer.get_word_size() == 4:
            serializer.pack_uint(elf_program_header.p_flags)
        serializer.pack_ulong(elf_program_header.p_align)


@dataclass
class ElfSectionHeaderModifierConfig(ComponentConfig):
    """
    Configuration for modifying ELF section header (Shdr) fields that organize file structure for linking and debugging.

    :var sh_name: Index into section name string table
    :var sh_type: Section type (SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, etc.)
    :var sh_flags: Section attributes (SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR, etc.)
    :var sh_addr: Virtual address of section in memory (if loaded)
    :var sh_offset: File offset where section data begins
    :var sh_size: Size of section in bytes
    :var sh_link: Section index of associated section (meaning depends on type)
    :var sh_info: Extra section information (meaning depends on type)
    :var sh_addralign: Section alignment requirement (power of 2)
    :var sh_entsize: Size of each entry if section holds table of fixed-size entries
    """

    sh_name: Optional[int] = None
    sh_type: Optional[int] = None
    sh_flags: Optional[int] = None
    sh_addr: Optional[int] = None
    sh_offset: Optional[int] = None
    sh_size: Optional[int] = None
    sh_link: Optional[int] = None
    sh_info: Optional[int] = None
    sh_addralign: Optional[int] = None
    sh_entsize: Optional[int] = None


class ElfSectionHeaderModifier(
    AbstractElfAttributeModifier, Modifier[ElfSectionHeaderModifierConfig]
):
    """
    Modifies ELF section header (Shdr) fields including section name, type, flags (writable,
    allocatable, executable), virtual address, file offset, size, link fields, info field,
    alignment, and entry size. Section headers organize the file for linking and debugging. Use for
    adjusting section properties, changing section addresses or sizes, modifying section flags
    (making sections writable or executable), fixing section headers after modifications, or
    reconfiguring section relationships. Essential for maintaining ELF structure integrity after
    changes.
    """

    id = b"ElfSectionHeaderModifier"
    targets = (ElfSectionHeader,)

    @classmethod
    def populate_serializer(
        cls,
        serializer: BinarySerializer,
        attributes: AttributesType[ElfSectionHeader],
    ):
        serializer.pack_multiple(
            "IIQQQQIIQQ",
            attributes.sh_name,
            attributes.sh_type,
            attributes.sh_flags,
            attributes.sh_addr,
            attributes.sh_offset,
            attributes.sh_size,
            attributes.sh_link,
            attributes.sh_info,
            attributes.sh_addralign,
            attributes.sh_entsize,
            auto_bitwidth=True,
        )

    async def modify(
        self,
        resource: Resource,
        config: ElfSectionHeaderModifierConfig,
    ):
        original_attributes = await resource.analyze(AttributesType[ElfSectionHeader])
        await self.serialize_and_patch(resource, original_attributes, config)


@dataclass
class ElfSymbolModifierConfig(ComponentConfig):
    """
    Configuration for modifying ELF symbol table entries that define functions, variables, and other symbols.

    :var st_name: Index into symbol name string table
    :var st_value: Symbol value/address (typically virtual address for functions/variables)
    :var st_size: Size of symbol in bytes (size of function or data object)
    :var st_info: Symbol binding (local/global/weak) and type (function/object/section) packed into one byte
    :var st_other: Symbol visibility (default/internal/hidden/protected)
    :var st_shndx: Section index where symbol is defined (or special values like SHN_UNDEF)
    """

    st_name: Optional[int] = None
    st_value: Optional[int] = None
    st_size: Optional[int] = None
    st_info: Optional[int] = None
    st_other: Optional[int] = None
    st_shndx: Optional[int] = None


class ElfSymbolModifier(AbstractElfAttributeModifier, Modifier[ElfSymbolModifierConfig]):
    """
    Modifies ELF symbol entry fields including name (string table index), value/address, size,
    binding (local/global/weak), type (function/object/section), visibility, and section index.
    These modifications change what the ELF header claims, not what's actually in the binary. Use
    when you need to update the symbol table that the OS loader will read (e.g., after manually
    modifying code locations), but note that modifying code doesn't automatically update these
    symbols - you must manually sync them.
    """

    id = b"ElfSymbolModifier"
    targets = (ElfSymbol,)

    @classmethod
    def populate_serializer(
        cls, serializer: BinarySerializer, attributes: AttributesType[ElfSymbol]
    ):
        if serializer.get_word_size() == 8:
            serializer.pack_multiple(
                "IBBHQQ",
                attributes.st_name,
                attributes.st_info,
                attributes.st_other,
                attributes.st_shndx,
                attributes.st_value,
                attributes.st_size,
            )
        else:
            serializer.pack_multiple(
                "IIIBBH",
                attributes.st_name,
                attributes.st_value,
                attributes.st_size,
                attributes.st_info,
                attributes.st_other,
                attributes.st_shndx,
            )

    async def modify(
        self,
        resource: Resource,
        config: ElfSymbolModifierConfig,
    ):
        original_attributes = await resource.analyze(AttributesType[ElfSymbol])
        await self.serialize_and_patch(resource, original_attributes, config)


@dataclass
class ElfRelaModifierConfig(ComponentConfig):
    """
    :var r_offset: vm offset information for each relocation entry
    :var r_info: Describes the type of relocation and sometimes the symbol related to the relocation
    :var r_addend: Describes the VM offset for each relocation itself
    """

    r_offset: Optional[int] = None
    r_info: Optional[int] = None
    r_addend: Optional[int] = None


class ElfRelaModifier(AbstractElfAttributeModifier, Modifier[ElfRelaModifierConfig]):
    """
    Modifies individual fields in ELF relocation entries with addends (Elf32_Rela or Elf64_Rela),
    including the offset where relocation applies, symbol index, relocation type, and addend
    constant. Relocations control how addresses are adjusted during linking and loading. Use when
    adjusting relocations during binary patching, fixing up relocations after code injection,
    changing symbol references, modifying relocation types, or debugging position-independent code
    issues. Must maintain consistency between relocations and actual code/data.
    """

    targets = (ElfRelaEntry,)

    @classmethod
    def populate_serializer(
        cls, serializer: BinarySerializer, attributes: AttributesType[ElfRelaEntry]
    ):
        if serializer.get_word_size() == 8:
            serializer.pack_multiple(
                "QQq",
                attributes.r_offset,
                attributes.r_info,
                attributes.r_addend,
            )
        else:
            serializer.pack_multiple(
                "IIi",
                attributes.r_offset,
                attributes.r_info,
                attributes.r_addend,
            )

    async def modify(
        self,
        resource: Resource,
        config: ElfRelaModifierConfig,
    ):
        """
        Patches the Elf{32, 64}_Rela struct
        """
        original_attributes = await resource.analyze(AttributesType[ElfRelaEntry])
        await self.serialize_and_patch(resource, original_attributes, config)


@dataclass
class ElfDynamicEntryModifierConfig(ComponentConfig):
    """
    :var d_tag: one of ElfDynamicTableTag
    :var d_un: malleable word size value that changes meaning depending on d_tag
    """

    d_tag: Optional[int] = None
    d_un: Optional[int] = None


class ElfDynamicEntryModifier(
    AbstractElfAttributeModifier, Modifier[ElfDynamicEntryModifierConfig]
):
    """
    Modifies ELF dynamic section entries (Elf32_Dyn or Elf64_Dyn) by changing tags or values,
    affecting runtime dynamic linking behavior. Can modify library dependencies, search paths,
    symbol table locations, initialization functions, and many other dynamic linking parameters.
    Use for changing required libraries (DT_NEEDED), modifying library search paths
    (DT_RPATH/DT_RUNPATH), adjusting symbol table pointers, changing initialization/finalization
    functions, or configuring dynamic linking behavior. Critical for controlling how the runtime
    linker loads and resolves the binary.
    """

    targets = (ElfDynamicEntry,)

    @classmethod
    def populate_serializer(
        cls,
        serializer: BinarySerializer,
        attributes: AttributesType[ElfDynamicEntry],
    ):
        if serializer.get_word_size() == 8:
            serializer.pack_multiple(
                "QQ",
                attributes.d_tag,
                attributes.d_un,
            )
        else:
            serializer.pack_multiple(
                "II",
                attributes.d_tag,
                attributes.d_un,
            )

    async def modify(
        self,
        resource: Resource,
        config: ElfDynamicEntryModifierConfig,
    ):
        """
        Patches the Elf{32, 64}_Dyn struct
        """
        original_attributes = await resource.analyze(AttributesType[ElfDynamicEntry])
        await self.serialize_and_patch(resource, original_attributes, config)


@dataclass
class ElfVirtualAddressModifierConfig(ComponentConfig):
    """
    :var value: an address
    """

    value: Optional[int] = None


class ElfVirtualAddressModifier(
    AbstractElfAttributeModifier, Modifier[ElfVirtualAddressModifierConfig]
):
    """
    Modifies individual pointer values within ELF pointer array sections, updating specific
    function pointer entries to reference new addresses. Each pointer can be independently modified.
    Use for redirecting specific constructor/destructor functions, changing function pointer table
    entries, updating callback addresses, modifying initialization function targets, or implementing
    function hooking via pointer tables. More surgical than ElfPointerArraySectionAddModifier which
    modifies all pointers uniformly.
    """

    targets = (ElfVirtualAddress,)

    @classmethod
    def populate_serializer(
        cls,
        serializer: BinarySerializer,
        attributes: AttributesType[ElfVirtualAddress],
    ):
        serializer.pack_ulong(attributes.value)

    async def modify(
        self,
        resource: Resource,
        config: ElfVirtualAddressModifierConfig,
    ):
        """
        Patches the virtual address
        """
        original_attributes = await resource.analyze(AttributesType[ElfVirtualAddress])
        await self.serialize_and_patch(resource, original_attributes, config)


@dataclass
class ElfPointerArraySectionAddModifierConfig(ComponentConfig):
    """
    :var skip_list: values that should not be modified
    :var add_value: value to add to all pointers
    """

    skip_list: Iterable[int]
    add_value: int


class ElfPointerArraySectionAddModifier(Modifier[ElfPointerArraySectionAddModifierConfig]):
    """
    Adds a constant offset value to all pointer entries in ELF pointer array sections like
    .init_array, .fini_array, .ctors, and .dtors. This batch operation updates every pointer in the
    section by the same amount. Use when relocating code or data that is referenced by
    constructor/destructor arrays, adjusting for base address changes, or fixing up pointers after
    memory layout modifications. Essential when code injection or relocation changes the addresses
    of initialization/cleanup functions.
    """

    targets = (ElfPointerArraySection,)

    async def modify(
        self,
        resource: Resource,
        config: ElfPointerArraySectionAddModifierConfig,
    ):
        """
        Patches the virtual addresses, doesn't change the ElfPointerArraySection attributes
        """

        elf_resource = await resource.get_only_ancestor_as_view(Elf, ResourceFilter.with_tags(Elf))
        e_basic_header_r = await elf_resource.get_basic_header()
        values = list()
        deserializer = BinaryDeserializer(
            io.BytesIO(await resource.get_data()),
            endianness=e_basic_header_r.get_endianness(),
            word_size=e_basic_header_r.get_bitwidth().get_word_size(),
        )
        num_values = (
            await resource.get_data_length() // e_basic_header_r.get_bitwidth().get_word_size()
        )
        for i in range(num_values):
            values.append(deserializer.unpack_ulong())

        buf = io.BytesIO()
        serializer = BinarySerializer(
            buf,
            endianness=e_basic_header_r.get_endianness(),
            word_size=e_basic_header_r.get_bitwidth().get_word_size(),
        )
        for value in values:
            if value not in config.skip_list:
                serializer.pack_ulong(value + config.add_value)
            else:
                serializer.pack_ulong(value)

        patch_length = await resource.get_data_length()
        resource.queue_patch(Range.from_size(0, patch_length), buf.getvalue())


@dataclass
class ElfAddStringModifierConfig(ComponentConfig):
    """
    Configuration for adding strings to the ELF string table for use as symbol or section names.

    :var strings: String or tuple of strings to add to .strtab section (will be null-terminated)
    """

    strings: Union[Tuple[str, ...], str]


class ElfAddStringModifier(Modifier[ElfAddStringModifierConfig]):
    """
    Adds one or more strings to the `.strtab` section in an ELF so that they can be used as the
    names for things like symbols. This modifier only inserts the strings and fixes up the
    succeeding section offsets; it does not modify any existing strings nor does it replace any
    existing strings.
    """

    targets = (Elf,)

    async def modify(
        self,
        resource: Resource,
        config: ElfAddStringModifierConfig,
    ):
        elf = await resource.view_as(Elf)
        string_section = await elf.get_string_section()
        string_section_size = await string_section.resource.get_data_length()

        if type(config.strings) is str:
            strings: Union[Tuple[str, ...], str] = (config.strings,)
        else:
            strings = config.strings
        encoded_strings = b"\x00"
        for string in strings:
            encoded_strings += string.encode("ascii") + b"\x00"
        total_string_section_size_increase = len(encoded_strings) - 1
        # Overwrites the last null byte, but our patch starts with a null byte
        string_section.resource.queue_patch(
            Range.from_size(string_section_size - 1, 1), encoded_strings
        )
        string_section_header = await string_section.get_header()
        original_string_section_offset = string_section_header.sh_offset

        # Now shift all the sections after the string section
        sections = await elf.get_sections()
        for section in sections:
            section_header = await section.get_header()
            if section_header.sh_offset <= original_string_section_offset:
                continue
            if ElfSectionFlag.ALLOC in section_header.get_flags():
                raise NotImplementedError(
                    "Expanding string section would shift offset of section "
                    "which is loaded into memory! May be possible to "
                    "handle, but this is not implemented."
                )
            await section_header.resource.run(
                ElfSectionHeaderModifier,
                ElfSectionHeaderModifierConfig(
                    sh_offset=section_header.sh_offset + total_string_section_size_increase
                ),
            )

        await string_section_header.resource.run(
            ElfSectionHeaderModifier,
            ElfSectionHeaderModifierConfig(
                sh_size=string_section_size + total_string_section_size_increase
            ),
        )

        # Section table is probably at end of binary too
        elf_header = await elf.get_header()
        if elf_header.e_shoff > string_section_header.sh_offset:
            await elf_header.resource.run(
                ElfHeaderModifier,
                ElfHeaderModifierConfig(
                    e_shoff=elf_header.e_shoff + total_string_section_size_increase
                ),
            )


@dataclass
class ElfRelocateSymbolsModifierConfig(ComponentConfig):
    """
    Configuration for changing symbol addresses in an ELF file, updating where symbols point in memory.

    :var new_symbol_vaddrs: Dictionary mapping original symbol virtual addresses to new virtual addresses
    """

    new_symbol_vaddrs: Dict[int, int]


class ElfRelocateSymbolsModifier(Modifier[ElfRelocateSymbolsModifierConfig]):
    """
    Changes the virtual address value of symbols in an ELF file. If that ELF is an object file
    and is subsequently linked into an executable, any instructions referencing that symbol will
    now refer to the new address. This works even on implicitly or automatically generated symbols,
    like the absolute branches between basic blocks within a function. A linker script cannot
    change the targets of these branches individually, but this modifier can.

    The config includes a dictionary, which should map from the original address of a symbol to
    the new address that symbol should be defined as. For example, if a branch jumps to `0x1000`
    and the goal is to change that branch to instead jump to `0x1800`, the config dictionary should
    include the pair `{0x1000: 0x1800}`.
    """

    targets = (Elf,)

    async def modify(self, resource: Resource, config: ElfRelocateSymbolsModifierConfig) -> None:
        elf = await resource.view_as(Elf)
        symbol_section = await elf.get_symbol_section()
        for symbol in await symbol_section.get_symbols():
            if symbol.st_value in config.new_symbol_vaddrs:
                await symbol.resource.run(
                    ElfSymbolModifier,
                    ElfSymbolModifierConfig(
                        st_value=config.new_symbol_vaddrs[symbol.st_value],
                    ),
                )
