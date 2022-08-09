import io
from abc import abstractmethod, ABC
from dataclasses import dataclass
from typing import Any, Iterable, List, Tuple, Union, Dict, Optional
from typing import cast

from ofrak.component.modifier import Modifier
from ofrak.model.component_model import ComponentConfig
from ofrak.model.resource_model import ResourceAttributes
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceFilter
from ofrak.core.elf.model import (
    ElfSectionHeader,
    Elf,
    ElfProgramHeader,
    ElfHeader,
    ElfSymbol,
    ElfSymbolType,
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
    id = b"ElfHeaderModifier"
    targets = (ElfHeader,)

    @classmethod
    def populate_serializer(
        cls, serializer: BinarySerializer, attributes: ElfHeader.attributes_type  # type: ignore
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
        original_attributes = await resource.analyze_attributes(ElfHeader.attributes_type)
        await self.serialize_and_patch(resource, original_attributes, config)


@dataclass
class ElfProgramHeaderModifierConfig(ComponentConfig):
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
    targets = (ElfProgramHeader,)

    async def modify(self, resource: Resource, config: ElfProgramHeaderModifierConfig):
        original_attributes = await resource.analyze_attributes(ElfProgramHeader.attributes_type)
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
    id = b"ElfSectionHeaderModifier"
    targets = (ElfSectionHeader,)

    @classmethod
    def populate_serializer(
        cls,
        serializer: BinarySerializer,
        attributes: ElfSectionHeader.attributes_type,  # type: ignore
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
        original_attributes = await resource.analyze(ElfSectionHeader.attributes_type)
        await self.serialize_and_patch(resource, original_attributes, config)


@dataclass
class ElfSymbolModifierConfig(ComponentConfig):
    st_name: Optional[int] = None
    st_value: Optional[int] = None
    st_size: Optional[int] = None
    st_info: Optional[int] = None
    st_other: Optional[int] = None
    st_shndx: Optional[int] = None


class ElfSymbolModifier(AbstractElfAttributeModifier, Modifier[ElfSymbolModifierConfig]):
    id = b"ElfSymbolModifier"
    targets = (ElfSymbol,)

    @classmethod
    def populate_serializer(
        cls, serializer: BinarySerializer, attributes: ElfSymbol.attributes_type  # type: ignore
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
        original_attributes = await resource.analyze_attributes(ElfSymbol.attributes_type)
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
    The ElfRelaModifier updates values in an Elf{32, 64}_Rela struct
    """

    targets = (ElfRelaEntry,)

    @classmethod
    def populate_serializer(
        cls, serializer: BinarySerializer, attributes: ElfRelaEntry.attributes_type  # type: ignore
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
        original_attributes = await resource.analyze_attributes(ElfRelaEntry.attributes_type)
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
    The ElfRelaModifier updates values in an Elf{32, 64}_Dyn struct
    """

    targets = (ElfDynamicEntry,)

    @classmethod
    def populate_serializer(
        cls,
        serializer: BinarySerializer,
        attributes: ElfDynamicEntry.attributes_type,  # type: ignore
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
        original_attributes = await resource.analyze_attributes(ElfDynamicEntry.attributes_type)
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
    The ElfVirtualAddressModifier updates a pointer value
    """

    targets = (ElfVirtualAddress,)

    @classmethod
    def populate_serializer(
        cls,
        serializer: BinarySerializer,
        attributes: ElfVirtualAddress.attributes_type,  # type: ignore
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
        original_attributes = await resource.analyze_attributes(ElfVirtualAddress.attributes_type)
        await self.serialize_and_patch(resource, original_attributes, config)


@dataclass
class ElfPointerArraySectionAddModifierConfig(ComponentConfig):
    """
    :var skip_list: values that should not be modified
    :var add_value: value to add to all pointers
    """

    skip_list: Iterable[int]
    add_value: int


class ElfPointerArraySectionAddModifier(
    AbstractElfAttributeModifier, Modifier[ElfPointerArraySectionAddModifierConfig]
):
    """
    The ElfPointerArrayAddModifier updates batches of pointer values
    """

    targets = (ElfPointerArraySection,)

    @classmethod
    def populate_serializer(cls, serializer: BinarySerializer, attributes: Any):
        pass

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


class ElfModifierUtils:
    @staticmethod
    async def assert_sections_sorted(e_section_headers_r: Iterable[ElfSectionHeader]):
        e_section_header_offset = -1
        for e_section_header_r in e_section_headers_r:
            if e_section_header_r.sh_offset < e_section_header_offset:
                # That would cause the logic identifying where to stick the section's data to fail
                # in very bad ways.
                raise NotImplementedError(
                    "The sections data is not in the same order as their headers"
                )
            e_section_header_offset = e_section_header_r.sh_offset

    @staticmethod
    async def assert_section_headers_last(
        e_header_r: ElfHeader,
        e_section_headers_r: List[ElfSectionHeader],
    ):
        for e_section_header_r in e_section_headers_r:
            if e_header_r.e_shoff < e_section_header_r.sh_offset + e_section_header_r.sh_size:
                raise ValueError("The elf headers are located before one of the section's data")

    @staticmethod
    async def assert_name_unique(e_section_headers_r: Iterable[ElfSectionHeader], name: str):
        for e_section_header_r in e_section_headers_r:
            e_section_header_name = e_section_header_r.sh_name
            if e_section_header_name == name:
                raise ValueError(f"A section named {name} already exist")

    @staticmethod
    async def find_last_mapped_section_index(e_symbols_r: Iterable[ElfSymbol]) -> int:
        e_section_added_index = -1
        for e_symbol_r in e_symbols_r:
            if e_symbol_r.get_type() is not ElfSymbolType.SECTION:
                continue
            e_section_added_index = max(
                e_section_added_index,
                # e_symbol_r.get_section_index returns an Optional[int], but should never be None
                # here since we know e_symbol_r.get_type() is ElfSymbolType.SECTION. Thus we cast.
                cast(int, e_symbol_r.get_section_index()),
            )
        return e_section_added_index

    @staticmethod
    async def find_mutable_start(
        e_section_headers_r: List[ElfSectionHeader],
        e_symbols_r: Iterable[ElfSymbol],
    ) -> int:
        # Anything after the last section mapped in can be moved around freely. The resize event
        # handler will take care of updating the necessary offsets.
        e_section_index = await ElfModifierUtils.find_last_mapped_section_index(e_symbols_r)
        e_section_header_r = e_section_headers_r[e_section_index]
        return e_section_header_r.get_file_range().end


@dataclass
class ElfAddStringModifierConfig(ComponentConfig):
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
