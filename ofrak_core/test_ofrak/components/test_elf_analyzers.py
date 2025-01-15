import dataclasses
import os
import random
import re
import struct
import subprocess
from dataclasses import dataclass
from typing import Union, Callable, Optional, Tuple, Type, cast, Iterable

import pytest

from ofrak import OFRAKContext
from ofrak.core.architecture import ProgramAttributes
from ofrak.core.elf.analyzer import (
    ElfRelaAnalyzer,
    ElfDynamicSectionAnalyzer,
    ElfPointerAnalyzer,
)
from ofrak.core.elf.model import (
    ElfBasicHeader,
    Elf,
    ElfHeader,
    ElfProgramHeader,
    ElfSectionHeader,
    ElfSymbol,
    ElfSectionNameStringSection,
    ElfSection,
    ElfSectionType,
    ElfSegmentStructure,
    ElfSectionStructure,
    ElfSymbolStructure,
    ElfRelaEntry,
    ElfDynamicEntry,
    ElfDynamicTableTag,
    ElfVirtualAddress,
    ElfRelaSection,
    ElfDynamicSection,
    ElfPointerArraySection,
)
from ofrak.model.viewable_tag_model import ViewableResourceTag, AttributesType
from ofrak.resource import Resource
from ofrak.resource_view import ResourceView
from ofrak.service.resource_service_i import ResourceFilter
from ofrak_type.architecture import InstructionSet
from ofrak_type.bit_width import BitWidth
from ofrak_type.endianness import Endianness


@dataclass
class ElfDeserializingAnalyzerTestCase:
    endianness: Endianness
    bit_width: BitWidth
    expected_view: ResourceView
    pack_format: Union[str, Callable[[ResourceView], bytes]]
    label: Optional[str] = None

    def get_target_tag(self) -> ViewableResourceTag:
        return type(self.expected_view)

    def get_header_data(self) -> bytes:
        if type(self.pack_format) is str:
            excluded_field_names = ResourceView.get_special_field_names().union(
                ("section_index", "symbol_index")
            )
            ordered_field_names = (
                f.name
                for f in dataclasses.fields(self.expected_view)
                if f.name not in excluded_field_names
            )
            field_values = (getattr(self.expected_view, fname) for fname in ordered_field_names)
            return struct.pack(self.pack_format, *field_values)
        else:
            return self.pack_format(self.expected_view)

    def create_basic_elf_header(self) -> ElfBasicHeader:
        if self.endianness is Endianness.BIG_ENDIAN:
            ei_data = 2
        else:
            ei_data = 1

        if self.bit_width is BitWidth.BIT_32:
            ei_class = 1
        elif self.bit_width is BitWidth.BIT_64:
            ei_class = 2
        else:
            raise ValueError(self.bit_width)
        return ElfBasicHeader(b"\x7fELF", ei_class, ei_data, 1, 0, 0, b"\x00" * 7)

    async def create_test_elf(self, ofrak_context: OFRAKContext) -> Resource:
        basic_header = self.create_basic_elf_header()
        elf_r = await ofrak_context.create_root_resource("test_elf", b"", tags=(Elf,))
        await elf_r.create_child_from_view(basic_header)
        if issubclass(self.get_target_tag(), ElfSegmentStructure):
            expected_elf_structure = cast(ElfSegmentStructure, self.expected_view)
            attributes = (
                AttributesType[ElfSegmentStructure](expected_elf_structure.segment_index),
            )
        elif issubclass(self.get_target_tag(), ElfSectionStructure):
            expected_elf_structure = cast(ElfSectionStructure, self.expected_view)
            attributes = (
                AttributesType[ElfSectionStructure](expected_elf_structure.section_index),
            )
        elif issubclass(self.get_target_tag(), ElfSymbolStructure):
            expected_elf_structure = cast(ElfSymbolStructure, self.expected_view)
            attributes = (AttributesType[ElfSymbolStructure](expected_elf_structure.symbol_index),)
        else:
            attributes = ()
        return await elf_r.create_child(
            tags=(self.get_target_tag(),),
            data=self.get_header_data(),
            attributes=attributes,
        )

    def get_label(self) -> str:
        return f"{self.get_target_tag().__name__}-{self.bit_width.name}-{self.endianness.name}"


ELF_ANALYZER_TEST_CASES = [
    ElfDeserializingAnalyzerTestCase(
        Endianness.BIG_ENDIAN,
        BitWidth.BIT_32,
        ElfHeader(
            e_type=random.randrange(0, (2**16) - 1),
            e_machine=random.randrange(0, (2**16) - 1),
            e_version=random.randrange(0, (2**32) - 1),
            e_entry=random.randrange(0, (2**32) - 1),
            e_phoff=random.randrange(0, (2**32) - 1),
            e_shoff=random.randrange(0, (2**32) - 1),
            e_flags=random.randrange(0, (2**32) - 1),
            e_ehsize=random.randrange(0, (2**16) - 1),
            e_phentsize=random.randrange(0, (2**16) - 1),
            e_phnum=random.randrange(0, (2**16) - 1),
            e_shentsize=random.randrange(0, (2**16) - 1),
            e_shnum=random.randrange(0, (2**16) - 1),
            e_shstrndx=random.randrange(0, (2**16) - 1),
        ),
        ">HHIIIIIHHHHHH",
    ),
    ElfDeserializingAnalyzerTestCase(
        Endianness.LITTLE_ENDIAN,
        BitWidth.BIT_32,
        ElfHeader(
            e_type=random.randrange(0, (2**16) - 1),
            e_machine=random.randrange(0, (2**16) - 1),
            e_version=random.randrange(0, (2**32) - 1),
            e_entry=random.randrange(0, (2**32) - 1),
            e_phoff=random.randrange(0, (2**32) - 1),
            e_shoff=random.randrange(0, (2**32) - 1),
            e_flags=random.randrange(0, (2**32) - 1),
            e_ehsize=random.randrange(0, (2**16) - 1),
            e_phentsize=random.randrange(0, (2**16) - 1),
            e_phnum=random.randrange(0, (2**16) - 1),
            e_shentsize=random.randrange(0, (2**16) - 1),
            e_shnum=random.randrange(0, (2**16) - 1),
            e_shstrndx=random.randrange(0, (2**16) - 1),
        ),
        "<HHIIIIIHHHHHH",
    ),
    ElfDeserializingAnalyzerTestCase(
        Endianness.BIG_ENDIAN,
        BitWidth.BIT_64,
        ElfHeader(
            e_type=random.randrange(0, (2**16) - 1),
            e_machine=random.randrange(0, (2**16) - 1),
            e_version=random.randrange(0, (2**32) - 1),
            e_entry=random.randrange(0, (2**64) - 1),
            e_phoff=random.randrange(0, (2**64) - 1),
            e_shoff=random.randrange(0, (2**64) - 1),
            e_flags=random.randrange(0, (2**32) - 1),
            e_ehsize=random.randrange(0, (2**16) - 1),
            e_phentsize=random.randrange(0, (2**16) - 1),
            e_phnum=random.randrange(0, (2**16) - 1),
            e_shentsize=random.randrange(0, (2**16) - 1),
            e_shnum=random.randrange(0, (2**16) - 1),
            e_shstrndx=random.randrange(0, (2**16) - 1),
        ),
        ">HHIQQQIHHHHHH",
    ),
    ElfDeserializingAnalyzerTestCase(
        Endianness.LITTLE_ENDIAN,
        BitWidth.BIT_64,
        ElfHeader(
            e_type=random.randrange(0, (2**16) - 1),
            e_machine=random.randrange(0, (2**16) - 1),
            e_version=random.randrange(0, (2**32) - 1),
            e_entry=random.randrange(0, (2**64) - 1),
            e_phoff=random.randrange(0, (2**64) - 1),
            e_shoff=random.randrange(0, (2**64) - 1),
            e_flags=random.randrange(0, (2**32) - 1),
            e_ehsize=random.randrange(0, (2**16) - 1),
            e_phentsize=random.randrange(0, (2**16) - 1),
            e_phnum=random.randrange(0, (2**16) - 1),
            e_shentsize=random.randrange(0, (2**16) - 1),
            e_shnum=random.randrange(0, (2**16) - 1),
            e_shstrndx=random.randrange(0, (2**16) - 1),
        ),
        "<HHIQQQIHHHHHH",
    ),
    ElfDeserializingAnalyzerTestCase(
        Endianness.BIG_ENDIAN,
        BitWidth.BIT_32,
        ElfProgramHeader(
            segment_index=1,
            p_type=random.randrange(0, (2**32) - 1),
            p_offset=random.randrange(0, (2**32) - 1),
            p_vaddr=random.randrange(0, (2**32) - 1),
            p_paddr=random.randrange(0, (2**32) - 1),
            p_filesz=random.randrange(0, (2**32) - 1),
            p_memsz=random.randrange(0, (2**32) - 1),
            p_flags=random.randrange(0, (2**32) - 1),
            p_align=random.randrange(0, (2**32) - 1),
        ),
        lambda pheader: struct.pack(
            ">IIIIIIII",
            pheader.p_type,
            pheader.p_offset,
            pheader.p_vaddr,
            pheader.p_paddr,
            pheader.p_filesz,
            pheader.p_memsz,
            pheader.p_flags,
            pheader.p_align,
        ),
    ),
    ElfDeserializingAnalyzerTestCase(
        Endianness.LITTLE_ENDIAN,
        BitWidth.BIT_32,
        ElfProgramHeader(
            segment_index=1,
            p_type=random.randrange(0, (2**32) - 1),
            p_offset=random.randrange(0, (2**32) - 1),
            p_vaddr=random.randrange(0, (2**32) - 1),
            p_paddr=random.randrange(0, (2**32) - 1),
            p_filesz=random.randrange(0, (2**32) - 1),
            p_memsz=random.randrange(0, (2**32) - 1),
            p_flags=random.randrange(0, (2**32) - 1),
            p_align=random.randrange(0, (2**32) - 1),
        ),
        lambda pheader: struct.pack(
            "<IIIIIIII",
            pheader.p_type,
            pheader.p_offset,
            pheader.p_vaddr,
            pheader.p_paddr,
            pheader.p_filesz,
            pheader.p_memsz,
            pheader.p_flags,
            pheader.p_align,
        ),
    ),
    ElfDeserializingAnalyzerTestCase(
        Endianness.BIG_ENDIAN,
        BitWidth.BIT_64,
        ElfProgramHeader(
            segment_index=1,
            p_type=random.randrange(0, (2**32) - 1),
            p_offset=random.randrange(0, (2**64) - 1),
            p_vaddr=random.randrange(0, (2**64) - 1),
            p_paddr=random.randrange(0, (2**64) - 1),
            p_filesz=random.randrange(0, (2**64) - 1),
            p_memsz=random.randrange(0, (2**64) - 1),
            p_flags=random.randrange(0, (2**32) - 1),
            p_align=random.randrange(0, (2**64) - 1),
        ),
        lambda pheader: struct.pack(
            ">IIQQQQQQ",
            pheader.p_type,
            pheader.p_flags,
            pheader.p_offset,
            pheader.p_vaddr,
            pheader.p_paddr,
            pheader.p_filesz,
            pheader.p_memsz,
            pheader.p_align,
        ),
    ),
    ElfDeserializingAnalyzerTestCase(
        Endianness.LITTLE_ENDIAN,
        BitWidth.BIT_64,
        ElfProgramHeader(
            segment_index=1,
            p_type=random.randrange(0, (2**32) - 1),
            p_offset=random.randrange(0, (2**64) - 1),
            p_vaddr=random.randrange(0, (2**64) - 1),
            p_paddr=random.randrange(0, (2**64) - 1),
            p_filesz=random.randrange(0, (2**64) - 1),
            p_memsz=random.randrange(0, (2**64) - 1),
            p_flags=random.randrange(0, (2**32) - 1),
            p_align=random.randrange(0, (2**64) - 1),
        ),
        lambda pheader: struct.pack(
            "<IIQQQQQQ",
            pheader.p_type,
            pheader.p_flags,
            pheader.p_offset,
            pheader.p_vaddr,
            pheader.p_paddr,
            pheader.p_filesz,
            pheader.p_memsz,
            pheader.p_align,
        ),
    ),
    ElfDeserializingAnalyzerTestCase(
        Endianness.BIG_ENDIAN,
        BitWidth.BIT_32,
        ElfSectionHeader(
            section_index=1,
            sh_name=random.randrange(0, (2**32) - 1),
            sh_type=random.randrange(0, (2**32) - 1),
            sh_flags=random.randrange(0, (2**32) - 1),
            sh_addr=random.randrange(0, (2**32) - 1),
            sh_offset=random.randrange(0, (2**32) - 1),
            sh_size=random.randrange(0, (2**32) - 1),
            sh_link=random.randrange(0, (2**32) - 1),
            sh_info=random.randrange(0, (2**32) - 1),
            sh_addralign=random.randrange(0, (2**32) - 1),
            sh_entsize=random.randrange(0, (2**32) - 1),
        ),
        ">IIIIIIIIII",
    ),
    ElfDeserializingAnalyzerTestCase(
        Endianness.LITTLE_ENDIAN,
        BitWidth.BIT_32,
        ElfSectionHeader(
            section_index=1,
            sh_name=random.randrange(0, (2**32) - 1),
            sh_type=random.randrange(0, (2**32) - 1),
            sh_flags=random.randrange(0, (2**32) - 1),
            sh_addr=random.randrange(0, (2**32) - 1),
            sh_offset=random.randrange(0, (2**32) - 1),
            sh_size=random.randrange(0, (2**32) - 1),
            sh_link=random.randrange(0, (2**32) - 1),
            sh_info=random.randrange(0, (2**32) - 1),
            sh_addralign=random.randrange(0, (2**32) - 1),
            sh_entsize=random.randrange(0, (2**32) - 1),
        ),
        "<IIIIIIIIII",
    ),
    ElfDeserializingAnalyzerTestCase(
        Endianness.BIG_ENDIAN,
        BitWidth.BIT_64,
        ElfSectionHeader(
            section_index=1,
            sh_name=random.randrange(0, (2**32) - 1),
            sh_type=random.randrange(0, (2**32) - 1),
            sh_flags=random.randrange(0, (2**64) - 1),
            sh_addr=random.randrange(0, (2**64) - 1),
            sh_offset=random.randrange(0, (2**64) - 1),
            sh_size=random.randrange(0, (2**64) - 1),
            sh_link=random.randrange(0, (2**32) - 1),
            sh_info=random.randrange(0, (2**32) - 1),
            sh_addralign=random.randrange(0, (2**64) - 1),
            sh_entsize=random.randrange(0, (2**64) - 1),
        ),
        ">IIQQQQIIQQ",
    ),
    ElfDeserializingAnalyzerTestCase(
        Endianness.LITTLE_ENDIAN,
        BitWidth.BIT_64,
        ElfSectionHeader(
            section_index=1,
            sh_name=random.randrange(0, (2**32) - 1),
            sh_type=random.randrange(0, (2**32) - 1),
            sh_flags=random.randrange(0, (2**64) - 1),
            sh_addr=random.randrange(0, (2**64) - 1),
            sh_offset=random.randrange(0, (2**64) - 1),
            sh_size=random.randrange(0, (2**64) - 1),
            sh_link=random.randrange(0, (2**32) - 1),
            sh_info=random.randrange(0, (2**32) - 1),
            sh_addralign=random.randrange(0, (2**64) - 1),
            sh_entsize=random.randrange(0, (2**64) - 1),
        ),
        "<IIQQQQIIQQ",
    ),
    ElfDeserializingAnalyzerTestCase(
        Endianness.BIG_ENDIAN,
        BitWidth.BIT_32,
        ElfSymbol(
            symbol_index=1,
            st_name=random.randrange(0, (2**32) - 1),
            st_value=random.randrange(0, (2**32) - 1),
            st_size=random.randrange(0, (2**32) - 1),
            st_info=random.randrange(0, (2**8) - 1),
            st_other=random.randrange(0, (2**8) - 1),
            st_shndx=random.randrange(0, (2**16) - 1),
        ),
        ">IIIBBH",
    ),
    ElfDeserializingAnalyzerTestCase(
        Endianness.LITTLE_ENDIAN,
        BitWidth.BIT_32,
        ElfSymbol(
            symbol_index=1,
            st_name=random.randrange(0, (2**32) - 1),
            st_value=random.randrange(0, (2**32) - 1),
            st_size=random.randrange(0, (2**32) - 1),
            st_info=random.randrange(0, (2**8) - 1),
            st_other=random.randrange(0, (2**8) - 1),
            st_shndx=random.randrange(0, (2**16) - 1),
        ),
        "<IIIBBH",
    ),
    ElfDeserializingAnalyzerTestCase(
        Endianness.BIG_ENDIAN,
        BitWidth.BIT_64,
        ElfSymbol(
            symbol_index=1,
            st_name=random.randrange(0, (2**32) - 1),
            st_value=random.randrange(0, (2**64) - 1),
            st_size=random.randrange(0, (2**64) - 1),
            st_info=random.randrange(0, (2**8) - 1),
            st_other=random.randrange(0, (2**8) - 1),
            st_shndx=random.randrange(0, (2**16) - 1),
        ),
        lambda st: struct.pack(
            ">IBBHQQ", st.st_name, st.st_info, st.st_other, st.st_shndx, st.st_value, st.st_size
        ),
    ),
    ElfDeserializingAnalyzerTestCase(
        Endianness.LITTLE_ENDIAN,
        BitWidth.BIT_64,
        ElfSymbol(
            symbol_index=1,
            st_name=random.randrange(0, (2**32) - 1),
            st_value=random.randrange(0, (2**64) - 1),
            st_size=random.randrange(0, (2**64) - 1),
            st_info=random.randrange(0, (2**8) - 1),
            st_other=random.randrange(0, (2**8) - 1),
            st_shndx=random.randrange(0, (2**16) - 1),
        ),
        lambda st: struct.pack(
            "<IBBHQQ", st.st_name, st.st_info, st.st_other, st.st_shndx, st.st_value, st.st_size
        ),
    ),
]


@pytest.mark.parametrize("test_case", ELF_ANALYZER_TEST_CASES, ids=lambda tc: tc.get_label())
async def test_deserializing_analyzers(ofrak_context, test_case: ElfDeserializingAnalyzerTestCase):
    test_target = await test_case.create_test_elf(ofrak_context)
    analyzed_view = await test_target.view_as(test_case.get_target_tag())  # type: ignore
    assert test_case.expected_view == analyzed_view


@dataclass
class ElfBasicHeaderTestCase:
    label: str
    data: bytes
    expected_results: Union[Tuple[Endianness, BitWidth], Type[Exception]]

    async def create_header(self, ofrak_context: OFRAKContext) -> Resource:
        return await ofrak_context.create_root_resource(
            self.label, self.data, tags=(ElfBasicHeader,)
        )


ELF_BASIC_HEADER_ANALYZER_TEST_CASES = [
    ElfBasicHeaderTestCase(
        "invalid magic",
        struct.pack("4sBBBBB7s", b"\x7fLOL", 0, 0, 0, 0, 0, b"\x00" * 7),
        AssertionError,
    ),
    ElfBasicHeaderTestCase(
        "little endian, 32-bit",
        struct.pack("4sBBBBB7s", b"\x7fELF", 1, 1, 0, 0, 0, b"\x00" * 7),
        (Endianness.LITTLE_ENDIAN, BitWidth.BIT_32),
    ),
    ElfBasicHeaderTestCase(
        "little endian, 64-bit",
        struct.pack("4sBBBBB7s", b"\x7fELF", 2, 1, 0, 0, 0, b"\x00" * 7),
        (Endianness.LITTLE_ENDIAN, BitWidth.BIT_64),
    ),
    ElfBasicHeaderTestCase(
        "big endian, 32-bit",
        struct.pack("4sBBBBB7s", b"\x7fELF", 1, 2, 0, 0, 0, b"\x00" * 7),
        (Endianness.BIG_ENDIAN, BitWidth.BIT_32),
    ),
    ElfBasicHeaderTestCase(
        "big endian, 64-bit",
        struct.pack("4sBBBBB7s", b"\x7fELF", 2, 2, 0, 0, 0, b"\x00" * 7),
        (Endianness.BIG_ENDIAN, BitWidth.BIT_64),
    ),
    ElfBasicHeaderTestCase(
        "invalid bit width",
        struct.pack("4sBBBBB7s", b"\x7fELF", 3, 1, 0, 0, 0, b"\x00" * 7),
        ValueError,
    ),
    ElfBasicHeaderTestCase(
        "invalid endianness",
        struct.pack("4sBBBBB7s", b"\x7fELF", 1, 3, 0, 0, 0, b"\x00" * 7),
        ValueError,
    ),
]


@pytest.mark.parametrize("test_case", ELF_BASIC_HEADER_ANALYZER_TEST_CASES, ids=lambda tc: tc.label)
async def test_basic_header_analyzer(
    ofrak_context: OFRAKContext, test_case: ElfBasicHeaderTestCase
):
    basic_header_r = await test_case.create_header(ofrak_context)
    if type(test_case.expected_results) is tuple:
        basic_header = await basic_header_r.view_as(ElfBasicHeader)
        expected_endianness, expected_bit_width = test_case.expected_results
        assert expected_endianness == basic_header.get_endianness()
        assert expected_bit_width == basic_header.get_bitwidth()
    else:
        expected_error = test_case.expected_results
        with pytest.raises(expected_error):
            basic_header = await basic_header_r.view_as(ElfBasicHeader)
            _ = basic_header.get_endianness()
            _ = basic_header.get_bitwidth()


async def test_elf_section_name_analyzer(ofrak_context: OFRAKContext):
    test_section_elf_index = 3
    test_section_name_offset = 0x40
    test_section_name = ".rbs_test_name"

    # set up minimal ELF resource structure
    elf_section_name_section = ElfSectionNameStringSection(
        1,
    )
    elf_section_name_section_data = (
        (b"\x00" * test_section_name_offset)
        + test_section_name.encode("ascii")
        + b"\x00"
        + b"\x44" * 0x10
    )
    section_header = ElfSectionHeader(
        test_section_elf_index,
        test_section_name_offset,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    section_body = ElfSectionStructure(test_section_elf_index)
    elf_r = await _create_populated_elf(
        ofrak_context,
        ei_class=1,  # 32-bit
        ei_data=1,  # little-endian
    )
    await elf_r.create_child_from_view(elf_section_name_section, data=elf_section_name_section_data)
    await elf_r.create_child_from_view(section_header)
    section_body_r = await elf_r.create_child_from_view(section_body, additional_tags=(ElfSection,))

    # Do analysis
    analyzed_elf_section = await section_body_r.view_as(ElfSection)
    assert test_section_name == analyzed_elf_section.name


async def test_elf_program_attributes_analyzer(ofrak_context: OFRAKContext):
    expected_program_attrs = ProgramAttributes(
        InstructionSet.ARM,
        None,
        BitWidth.BIT_32,
        Endianness.LITTLE_ENDIAN,
        None,
    )
    elf_r = await _create_populated_elf(
        ofrak_context,
        ei_class=1,  # 32-bit
        ei_data=1,  # little-endian
        e_machine=0x28,
    )

    analyzed_program_attrs = await elf_r.analyze(ProgramAttributes)
    assert analyzed_program_attrs == expected_program_attrs


async def test_elf_program_attributes_analyzer_unknown_isa(ofrak_context: OFRAKContext):
    elf_r = await _create_populated_elf(
        ofrak_context,
        ei_class=1,  # 32-bit
        ei_data=1,  # little-endian
        e_machine=0xFF,
    )

    with pytest.raises(KeyError):
        _ = await elf_r.analyze(ProgramAttributes)


async def test_elf_unknown_os_specific_section_type():
    """
    A range of possible section types is reserved for OS-specific types, so we don't necessarily
    have an enum type for them. This should not cause any failures in OFRAK though. However we do
    expect to raise an error if the section type is unknown and not in this reserved OS-specific
    range.
    Although this is not a test of an analyzer exactly, it seems important to explicitly test.
    :return:
    """
    os_specific_section_type = ElfSectionType(0x6007010F)
    assert os_specific_section_type is ElfSectionType.UNKNOWN_OS_SPECIFIC

    with pytest.raises(ValueError):
        _ = ElfSectionType(0x50000000)


async def _create_populated_elf(
    ofrak_context: OFRAKContext,
    ei_magic: bytes = b"\x7ELF",
    ei_class: int = 0,
    ei_data: int = 0,
    ei_version: int = 0,
    ei_osabi: int = 0,
    ei_abiversion: int = 0,
    ei_pad: bytes = b"\x00" * 7,
    e_type=0,
    e_machine=0,
    e_version=0,
    e_entry=0,
    e_phoff=0,
    e_shoff=0,
    e_flags=0,
    e_ehsize=0,
    e_phentsize=0,
    e_phnum=0,
    e_shentsize=0,
    e_shnum=0,
    e_shstrndx=0,
) -> Resource:
    elf_basic_header = ElfBasicHeader(
        ei_magic,
        ei_class,
        ei_data,
        ei_version,
        ei_osabi,
        ei_abiversion,
        ei_pad,
    )
    elf_header = ElfHeader(
        e_type=e_type,
        e_machine=e_machine,
        e_version=e_version,
        e_entry=e_entry,
        e_phoff=e_phoff,
        e_shoff=e_shoff,
        e_flags=e_flags,
        e_ehsize=e_ehsize,
        e_phentsize=e_phentsize,
        e_phnum=e_phnum,
        e_shentsize=e_shentsize,
        e_shnum=e_shnum,
        e_shstrndx=e_shstrndx,
    )
    elf_r = await ofrak_context.create_root_resource("test_elf", b"", tags=(Elf,))
    await elf_r.create_child_from_view(elf_basic_header)
    await elf_r.create_child_from_view(elf_header)

    return elf_r


def readelf_extract_relocs(readelf_path: str, executable_file: str) -> Iterable[ElfRelaEntry]:
    """
    Relocation section '.rela.dyn' at offset 0x488 contains 8 entries:
      Offset          Info           Type           Sym. Value    Sym. Name + Addend
    000000003de8  000000000008 R_X86_64_RELATIVE                    1130
    000000003df0  000000000008 R_X86_64_RELATIVE                    10f0
    000000004028  000000000008 R_X86_64_RELATIVE                    4028
    000000003fd8  000100000006 R_X86_64_GLOB_DAT 0000000000000000 _ITM_deregisterTM[...] + 0
    000000003fe0  000300000006 R_X86_64_GLOB_DAT 0000000000000000 __libc_start_main@GLIBC_2.2.5 + 0
    000000003fe8  000400000006 R_X86_64_GLOB_DAT 0000000000000000 __gmon_start__ + 0
    """
    flags = "--relocs"
    args = [readelf_path, flags, executable_file]
    proc = subprocess.run(args, stdout=subprocess.PIPE, encoding="utf-8", check=True)
    lines = proc.stdout.split("\n")
    result = list()
    for line in lines:
        tokens = line.split()
        if len(tokens) == 0 or tokens[0] in ["Relocation", "Offset"]:
            continue
        rela = ElfRelaEntry(int(tokens[0], 16), int(tokens[1], 16), int(tokens[-1], 16))
        result.append(rela)

    return result


def filter_dyn(dyns: Iterable[ElfDynamicEntry]):
    # These should be enough to test against for now until someone volunteers
    # to parse the readelf output for the rest.
    keep_list = [
        ElfDynamicTableTag.DT_NULL,
        ElfDynamicTableTag.DT_PLTRELSZ,
        ElfDynamicTableTag.DT_PLTGOT,
        ElfDynamicTableTag.DT_HASH,
        ElfDynamicTableTag.DT_STRTAB,
        ElfDynamicTableTag.DT_SYMTAB,
        ElfDynamicTableTag.DT_RELA,
        ElfDynamicTableTag.DT_RELASZ,
        ElfDynamicTableTag.DT_RELAENT,
        ElfDynamicTableTag.DT_INIT,
        ElfDynamicTableTag.DT_FINI,
        ElfDynamicTableTag.DT_DEBUG,
        ElfDynamicTableTag.DT_JMPREL,
        ElfDynamicTableTag.DT_INIT_ARRAY,
        ElfDynamicTableTag.DT_FINI_ARRAY,
        ElfDynamicTableTag.DT_INIT_ARRAYSZ,
        ElfDynamicTableTag.DT_FINI_ARRAYSZ,
        ElfDynamicTableTag.DT_GNU_HASH,
        ElfDynamicTableTag.DT_RELACOUNT,
        ElfDynamicTableTag.DT_VERNEED,
        ElfDynamicTableTag.DT_VERNEEDNUM,
    ]

    # Tags in this table are unique.
    # There should be one NULL entry then some padding, which can also be interpreted by our
    # analyzer as duplicate NULL entries. This is benign behavior.
    # OFRAK doesn't seem to like hashable types, so I can't enforce a set().
    result = list()
    have_null = False
    for dyn in dyns:
        if dyn.d_tag not in keep_list:
            continue
        if dyn.d_tag == ElfDynamicTableTag.DT_NULL:
            if have_null:
                continue
            else:
                have_null = True
                result.append(dyn)
    return result


def readelf_extract_dyns(readelf_path: str, executable_file: str) -> Iterable[ElfDynamicEntry]:
    """
    Dynamic section at offset 0x2df8 contains 26 entries:
      Tag        Type                         Name/Value
     0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
     0x000000000000000c (INIT)               0x1000
     0x000000000000000d (FINI)               0x11d4
     0x0000000000000019 (INIT_ARRAY)         0x3de8
     0x000000000000001b (INIT_ARRAYSZ)       8 (bytes)
     0x000000000000001a (FINI_ARRAY)         0x3df0
     ...
    """
    flags = "--dynamic"
    args = [readelf_path, flags, executable_file]
    proc = subprocess.run(args, stdout=subprocess.PIPE, encoding="utf-8", check=True)
    lines = proc.stdout.split("\n")
    result = list()
    for line in lines:
        tokens = line.split()
        val = None
        if len(tokens) == 0 or tokens[0] in ["Dynamic", "Tag"]:
            continue
        if len(tokens) == 3:
            if not tokens[-1].startswith("0x"):
                if not tokens[-1].isnumeric():  # isnumeric fails for 0x values
                    continue
            val = tokens[-1]
        elif len(tokens) == 4:
            if tokens[-1] == "(bytes)":
                val = tokens[-2]
        else:
            continue

        if val is None:
            continue

        dyn = ElfDynamicEntry(int(tokens[0], 16), int(val, 16))
        result.append(dyn)

    return result


def readelf_extract_vaddrs(readelf_path: str, executable_file: str) -> Iterable[ElfVirtualAddress]:
    """
    Hex dump of section '.got.plt':
    NOTE: This section has relocations against it, but these have NOT been applied to this dump.
    0x00004000 f83d0000 00000000 00000000 00000000 .=..............
    0x00004010 00000000 00000000 36100000 00000000 ........6......
    """
    re_vals = re.compile(r"(?<=0x\S{8} )(\S{8} ){2,4}")
    flags1 = "--hex-dump=.init_array"
    flags2 = "--hex-dump=.fini_array"
    args1 = [readelf_path, flags1, executable_file]
    proc1 = subprocess.run(args1, stdout=subprocess.PIPE, encoding="utf-8", check=True)
    args2 = [readelf_path, flags2, executable_file]
    proc2 = subprocess.run(args2, stdout=subprocess.PIPE, encoding="utf-8", check=True)
    lines = list()
    for proc in [proc1, proc2]:
        lines += proc.stdout.split("\n")
    result = list()
    for line in lines:
        vals = re_vals.search(line)
        if vals == None:
            continue
        stripped_vals = "".join(vals.group(0).split(" "))
        # because little endian...
        byte_swapped = "".join(
            reversed([stripped_vals[i : i + 2] for i in range(0, len(stripped_vals), 2)])
        )
        result.append(ElfVirtualAddress(int(byte_swapped, 16)))

    return result


ANALYZER_VIEWS_UNDER_TEST = [
    (
        readelf_extract_relocs,
        ElfRelaAnalyzer,
        ElfRelaSection,
        ElfRelaEntry,
        None,
        "r_offset",
    ),
    (
        readelf_extract_dyns,
        ElfDynamicSectionAnalyzer,
        ElfDynamicSection,
        ElfDynamicEntry,
        filter_dyn,
        "d_tag",
    ),
    (
        readelf_extract_vaddrs,
        ElfPointerAnalyzer,
        ElfPointerArraySection,
        ElfVirtualAddress,
        None,
        "value",
    ),
]


@pytest.mark.parametrize(
    "readelf_helper, analyzer, test_view, test_entry_view, filter_helper, entry_sort",
    ANALYZER_VIEWS_UNDER_TEST,
)
async def test_analyzer(
    ofrak_context: OFRAKContext,
    elf_executable_file,
    elf_test_directory,
    readelf_helper,
    analyzer,
    test_view,
    test_entry_view,
    filter_helper,
    entry_sort,
):
    readelf_path = "/usr/bin/readelf"
    assert os.path.exists(readelf_path)
    expected_entries: Iterable[test_entry_view] = readelf_helper(readelf_path, elf_executable_file)
    original_elf = await ofrak_context.create_root_resource_from_file(elf_executable_file)
    await original_elf.unpack()
    views = list(
        await original_elf.get_children_as_view(
            test_view,
            ResourceFilter(tags=(test_view,)),
        )
    )
    assert len(views) > 0
    entries = list()
    for view in views:
        entries.extend(list(await view.get_entries()))
    if filter_helper:
        entries = filter_helper(entries)
        expected_entries = filter_helper(expected_entries)

    assert len(entries) == len(list(expected_entries))
    expected_sorted = sorted(expected_entries, key=lambda x: getattr(x, entry_sort))
    extracted_sorted = sorted(entries, key=lambda x: getattr(x, entry_sort))
    for entry, expected_entry in zip(extracted_sorted, expected_sorted):
        assert entry == expected_entry
