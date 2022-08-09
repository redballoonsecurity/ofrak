import asyncio
from typing import Optional, Dict, Type, Tuple

from ofrak.model.tag_model import ResourceTag

from ofrak.component.unpacker import Unpacker
from ofrak.core.code_region import CodeRegion
from ofrak.model.resource_model import ResourceAttributes
from ofrak.resource import Resource
from ofrak.service.resource_service_i import ResourceFilter
from ofrak.core.elf.model import (
    ElfHeader,
    ElfProgramHeader,
    ElfProgramHeaderType,
    ElfSegment,
    ElfSectionHeader,
    ElfSection,
    ElfStringSection,
    ElfSectionType,
    ElfSymbolSection,
    ElfSymbol,
    ElfBasicHeader,
    ElfSectionFlag,
    ElfSectionNameStringSection,
    Elf,
    ElfSegmentStructure,
    ElfSectionStructure,
    ElfRelaSection,
    ElfRelaEntry,
    ElfDynSymbolSection,
    ElfDynamicSection,
    ElfDynamicEntry,
    ElfFiniArraySection,
    ElfInitArraySection,
    ElfPointerArraySection,
    ElfSymbolStructure,
    ElfVirtualAddress,
)
from ofrak_type.bit_width import BitWidth
from ofrak_type.range import Range


class ElfUnpacker(Unpacker[None]):
    id = b"ElfUnpacker"
    targets = (Elf,)
    children = (
        ElfBasicHeader,
        ElfHeader,
        ElfProgramHeader,
        ElfSegment,
        ElfSectionHeader,
        ElfSection,
        ElfStringSection,
        ElfSymbolSection,
        CodeRegion,
    )

    async def unpack(self, resource: Resource, config=None):
        """
        Unpack ELF headers and sections / segments into the OFRAK resource tree.

        After unpacking the ElfHeader, the unpacker first unpacks ElfSections defined in the ElfSectionHeader into the
        resource tree.

        If no executable sections are found, then the proceeding ElfProgramHeader unpacking routine is permitted to
        unpack LOAD-able ElfSegments into the resource tree. Executable LOAD-able ElfSegments are unpacked into
        CodeRegions.

        legend:  +    composable child
                 ^    exclusive child
                [ ]   optional / conditional child
                (s)   one or more instances of child

        RESOURCE
         + ElfBasicHeader
         + ElfHeader
           [+] ElfProgramHeader              (creates LOAD-able ElfSegments if ElfSectionHeaders yields no CodeRegions)
           [+] ElfSectionHeader
        [+] ElfSection(s)
           [^] ElfFiniArraySection           (if FINI_ARRAY)
           [^] ElfInitArraySection           (if INIT_ARRAY)
           [^] ElfDynamicSection             (if DYNAMIC)
           [^] ElfRelaSection                (if RELA)
           [^] ElfDynSymbolSection           (if DYNSYM)
           [^] ElfSymbolSection              (if SYMTAB)
           [^] ElfStringSection              (if STRTAB)
           [+] CodeRegion                    (if executable)
           [+] ElfSectionNameStringSection   (if name string section)
        [+] ElfSegment(s)                    (if ElfSection yields no CodeRegions,
           [+] CodeRegion (if executable)     LOAD-able ElfSegments will populate the body of the resource tree instead)
        """

        # Unfortunately, ELF files do allow sections to overlap each other.
        await resource.set_data_overlaps_enabled(True)

        e_basic_header_r = await resource.create_child(
            tags=(ElfBasicHeader,), data_range=Range(0, 16)
        )
        e_basic_header = await e_basic_header_r.view_as(ElfBasicHeader)

        e_header_range = Range.from_size(
            16, 36 if e_basic_header.get_bitwidth() is BitWidth.BIT_32 else 48
        )
        e_header_r = await resource.create_child(tags=(ElfHeader,), data_range=e_header_range)
        e_header = await e_header_r.view_as(ElfHeader)

        ###########################################################################################
        ### Unpack section headers and associated sections

        sections_by_range_start: Dict[int, Resource] = dict()
        code_region_present = None

        # Create the section header/body resources
        for index in range(e_header.e_shnum):
            e_section_header_offset = e_header.e_shoff + index * e_header.e_shentsize
            e_section_header_range = Range.from_size(e_section_header_offset, e_header.e_shentsize)
            e_section_header_r = await resource.create_child(
                tags=(ElfSectionHeader,),
                data_range=e_section_header_range,
                attributes=(ElfSectionStructure.attributes_type(index),),  # type: ignore
            )
            e_section_header = await e_section_header_r.view_as(ElfSectionHeader)

            e_section_offset = e_section_header.sh_offset
            e_section_range = Range.from_size(e_section_offset, e_section_header.sh_size)
            opt_e_section_range: Optional[Range] = e_section_range
            if e_section_range.length() == 0:
                # It's possible that the section does not contain any data
                opt_e_section_range = None
            if e_section_header.get_type() is ElfSectionType.NOBITS:
                # NOBITS sections never have data in the file; their sh_size refers to in-mem size
                opt_e_section_range = None
            data_after = sections_by_range_start.get(e_section_offset)
            e_section_r = await resource.create_child(
                tags=(ElfSection,),
                data_range=opt_e_section_range,
                data_after=data_after,
                attributes=(ElfSectionStructure.attributes_type(index),),  # type: ignore
            )
            sections_by_range_start[e_section_offset] = e_section_r
            if e_section_header.get_type() is ElfSectionType.FINI_ARRAY:
                e_section_r.add_tag(ElfFiniArraySection)
            elif e_section_header.get_type() is ElfSectionType.INIT_ARRAY:
                e_section_r.add_tag(ElfInitArraySection)
            elif e_section_header.get_type() is ElfSectionType.DYNAMIC:
                e_section_r.add_tag(ElfDynamicSection)
            elif e_section_header.get_type() is ElfSectionType.RELA:
                e_section_r.add_tag(ElfRelaSection)
            elif e_section_header.get_type() is ElfSectionType.DYNSYM:
                e_section_r.add_tag(ElfDynSymbolSection)
            elif e_section_header.get_type() is ElfSectionType.SYMTAB:
                e_section_r.add_tag(ElfSymbolSection)
            elif e_section_header.get_type() is ElfSectionType.STRTAB:
                e_section_r.add_tag(ElfStringSection)

            if e_section_header.has_flag(ElfSectionFlag.EXECINSTR):
                e_section_r.add_tag(CodeRegion)
                code_region_present = True

            if index == e_header.e_shstrndx:
                e_section_r.add_tag(ElfSectionNameStringSection)

        ###########################################################################################
        ### Unpack segment headers, conditionally unpack associated loadable segments

        preceding_resource: Optional[Resource] = e_header_r

        # Create the program header resources
        for index in range(e_header.e_phnum):
            e_program_header_offset = e_header.e_phoff + (index * e_header.e_phentsize)
            e_program_header_range = Range.from_size(e_program_header_offset, e_header.e_phentsize)

            e_program_header_r = await resource.create_child(
                tags=(ElfProgramHeader,),
                data_range=e_program_header_range,
                attributes=(ElfSegmentStructure.attributes_type(index),),  # type: ignore
            )

            e_program_header = await e_program_header_r.view_as(ElfProgramHeader)

            # Don't unpack loadable segments if the section unpacker had already unpacked any CodeRegions
            if code_region_present:
                continue

            if e_program_header.p_type == ElfProgramHeaderType.LOAD.value:
                e_segment_offset = e_program_header.p_offset
                e_segment_range = Range.from_size(e_segment_offset, e_program_header.p_filesz)
                opt_e_segment_range: Optional[Range] = e_segment_range

                # Loaded segments can have no data to initialize with (heap, bss, etc.)
                if e_segment_range.length() == 0:
                    opt_e_segment_range = None

                # We need to inform OFRAK data service the order of child nodes to be populated into the resource tree,
                # since there may be overlapping regions due to flattening non-flat memory structures derived from the
                # binary-under-analysis. We should deprecate `data_after` and `data_before` in favor of a structure
                # that can hold multiple memory views (virtual, physical, file, etc.) of an analyzed binary.
                e_segment_r = await resource.create_child(
                    tags=(ElfSegment,),
                    data_range=opt_e_segment_range,
                    data_before=preceding_resource,
                    attributes=(ElfSegmentStructure.attributes_type(index),),  # type: ignore
                )

                # Tag the segment as a CodeRegion if the loaded segment is executable
                if e_program_header.is_executable():
                    e_segment_r.add_tag(CodeRegion)
                await e_segment_r.save()

                preceding_resource = None


class ElfDynamicSectionUnpacker(Unpacker[None]):
    id = b"ElfDynamicSectionUnpacker"
    targets = (ElfDynamicSection,)
    children = (ElfDynamicEntry,)

    async def unpack(self, resource: Resource, config=None):
        e_section = await resource.view_as(ElfDynamicSection)
        elf_r = await e_section.get_parent()
        e_basic_header = await elf_r.get_basic_header()
        dyn_entry_size = 16 if e_basic_header.get_bitwidth() is BitWidth.BIT_64 else 8
        await make_children_helper(resource, ElfDynamicEntry, dyn_entry_size, None)


class ElfRelaUnpacker(Unpacker[None]):
    id = b"ElfRelaUnpacker"
    targets = (ElfRelaSection,)
    children = (ElfRelaEntry,)

    async def unpack(self, resource: Resource, config=None):
        e_section = await resource.view_as(ElfRelaSection)
        elf_r = await e_section.get_parent()
        e_basic_header = await elf_r.get_basic_header()
        rela_size = 24 if e_basic_header.get_bitwidth() is BitWidth.BIT_64 else 12
        await make_children_helper(resource, ElfRelaEntry, rela_size, None)


class ElfSymbolUnpacker(Unpacker[None]):
    id = b"ElfSymbolUnpacker"
    targets = (ElfSymbolSection,)
    children = (ElfSymbol,)

    async def unpack(self, resource: Resource, config=None):
        e_section = await resource.view_as(ElfSymbolSection)
        elf_r = await e_section.get_parent()
        e_basic_header = await elf_r.get_basic_header()
        symbol_size = 16 if e_basic_header.get_bitwidth() is BitWidth.BIT_32 else 24
        await make_children_helper(
            resource, ElfSymbol, symbol_size, ElfSymbolStructure.attributes_type
        )


class ElfPointerArraySectionUnpacker(Unpacker[None]):
    id = b"ElfPointerArraySectionUnpacker"
    targets = (ElfPointerArraySection,)
    children = (ElfVirtualAddress,)

    async def unpack(self, resource: Resource, config=None):
        elf_r = await resource.get_only_ancestor_as_view(Elf, ResourceFilter.with_tags(Elf))
        e_basic_header = await elf_r.get_basic_header()
        addr_size = 4 if e_basic_header.get_bitwidth() is BitWidth.BIT_32 else 8
        await make_children_helper(resource, ElfVirtualAddress, addr_size, None)


async def make_children_helper(
    resource: Resource,
    entry_type: ResourceTag,
    entry_size: int,
    structure_index_type: Optional[Type[ResourceAttributes]],
) -> None:
    elf_section_size = await resource.get_data_length()
    create_child_tasks = []
    for i, offset in enumerate(range(0, elf_section_size, entry_size)):
        if structure_index_type is not None:
            attrs: Tuple[ResourceAttributes, ...] = (structure_index_type(i),)  # type: ignore
        else:
            attrs = ()
        create_child_tasks.append(
            resource.create_child(
                tags=(entry_type,),
                data_range=Range.from_size(offset, entry_size),
                attributes=attrs,
            )
        )
    await asyncio.gather(*create_child_tasks)
