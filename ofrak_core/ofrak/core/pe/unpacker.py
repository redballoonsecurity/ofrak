import pefile as pefile

from ofrak.component.unpacker import Unpacker
from ofrak.core.code_region import CodeRegion
from ofrak.resource import Resource
from ofrak.core.pe.model import (
    Pe,
    PeMsDosHeader,
    PeFileHeader,
    PeOptionalHeader,
    PeDataDirectory,
    PeSectionHeader,
    PeSection,
    PeSectionFlag,
)
from ofrak_type.range import Range


class PeUnpacker(Unpacker[None]):
    id = b"PeUnpacker"
    targets = (Pe,)
    children = (
        PeMsDosHeader,
        PeFileHeader,
        PeOptionalHeader,
        PeDataDirectory,
        PeSectionHeader,
        PeSection,
    )

    async def unpack(self, resource: Resource, config=None):
        """
        Unpack a PE file using the pefile library for the parsing itself, then
        create the appropriate OFRAK child resources for the PE file.
        """
        pe = pefile.PE(data=await resource.get_data())

        # MS-DOS header
        ms_dos_header = self.ms_dos_header_from_pefile(pe.DOS_HEADER)
        await resource.create_child_from_view(
            ms_dos_header,
            data_range=Range.from_size(pe.DOS_HEADER.get_file_offset(), pe.DOS_HEADER.sizeof()),
        )

        # File header
        file_header = self.file_header_from_pefile(pe.FILE_HEADER)
        await resource.create_child_from_view(
            file_header,
            data_range=Range.from_size(pe.FILE_HEADER.get_file_offset(), pe.FILE_HEADER.sizeof()),
        )

        # Optional header
        if pe.OPTIONAL_HEADER is not None:
            optional_header = self.optional_header_from_pefile(pe.OPTIONAL_HEADER)
            await resource.create_child_from_view(
                optional_header,
                data_range=Range.from_size(
                    pe.OPTIONAL_HEADER.get_file_offset(), pe.OPTIONAL_HEADER.sizeof()
                ),
            )

            # Data directories
            for pe_data_directory in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
                data_directory = self.data_directory_from_pefile(pe_data_directory)
                await resource.create_child_from_view(
                    data_directory,
                    data_range=Range.from_size(
                        pe_data_directory.get_file_offset(), pe_data_directory.sizeof()
                    ),
                )

        # Sections
        for index, pe_section in enumerate(pe.sections):
            # Section header
            section_header = self.section_header_from_pefile(pe_section, index)
            await resource.create_child_from_view(
                section_header,
                data_range=Range.from_size(pe_section.get_file_offset(), pe_section.sizeof()),
            )
            # The section itself
            section = PeSection(
                section_index=index,
                name=section_header.name,
                virtual_address=section_header.m_virtual_address,
                size=section_header.m_virtual_size,
            )
            if pe_section.SizeOfRawData > 0:
                section_range = Range.from_size(
                    pe_section.PointerToRawData, pe_section.SizeOfRawData
                )
            else:
                section_range = None

            section_r = await resource.create_child_from_view(
                section,
                data_range=section_range,
            )

            if section_header.has_flag(PeSectionFlag.IMAGE_SCN_CNT_CODE):
                section_r.add_tag(CodeRegion)

    @staticmethod
    def ms_dos_header_from_pefile(dos_header: pefile.Structure) -> PeMsDosHeader:
        return PeMsDosHeader(
            e_magic=dos_header.e_magic,
            e_cblp=dos_header.e_cblp,
            e_cp=dos_header.e_cp,
            e_crlc=dos_header.e_crlc,
            e_cparhdr=dos_header.e_cparhdr,
            e_minalloc=dos_header.e_minalloc,
            e_maxalloc=dos_header.e_maxalloc,
            e_ss=dos_header.e_ss,
            e_sp=dos_header.e_sp,
            e_csum=dos_header.e_csum,
            e_ip=dos_header.e_ip,
            e_cs=dos_header.e_cs,
            e_lfarlc=dos_header.e_lfarlc,
            e_ovno=dos_header.e_ovno,
            e_res=dos_header.e_res,
            e_oemid=dos_header.e_oemid,
            e_oeminfo=dos_header.e_oeminfo,
            e_res2=dos_header.e_res2,
            e_lfanew=dos_header.e_lfanew,
        )

    @staticmethod
    def file_header_from_pefile(file_header: pefile.Structure) -> PeFileHeader:
        return PeFileHeader(
            machine=file_header.Machine,
            number_of_sections=file_header.NumberOfSections,
            time_date_stamp=file_header.TimeDateStamp,
            pointer_to_symbol_table=file_header.PointerToSymbolTable,
            number_of_symbols=file_header.NumberOfSymbols,
            size_of_optional_header=file_header.SizeOfOptionalHeader,
            characteristics=file_header.Characteristics,
        )

    @staticmethod
    def optional_header_from_pefile(optional_header: pefile.Structure) -> PeOptionalHeader:
        return PeOptionalHeader(
            magic=optional_header.Magic,
            major_linker_version=optional_header.MajorLinkerVersion,
            minor_linker_version=optional_header.MinorLinkerVersion,
            size_of_code=optional_header.SizeOfCode,
            size_of_initialized_data=optional_header.SizeOfInitializedData,
            size_of_uninitialized_data=optional_header.SizeOfUninitializedData,
            address_of_entry_point=optional_header.AddressOfEntryPoint,
            base_of_code=optional_header.BaseOfCode,
            base_of_data=optional_header.BaseOfData,
            image_base=optional_header.ImageBase,
            section_alignment=optional_header.SectionAlignment,
            file_alignment=optional_header.FileAlignment,
            major_operating_system_version=optional_header.MajorOperatingSystemVersion,
            minor_operating_system_version=optional_header.MinorOperatingSystemVersion,
            major_image_version=optional_header.MajorImageVersion,
            minor_image_version=optional_header.MinorImageVersion,
            major_subsystem_version=optional_header.MajorSubsystemVersion,
            minor_subsystem_version=optional_header.MinorSubsystemVersion,
            size_of_image=optional_header.SizeOfImage,
            size_of_headers=optional_header.SizeOfHeaders,
            checksum=optional_header.CheckSum,
            subsystem=optional_header.Subsystem,
            dll_characteristics=optional_header.DllCharacteristics,
            size_of_stack_reserve=optional_header.SizeOfStackReserve,
            size_of_stack_commit=optional_header.SizeOfStackCommit,
            size_of_heap_reserve=optional_header.SizeOfHeapReserve,
            size_of_heap_commit=optional_header.SizeOfHeapCommit,
            loader_flags=optional_header.LoaderFlags,
            number_of_rva_and_sizes=optional_header.NumberOfRvaAndSizes,
        )

    @staticmethod
    def data_directory_from_pefile(data_directory: pefile.Structure) -> PeDataDirectory:
        return PeDataDirectory(
            name=data_directory.name,
            virtual_address=data_directory.VirtualAddress,
            size=data_directory.Size,
        )

    @staticmethod
    def section_header_from_pefile(section_header: pefile.Structure, index: int) -> PeSectionHeader:
        return PeSectionHeader(
            m_name=section_header.Name,
            m_virtual_size=section_header.Misc_VirtualSize,
            m_virtual_address=section_header.VirtualAddress,
            m_size_of_raw_data=section_header.SizeOfRawData,
            m_pointer_to_raw_data=section_header.PointerToRawData,
            m_pointer_to_relocations=section_header.PointerToRelocations,
            m_pointer_to_linenumbers=section_header.PointerToLinenumbers,
            m_number_of_relocations=section_header.NumberOfRelocations,
            m_number_of_linenumbers=section_header.NumberOfLinenumbers,
            m_characteristics=section_header.Characteristics,
            section_index=index,
        )
