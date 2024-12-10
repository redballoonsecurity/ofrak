import logging
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Tuple, Optional, List
import struct

from ofrak.core.program import Program, CodeRegion
from ofrak.core.program_section import NamedProgramSection
from ofrak.model.resource_model import index, ResourceAttributes
from ofrak.component.identifier import Identifier
from ofrak.component.analyzer import Analyzer
from ofrak.component.unpacker import Unpacker, UnpackerError
from ofrak.core.binary import GenericBinary
from ofrak.core.filesystem import File
from ofrak.resource import Resource
from ofrak.resource_view import ResourceView
from ofrak.service.resource_service_i import (
    ResourceAttributeValueFilter,
    ResourceFilter,
)
from ofrak.service.resource_service_i import ResourceFilter
from ofrak_type.range import Range
from ofrak.model.component_model import ComponentConfig

"""
# ESP-IDF Flash Dump, Partition-table based, Documentation
    +-------+--------------------------------------------+
    | Byte  | Description                                  |
    +=======+==============================================+
    |  0-1  | Magic number (0x50aa)                        |
    +-------+----------------------------------------------+
    |   2   | Type (0 = APP, 1 = DATA, >1 = {invalid})     |
    +-------+----------------------------------------------+
    |   3   | Subtype                                      |
    |       | 0x00 = Factory/OTA DATA                      |
    |       | 0x01 = PHY/RF                                |
    |       | 0x02 = NVS                                   |
    |       | 0x03 = Coredump                              |
    |       | 0x04 = NVS Keys                              |
    |       | 0x05 = eFuse                                 |
    |       | 0x10 = OTA 0                                 |
    |       | 0x11 = OTA 1                                 |
    |       | 0x12 = OTA 2                                 |
    |       | 0x13 = OTA 3                                 |
    |       | 0x14 = OTA 4                                 |
    |       | 0x15 = OTA 5                                 |
    |       | 0x16 = OTA 6                                 |
    |       | 0x17 = OTA 7                                 |
    |       | 0x18 = OTA 8                                 |
    |       | 0x19 = OTA 9                                 |
    |       | 0x1a = OTA 10                                |
    |       | 0x1b = OTA 11                                |
    |       | 0x1c = OTA 12                                |
    |       | 0x1d = OTA 13                                |
    |       | 0x1e = OTA 14                                |
    |       | 0x1f = OTA 15                                |
    |       | 0x20 = TEST/OTA 16                           |
    |       | 0x80 = ESPHTTP                               |
    |       | 0x81 = FAT                                   |
    |       | 0x82 = SPIFFS                                |
    |       | >0x82 = {invalid}                            |
    +-------+----------------------------------------------+
    |  4-7  | Offset                                       |
    +-------+----------------------------------------------+
    | 8-11  | Size                                         |
    +-------+----------------------------------------------+
    | 12-23 | Label (string, "%s")                         |
    +-------+----------------------------------------------+
    |  24   | Flags                                        |
    |       | 0 = not encrypted                            |
    |       | 1 = encrypted                                |
    |       | >1 = {invalid}                               |
    +-------+----------------------------------------------+
"""

LOGGER = logging.getLogger(__name__)

ESP_PARTITION_ENTRY_MAGIC = 0x50AA.to_bytes(2, "little")
ESP_PARTITION_TABLE_OFFSET = 0x8000
ESP_PARTITION_TABLE_EST_MAX = 0x9000
ESP_PARTITION_ENTRY_SIZE = 25
ESP_BOOTLOADER_OFFSET = 0x1000
ESP_BOOTLOADER_MAGIC = 0xE9


#####################
#       Enums       #
#####################
class ESPPartitionType(Enum):
    APP = 0
    DATA = 1
    INVALID = "Invalid"

    @staticmethod
    def from_value(value):
        if value == 0:
            return ESPPartitionType.APP
        elif value == 1:
            return ESPPartitionType.DATA
        else:
            return ESPPartitionType.INVALID


class ESPPartitionSubtype(Enum):
    FACTORY_OTA_DATA = 0x00
    PHY_RF = 0x01
    NVS = 0x02
    COREDUMP = 0x03
    NVS_KEYS = 0x04
    EFUSE = 0x05
    OTA_0 = 0x10
    OTA_1 = 0x11
    OTA_2 = 0x12
    OTA_3 = 0x13
    OTA_4 = 0x14
    OTA_5 = 0x15
    OTA_6 = 0x16
    OTA_7 = 0x17
    OTA_8 = 0x18
    OTA_9 = 0x19
    OTA_10 = 0x1A
    OTA_11 = 0x1B
    OTA_12 = 0x1C
    OTA_13 = 0x1D
    OTA_14 = 0x1E
    OTA_15 = 0x1F
    TEST_OTA_16 = 0x20
    ESPHTTP = 0x80
    FAT = 0x81
    SPIFFS = 0x82
    INVALID = "Invalid"

    @staticmethod
    def from_value(value):
        for subtype in ESPPartitionSubtype:
            if subtype.value == value:
                return subtype
        return ESPPartitionSubtype.INVALID


class ESPPartitionFlag(Enum):
    NOT_ENCRYPTED = 0
    ENCRYPTED = 1
    INVALID = "Invalid"

    @staticmethod
    def from_value(value):
        if value == 0:
            return ESPPartitionFlag.NOT_ENCRYPTED
        elif value == 1:
            return ESPPartitionFlag.ENCRYPTED
        else:
            return ESPPartitionFlag.INVALID


#####################
#     RESOURCES     #
#####################
@dataclass
class ESPFlashSectionStructure(ResourceView):
    """
    Base class for section headers and sections, links them via index.
    :param section_index: Index of the section
    """
    section_index: int

    @index
    def SectionIndex(self) -> int:
        """
        Returns the index of the section.

        :return: Index of the section
        """
        return self.section_index

@dataclass
class ESPFlashSection(ESPFlashSectionStructure, NamedProgramSection):
    """
    ESP Flash Section.

    :param offset: offset of the partition/section.
    :param size: size of the partition/section.
    """

@dataclass
class ESPPartitionStructure(ResourceView):
    """
    Base class for partition entries and sections, links them via index.
    :param partition_index: Index of the partition.
    """
    partition_index: int

    @index
    def SectionIndex(self) -> int:
        """
        Returns the index of the section.

        :return: Index of the section.
        """
        return self.partition_index

@dataclass
class ESPPartitionTableEntry(ESPPartitionStructure, ESPFlashSection):
    """
    ESP Partition Table entry.

    :param type: type of the partition/section.
    :param subtype: subtype of the partition/section.
    :param flag: flag of the partition/section.
    """
    type: ESPPartitionType
    subtype: ESPPartitionSubtype
    flag: ESPPartitionFlag

    async def get_body(self) -> "ESPPartition":
        """
        Retrives the body of the partition/section.

        :return: The body of the partition/section.
        """
        return await self.resource.get_only_sibling_as_view(
            ESPPartition,
            ResourceFilter(
                tags=(ESPPartition,),
                attribute_filters=[
                    ResourceAttributeValueFilter(
                        ESPPartitionStructure.partition_index, self.partition_index
                    )
                ],
            ),
        )

@dataclass
class ESPPartition(ESPPartitionStructure, ESPFlashSection):
    """
    ESP Flash partition.

    Represents a section within the ESP Flash.
    """

    async def get_header(self) -> "ESPPartitionTableEntry":
        """
        Retrives the entry in the partition table for this section.

        :return: The header of the section
        """
        return await self.resource.get_only_sibling_as_view(
            ESPPartitionTableEntry,
            ResourceFilter(
                tags=(ESPPartitionTableEntry,),
                attribute_filters=[
                    ResourceAttributeValueFilter(
                        ESPPartitionStructure.partition_index, self.partition_index
                    )
                ],
            ),
        )

@dataclass
class ESPPartitionTable(ESPFlashSection):
    """
    ESP Paritition Table.
    """
    
    async def get_entries(self) -> Iterable[ESPPartitionTableEntry]:
        await self.resource.unpack()
        
        return await self.resource.get_children_as_view(
            ESPPartitionTableEntry,
            ResourceFilter(tags=(ESPPartitionTableEntry,)),
        )
    
    async def get_section_by_name(self, name: str) -> ESPPartition:
        """
        Get a specific `ESPPartition` by its name.

        :param name: The name of the section to retrieve
        :raises NotFoundError: If no section with the given name is found
        :return: The `ESPSection` instance with the specified name
        """
        await self.get_entries()

        return await self.resource.get_only_child_as_view(
            ESPPartition,
            ResourceFilter(
                tags=(ESPPartition,),
                attribute_filters=(ResourceAttributeValueFilter(ESPPartition.name, name),),
            ),
        )

@dataclass
class ESPFlash(Program):
    """
    Binary file for ESP flash dump.
    """

    async def get_sections(self) -> Iterable[ESPFlashSection]:
        """
        Return the children `ESPFlashSection` resources.

        :return: An iterable of `ESPFlashSection` instances.
        """
        return await self.resource.get_children_as_view(
            ESPFlashSection,
            ResourceFilter(
                tags=(ESPFlashSection,),
            )
        )
    
    async def get_section_by_name(self, name: str) -> ESPFlashSection:
        """
        Get a specific `ESPSection` by its name.

        :param name: The name of the section to retrieve
        :raises NotFoundError: If no section with the given name is found
        :return: The `ESPSection` instance with the specified name
        """
        await self.get_sections()

        return await self.resource.get_only_child_as_view(
            ESPFlashSection,
            ResourceFilter(
                tags=(ESPFlashSection,),
                attribute_filters=(ResourceAttributeValueFilter(ESPFlashSection.name, name),),
            ),
        )
    
    async def get_partition_table(self) -> ESPPartitionTable:
        return await self.resource.get_only_child_as_view(
            ESPPartitionTable,
            ResourceFilter(
                tags=(ESPPartitionTable,),
            ),
        )
    


####################
#    IDENTIFIER    #
####################
class ESPFlashIdentifier(Identifier):
    """
    Identify ESP Partition Table.

    :param targets: A tuple containing the target resources types for identification
    """

    targets = (File, GenericBinary, Program)

    async def identify(self, resource: Resource, config=None) -> None:
        """
        Identitifies if the given resource is an ESP Partition Table.

        :param resource: The resource to identify
        :param config: Optional configuration for identification
        """
        end = await resource.get_data_length()
        if end >= 0x80FF:  # Partition table is at 0x8000 so it needs to be larger
            data = await resource.get_data(
                range=Range.from_size(ESP_PARTITION_TABLE_OFFSET, 2)
            )
            if ESP_PARTITION_ENTRY_MAGIC == data:
                data = await resource.get_data(range=Range.from_size(ESP_BOOTLOADER_OFFSET, 1))
                if data == ESP_BOOTLOADER_MAGIC.to_bytes(1, "little"):
                    resource.add_tag(ESPFlash)


####################
#    UNPACKER      #
####################
class ESPFlashUnpacker(Unpacker[None]):
    """
    Unpacker for ESP partition table.

    :param id: Identifie4r for the unpacker
    :param targets: A typle containing the target resources types for unpacking
    :param children: A tuple containing the children resource types expected
        after unpacking
    """

    id = b"ESPFlashUnpacker"
    targets = (ESPFlash,)
    children = (
        ESPFlashSection,
        ESPPartitionTable,
        ESPPartitionStructure,
        ESPPartitionTableEntry,
        ESPFlashSectionStructure,
        ESPPartition,
        )

    async def unpack(self, resource: Resource, config=None):
        """
        Asynchronously unpacks an ESP Partition Table, extracting its components and metadata.

        :param resource: The resource to unpack
        :param config: Optoional configuration for unpacking
        :raises UnpackingError: If unpacking fails due to invalid data or file operations.
        """
        end = await resource.get_data_length()
        data = await resource.get_data()
        if (
            end >= 0x80FF
            and ESP_PARTITION_ENTRY_MAGIC
            == data[ESP_PARTITION_TABLE_OFFSET : ESP_PARTITION_TABLE_OFFSET + 2]
            and data[ESP_BOOTLOADER_OFFSET] == ESP_BOOTLOADER_MAGIC
        ):
            end = ESP_PARTITION_TABLE_EST_MAX if end > ESP_PARTITION_TABLE_EST_MAX else end
            # Get bootloader
            size = ESP_PARTITION_TABLE_OFFSET-ESP_BOOTLOADER_OFFSET
            bootloader = ESPFlashSection(
                section_index=0,
                name="bootloader",
                virtual_address=ESP_BOOTLOADER_OFFSET,
                size=size
            )
            await resource.create_child_from_view(
                bootloader, data_range=Range.from_size(ESP_BOOTLOADER_OFFSET, size)
            )
            # Get partition table
            partition_table = ESPPartitionTable(
                section_index=1,
                name="partition_table",
                virtual_address=ESP_PARTITION_TABLE_OFFSET,
                size=ESP_PARTITION_TABLE_EST_MAX
            )
            await resource.create_child_from_view(
                partition_table, data_range=Range.from_size(ESP_PARTITION_TABLE_OFFSET, ESP_PARTITION_TABLE_EST_MAX)
            )
            # Get partition table entries
            sec_index = 2
            par_index = 0
            last_partition_ends = 0x9000
            for i in range(ESP_PARTITION_TABLE_OFFSET, ESP_PARTITION_TABLE_EST_MAX - 1):
                if data[i : i + 2] == ESP_PARTITION_ENTRY_MAGIC:
                    entry = data[i:i+25]
                    _, type, subtype, offset, size, label, flags = struct.unpack(
                        "<HBBII12sB", entry
                    )
                    label = label.decode("ascii").rstrip("\x00")
                    partition_entry = ESPPartitionTableEntry(
                        section_index=sec_index,
                        partition_index=par_index,
                        name=label,
                        virtual_address=i,
                        size=i + 25,
                        type=ESPPartitionType.from_value(type),
                        subtype=ESPPartitionSubtype.from_value(subtype),
                        flag=ESPPartitionSubtype.from_value(flags),
                    )
                    await resource.create_child_from_view(
                        partition_entry, data_range=Range(i, i + 25)
                    )
                    partition = ESPPartition(
                        section_index=sec_index,
                        partition_index=par_index,
                        name=label,
                        virtual_address=offset,
                        size=size
                    )
                    await resource.create_child_from_view(
                        partition, data_range=Range.from_size(offset, size)
                    )
                    sec_index += 1
                    par_index += 1
                    partition_ends = offset + size
                    if partition_ends > last_partition_ends:
                        last_partition_ends = partition_ends

        else:
            raise UnpackerError(
                "This is not a valid ESP Flash" "(could not find magic number)"
            )

