import logging
from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from ofrak.core.program import Program
from ofrak.core.program_section import NamedProgramSection
from ofrak.model.resource_model import index
from ofrak.resource_view import ResourceView
from ofrak.service.resource_service_i import (
    ResourceAttributeValueFilter,
    ResourceFilter,
)
from ofrak.service.resource_service_i import ResourceFilter

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
        # Get the flash resource (parent of parent - grandparent)
        flash_resource = await (await self.resource.get_parent()).get_parent()
        
        return await flash_resource.get_only_child_as_view(
            ESPPartition,
            ResourceFilter(
                tags=(ESPPartition,),
                attribute_filters=[
                    ResourceAttributeValueFilter(
                        ESPPartitionStructure.SectionIndex, self.partition_index
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
                        ESPPartitionStructure.SectionIndex, self.partition_index
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
                attribute_filters=(ResourceAttributeValueFilter(ESPPartition.SectionName, name),),
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
                attribute_filters=(ResourceAttributeValueFilter(ESPFlashSection.SectionName, name),),
            ),
        )
    
    async def get_partition_table(self) -> ESPPartitionTable:
        return await self.resource.get_only_child_as_view(
            ESPPartitionTable,
            ResourceFilter(
                tags=(ESPPartitionTable,),
            ),
        )
