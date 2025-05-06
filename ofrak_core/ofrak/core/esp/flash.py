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
from ofrak.component.modifier import Modifier
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
from ofrak.core.esp.flash_model import *
from ofrak_io.deserializer import BinaryDeserializer
from ofrak_io.serializer import BinarySerializer
import io
from ofrak_type.endianness import Endianness
from ofrak_type.bit_width import BitWidth

#TODO: use asserts in places other then identifier when checking thats its an ESP thing

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

    :param id: Identifier for the unpacker
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
            data_reader = io.BytesIO(data[ESP_PARTITION_TABLE_OFFSET:ESP_PARTITION_TABLE_EST_MAX - 1])
            deserializer = BinaryDeserializer(data_reader)
            virtual_addr = ESP_PARTITION_TABLE_OFFSET

            while (data_reader):
                _, type, subtype, offset, size, label, flags = deserializer.unpack_multiple("<HBBII12sB")
                virtual_addr += 25
                label = label.decode("ascii").rstrip("\x00")
                partition_entry = ESPPartitionTableEntry(
                    section_index=sec_index,
                    partition_index=par_index,
                    name=label,
                    virtual_address=virtual_addr,
                    size=virtual_addr + 25,
                    type=ESPPartitionType.from_value(type),
                    subtype=ESPPartitionSubtype.from_value(subtype),
                    flag=ESPPartitionSubtype.from_value(flags),
                )
                await resource.create_child_from_view(
                    partition_entry, data_range=Range(virtual_addr, virtual_addr + 25)
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

####################
#    ANALYZERS     #
####################


####################
#     MODIFERS     #
####################
# @dataclass
# class ESPPartitionTableEntryModifierConfig(ComponentConfig):
#     type: Optional[ESPPartitionType] = None
#     subtype: Optional[ESPPartitionSubtype] = None
#     flag: Optional[ESPPartitionFlag] = None


# class ESPPartitionTableEntryModifier(Modifier[ESPPartitionTableEntryModifierConfig]):
#     id = b"ESPPartitionTableEntryModifier"
#     targets = (ESPPartitionTableEntry,)

#     async def modify(self, resource: Resource, config: ESPPartitionTableEntryModifierConfig):
#         original_attributes = await resource.get_only_child_as_view(
#             ESPPartitionTableEntry,
#             ResourceFilter(
#                 tags=(ESPPartitionTableEntry,)
#             ))
#         esp_resource = await resource.get_only_ancestor_as_view(
#             ESPFlash,
#             ResourceFilter.with_tags(ESPFlash)
#             )
#         new_attributes = ResourceAttributes.replace_updated(original_attributes, config)
#         buf = io.BytesIO()
#         serializer = BinarySerializer(
#             buf,
#             endianness=Endianness.LITTLE_ENDIAN,
#             word_size=BitWidth.BIT_32,
#         )
#         serializer.pack_multiple()
#         patch_length = await resource.get_data_length()
#         resource.queue_patch(Range.from_size(0, patch_length), new_data)

        