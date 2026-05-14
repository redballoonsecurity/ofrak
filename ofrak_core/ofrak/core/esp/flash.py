from dataclasses import dataclass
from typing import Tuple, Optional, List, Any
import struct
from abc import abstractmethod, ABC

from ofrak.core.program import Program
from ofrak.model.resource_model import ResourceAttributes
from ofrak.component.identifier import Identifier
from ofrak.component.analyzer import Analyzer
from ofrak.component.unpacker import Unpacker, UnpackerError
from ofrak.component.modifier import Modifier
from ofrak.core.binary import GenericBinary
from ofrak.core.filesystem import File
from ofrak.resource import Resource
from ofrak_type.range import Range
from ofrak.model.component_model import ComponentConfig
from ofrak.core.esp.flash_model import *
from ofrak_io.deserializer import BinaryDeserializer
from ofrak_io.serializer import BinarySerializer
import io
from ofrak_type.endianness import Endianness


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
            data = await resource.get_data(range=Range.from_size(ESP_PARTITION_TABLE_OFFSET, 2))
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

    async def unpack(self, resource: Resource, config=None) -> None:
        """
        Parse an ESP32 flash image, extracting:
        • bootloader section
        • partition-table blob
        • every partition-table entry
        • each partition payload that actually lies inside the image
        """
        data_len = await resource.get_data_length()
        data = await resource.get_data()

        ENTRY_MAGIC_BYTES = ESP_PARTITION_ENTRY_MAGIC  # b"\xAA\x50"
        ENTRY_MAGIC_INT = int.from_bytes(ENTRY_MAGIC_BYTES, "little")

        if data_len < ESP_PARTITION_TABLE_OFFSET + 2:
            raise UnpackerError("Image too small to contain a partition table")

        if data[ESP_BOOTLOADER_OFFSET] != ESP_BOOTLOADER_MAGIC:
            raise UnpackerError("Boot-loader magic not found - not an ESP image")

        if data[ESP_PARTITION_TABLE_OFFSET : ESP_PARTITION_TABLE_OFFSET + 2] != ENTRY_MAGIC_BYTES:
            raise UnpackerError("Partition-table magic not found - not an ESP image")

        boot_sz = ESP_PARTITION_TABLE_OFFSET - ESP_BOOTLOADER_OFFSET
        await resource.create_child_from_view(
            ESPFlashSection(
                section_index=0,
                name="bootloader",
                virtual_address=ESP_BOOTLOADER_OFFSET,
                size=boot_sz,
            ),
            data_range=Range.from_size(ESP_BOOTLOADER_OFFSET, boot_sz),
        )

        pt_blob_size = min(ESP_PARTITION_TABLE_EST_MAX, data_len - ESP_PARTITION_TABLE_OFFSET)

        partition_table_res = await resource.create_child_from_view(
            ESPPartitionTable(
                section_index=1,
                name="partition_table",
                virtual_address=ESP_PARTITION_TABLE_OFFSET,
                size=pt_blob_size,
            ),
            data_range=Range.from_size(ESP_PARTITION_TABLE_OFFSET, pt_blob_size),
        )

        ENTRY_FMT = "HBBII16sI"
        ENTRY_SIZE = struct.calcsize("<" + ENTRY_FMT)

        deserializer = BinaryDeserializer(
            io.BytesIO(
                data[ESP_PARTITION_TABLE_OFFSET : ESP_PARTITION_TABLE_OFFSET + pt_blob_size]
            ),
            endianness=Endianness.LITTLE_ENDIAN,
            word_size=4,
        )

        par_idx = 0
        entry_va = ESP_PARTITION_TABLE_OFFSET

        while True:
            try:
                magic, p_type, p_sub, offset, size, raw_label, flag = deserializer.unpack_multiple(
                    ENTRY_FMT
                )
            except EOFError as e:
                break

            if magic != ENTRY_MAGIC_INT:  # 0xFFFF terminator
                break

            label = raw_label.rstrip(b"\0").decode() or f"partition_{par_idx}"
            await partition_table_res.create_child_from_view(
                ESPPartitionTableEntry(
                    section_index=par_idx,  # index inside the table
                    partition_index=par_idx,
                    name=label,
                    virtual_address=entry_va,
                    size=ENTRY_SIZE,
                    type=ESPPartitionType.from_value(p_type),
                    subtype=ESPPartitionSubtype.from_value(p_sub),
                    flag=ESPPartitionFlag.from_value(flag),
                ),
                data_range=Range.from_size(entry_va, ENTRY_SIZE),
            )

            if offset < data_len:
                payload_sz = min(size, data_len - offset)
                if payload_sz:
                    await resource.create_child_from_view(
                        ESPPartition(
                            section_index=2 + par_idx,  # after bootloader & table
                            partition_index=par_idx,
                            name=str(label),
                            virtual_address=offset,
                            size=payload_sz,
                        ),
                        data_range=Range.from_size(offset, payload_sz),
                    )

            par_idx += 1
            entry_va += ENTRY_SIZE


####################
#    ANALYZER      #
####################
@dataclass(**ResourceAttributes.DATACLASS_PARAMS)
class ESPFlashAttributes(ResourceAttributes):
    total_partitions: int
    total_flash_size: int
    has_overlapping_partitions: bool
    unused_space: int


class ESPFlashAnalyzer(Analyzer[None, ESPFlashAttributes]):
    """
    Analyze ESP flash image for validity and attributes.
    """

    targets = (ESPFlash,)
    outputs = (ESPFlashAttributes,)

    async def analyze(self, resource: Resource, config=None) -> ESPFlashAttributes:
        flash = await resource.view_as(ESPFlash)
        partition_table = await flash.get_partition_table()
        entries = await partition_table.get_entries()

        total_partitions = len(list(entries))
        total_flash_size = await resource.get_data_length()

        # Check for overlapping partitions
        has_overlapping = False
        partition_ranges: List[Tuple[int, int]] = []
        max_end = 0

        for entry in entries:
            partition = await entry.get_body()
            start = partition.virtual_address
            end = start + partition.size

            # Check overlap with existing partitions
            for p_start, p_end in partition_ranges:
                if start < p_end and end > p_start:
                    has_overlapping = True
                    break

            partition_ranges.append((start, end))
            if end > max_end:
                max_end = end

        # Calculate unused space (gap between last partition and end of flash)
        unused_space = total_flash_size - max_end if max_end < total_flash_size else 0

        return ESPFlashAttributes(
            total_partitions=total_partitions,
            total_flash_size=total_flash_size,
            has_overlapping_partitions=has_overlapping,
            unused_space=unused_space,
        )


####################
#    MODIFIERS     #
####################
class AbstractESPFlashAttributeModifier(ABC):
    @classmethod
    @abstractmethod
    def populate_serializer(cls, serializer: BinarySerializer, attributes: Any):
        raise NotImplementedError()

    async def serialize(self, resource: Resource, updated_attributes: ResourceAttributes) -> bytes:
        buf = io.BytesIO()
        serializer = BinarySerializer(
            buf,
            endianness=Endianness.LITTLE_ENDIAN,
        )
        self.populate_serializer(serializer, updated_attributes)
        return buf.getvalue()

    async def serialize_and_patch(
        self,
        resource: Resource,
        original_attributes: Any,
        modifier_config: ComponentConfig,
    ):
        new_attributes = ResourceAttributes.replace_updated(original_attributes, modifier_config)
        new_data = await self.serialize(resource, new_attributes)
        patch_length = await resource.get_data_length()
        resource.queue_patch(Range.from_size(0, patch_length), new_data)
        resource.add_attributes(new_attributes)


@dataclass
class ESPPartitionTableEntryModifierConfig(ComponentConfig):
    type: Optional[ESPPartitionType] = None
    subtype: Optional[ESPPartitionSubtype] = None
    virtual_address: Optional[int] = None
    size: Optional[int] = None
    name: Optional[str] = None
    flag: Optional[ESPPartitionFlag] = None


class ESPPartitionTableEntryModifier(Modifier[ESPPartitionTableEntryModifierConfig]):
    """
    Modifier for ESP partition table entries.
    """

    id = b"ESPPartitionTableEntryModifier"
    targets = (ESPPartitionTableEntry,)

    @classmethod
    def populate_serializer(cls, serializer: BinarySerializer, attributes: ESPPartitionTableEntry):
        # Pack magic, type, subtype, offset, and size
        magic_value = int.from_bytes(ESP_PARTITION_ENTRY_MAGIC, "little")
        type_value = attributes.type.value if isinstance(attributes.type.value, int) else 0xFF
        subtype_value = (
            attributes.subtype.value if isinstance(attributes.subtype.value, int) else 0xFF
        )

        serializer.pack_multiple(
            "HBBII",
            magic_value,
            type_value,
            subtype_value,
            attributes.virtual_address,
            attributes.size,
        )

        # Pack label (16 bytes to match unpacker format)
        label_bytes = attributes.name.encode("ascii")[:16]
        serializer.write(label_bytes.ljust(16, b"\x00"))

        # Pack flags
        flag_value = attributes.flag.value if isinstance(attributes.flag.value, int) else 0
        serializer.pack_uint(flag_value)

    async def modify(self, resource: Resource, config: ESPPartitionTableEntryModifierConfig):
        original_entry = await resource.view_as(ESPPartitionTableEntry)
        original_entry.type = config.type if config.type is not None else original_entry.type
        original_entry.subtype = (
            config.subtype if config.subtype is not None else original_entry.subtype
        )
        original_entry.virtual_address = (
            config.virtual_address
            if config.virtual_address is not None
            else original_entry.virtual_address
        )
        original_entry.size = config.size if config.size is not None else original_entry.size
        original_entry.name = config.name if config.name is not None else original_entry.name
        original_entry.flag = config.flag if config.flag is not None else original_entry.flag
        new_data = await self.serialize(resource, original_entry)
        patch_length = await resource.get_data_length()
        resource.queue_patch(Range.from_size(0, patch_length), new_data)
        inst = original_entry.get_attributes_instances()  # type: ignore
        [resource.add_attributes(i) for i in inst.values()]

    async def serialize(
        self, resource: Resource, updated_attributes: ESPPartitionTableEntry
    ) -> bytes:
        buf = io.BytesIO()
        serializer = BinarySerializer(
            buf,
            endianness=Endianness.LITTLE_ENDIAN,
        )
        self.populate_serializer(serializer, updated_attributes)
        return buf.getvalue()
