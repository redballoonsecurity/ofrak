import struct
from dataclasses import dataclass
from typing import List, Optional, Tuple

from ofrak.component.analyzer import Analyzer
from ofrak.component.identifier import Identifier
from ofrak.component.modifier import Modifier
from ofrak.component.unpacker import Unpacker, UnpackerError
from ofrak.core.binary import GenericBinary
from ofrak.core.program import Program
from ofrak.model.component_model import ComponentConfig
from ofrak.resource import Resource
from ofrak_type.error import NotFoundError
from ofrak_type.range import Range

from ofrak.core.esp.flash_model import (
    ESPFlash,
    ESPFlashAttributes,
    ESPFlashSection,
    ESPFlashSectionStructure,
    ESPPartition,
    ESPPartitionFlag,
    ESPPartitionStructure,
    ESPPartitionSubtype,
    ESPPartitionTable,
    ESPPartitionTableEntry,
    ESPPartitionType,
    ESP_BOOTLOADER_MAGIC,
    ESP_BOOTLOADER_OFFSET,
    ESP_PARTITION_ENTRY_MAGIC,
    ESP_PARTITION_ENTRY_SIZE,
    ESP_PARTITION_TABLE_OFFSET,
    ESP_PARTITION_TABLE_SIZE,
)

# Partition-table entry layout: magic (H), type (B), subtype (B), offset (I), size (I),
# 16-byte label (16s), flags (I) -- 32 bytes total (``ESP_PARTITION_ENTRY_SIZE``).
_ENTRY_FORMAT = "<HBBII16sI"


####################
#    IDENTIFIER    #
####################
class ESPFlashIdentifier(Identifier):
    """
    Identify an ESP flash dump by its bootloader and partition-table magics.
    """

    targets = (GenericBinary, Program)

    async def identify(self, resource: Resource, config=None) -> None:
        """
        Identifies if the given resource is an ESP flash dump.

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
    Unpacker for an ESP flash dump.

    Creates a child for the bootloader, the partition table, every partition-table entry, and each
    partition payload that actually lies inside the image.
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
        Parse an ESP flash image, extracting:
        • bootloader section
        • partition-table blob
        • every partition-table entry
        • each partition payload that actually lies inside the image
        """
        data = await resource.get_data()
        data_len = len(data)

        if data_len < ESP_PARTITION_TABLE_OFFSET + ESP_PARTITION_ENTRY_SIZE:
            raise UnpackerError("Image too small to contain a partition table")
        if data[ESP_BOOTLOADER_OFFSET] != ESP_BOOTLOADER_MAGIC:
            raise UnpackerError("Boot-loader magic not found - not an ESP image")
        if (
            data[ESP_PARTITION_TABLE_OFFSET : ESP_PARTITION_TABLE_OFFSET + 2]
            != ESP_PARTITION_ENTRY_MAGIC
        ):
            raise UnpackerError("Partition-table magic not found - not an ESP image")

        # Bootloader occupies [0x1000, 0x8000) (root-relative range == flash offset).
        boot_size = ESP_PARTITION_TABLE_OFFSET - ESP_BOOTLOADER_OFFSET
        await resource.create_child_from_view(
            ESPFlashSection(
                section_index=0,
                name="bootloader",
                virtual_address=ESP_BOOTLOADER_OFFSET,
                size=boot_size,
            ),
            data_range=Range.from_size(ESP_BOOTLOADER_OFFSET, boot_size),
        )

        # The partition table is a single 4 KB sector at 0x8000.
        table_size = min(ESP_PARTITION_TABLE_SIZE, data_len - ESP_PARTITION_TABLE_OFFSET)
        partition_table_res = await resource.create_child_from_view(
            ESPPartitionTable(
                section_index=1,
                name="partition_table",
                virtual_address=ESP_PARTITION_TABLE_OFFSET,
                size=table_size,
            ),
            data_range=Range.from_size(ESP_PARTITION_TABLE_OFFSET, table_size),
        )
        table = data[ESP_PARTITION_TABLE_OFFSET : ESP_PARTITION_TABLE_OFFSET + table_size]

        par_idx = 0
        for entry_offset in range(
            0, table_size - ESP_PARTITION_ENTRY_SIZE + 1, ESP_PARTITION_ENTRY_SIZE
        ):
            magic, p_type, p_sub, offset, size, raw_label, flag = struct.unpack_from(
                _ENTRY_FORMAT, table, entry_offset
            )
            if magic.to_bytes(2, "little") != ESP_PARTITION_ENTRY_MAGIC:  # 0xFFFF terminator
                break

            label = raw_label.rstrip(b"\0").decode() or f"partition_{par_idx}"

            # Entry children map into the partition-table resource, so the data range is relative
            # to the partition table (offset within the sector), not the absolute flash offset.
            await partition_table_res.create_child_from_view(
                ESPPartitionTableEntry(
                    section_index=par_idx,
                    partition_index=par_idx,
                    name=label,
                    virtual_address=ESP_PARTITION_TABLE_OFFSET + entry_offset,
                    size=ESP_PARTITION_ENTRY_SIZE,
                    type=ESPPartitionType.from_value(p_type),
                    subtype=ESPPartitionSubtype.from_value(p_sub),
                    flag=ESPPartitionFlag.from_value(flag),
                ),
                data_range=Range.from_size(entry_offset, ESP_PARTITION_ENTRY_SIZE),
            )

            if offset < data_len:
                payload_size = min(size, data_len - offset)
                if payload_size:
                    await resource.create_child_from_view(
                        ESPPartition(
                            section_index=2 + par_idx,  # after bootloader & table
                            partition_index=par_idx,
                            name=label,
                            virtual_address=offset,
                            size=payload_size,
                        ),
                        data_range=Range.from_size(offset, payload_size),
                    )

            par_idx += 1


####################
#    ANALYZER      #
####################
class ESPFlashAnalyzer(Analyzer[None, ESPFlashAttributes]):
    """
    Analyze ESP flash image for validity and attributes.
    """

    targets = (ESPFlash,)
    outputs = (ESPFlashAttributes,)

    async def analyze(self, resource: Resource, config=None) -> ESPFlashAttributes:
        flash = await resource.view_as(ESPFlash)
        partition_table = await flash.get_partition_table()
        entries = list(await partition_table.get_entries())

        total_partitions = len(entries)
        total_flash_size = await resource.get_data_length()

        # Check for overlapping partitions
        has_overlapping = False
        partition_ranges: List[Tuple[int, int]] = []
        max_end = 0

        for entry in entries:
            try:
                partition = await entry.get_body()
            except NotFoundError:
                # The entry's payload lies outside the dump (no ESPPartition child was created for
                # it), so it contributes no in-image range; skip it.
                continue
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
    Edit a single partition-table entry in place. Only the fields set on the config are changed; the
    rest (notably the partition's ``offset`` and ``size``) are preserved verbatim from the original
    entry bytes. ``config.virtual_address`` maps to the entry's ``offset`` field (the partition's
    flash offset) and ``config.size`` to its ``size`` field.
    """

    id = b"ESPPartitionTableEntryModifier"
    targets = (ESPPartitionTableEntry,)

    async def modify(self, resource: Resource, config: ESPPartitionTableEntryModifierConfig):
        original = await resource.get_data()
        _, p_type, p_sub, offset, size, raw_label, flag = struct.unpack(_ENTRY_FORMAT, original)

        if config.type is not None:
            p_type = config.type.value if isinstance(config.type.value, int) else 0xFF
        if config.subtype is not None:
            p_sub = config.subtype.value if isinstance(config.subtype.value, int) else 0xFF
        if config.virtual_address is not None:
            offset = config.virtual_address
        if config.size is not None:
            size = config.size
        if config.name is not None:
            raw_label = config.name.encode("ascii")[:16].ljust(16, b"\x00")
        if config.flag is not None:
            flag = config.flag.value if isinstance(config.flag.value, int) else 0

        new_entry = struct.pack(
            _ENTRY_FORMAT,
            int.from_bytes(ESP_PARTITION_ENTRY_MAGIC, "little"),
            p_type,
            p_sub,
            offset,
            size,
            raw_label,
            flag,
        )
        resource.queue_patch(Range.from_size(0, len(original)), new_entry)
