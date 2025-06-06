import pytest
from pathlib import Path
from typing import List, Optional

from ofrak import OFRAKContext
from ofrak.resource import Resource
from ofrak.core.esp import (
    ESPFlash,
    ESPFlashIdentifier,
    ESPFlashUnpacker,
    ESPFlashAnalyzer,
    ESPFlashAttributes,
    ESPPartitionTable,
    ESPPartitionTableEntry,
    ESPPartition,
    ESPFlashSection,
    ESPPartitionTableEntryModifier,
    ESPPartitionTableEntryModifierConfig,
    ESPPartitionType,
    ESPPartitionSubtype,
    ESPPartitionFlag,
    ESP_PARTITION_TABLE_OFFSET,
    ESP_BOOTLOADER_OFFSET,
)
from ofrak.service.resource_service_i import ResourceFilter, ResourceAttributeValueFilter
from ofrak.core.esp.flash_model import ESPPartitionStructure
from ofrak.core.program_section import NamedProgramSection


def load_esp_flash_asset(filename: str) -> bytes:
    """Load ESP flash binary from test assets."""
    asset_path = Path(__file__).parent / "assets" / "esp" / filename
    return asset_path.read_bytes()


@pytest.fixture
def esp32_flash_data():
    """Fixture providing test ESP32 flash data from assets"""
    return load_esp_flash_asset("esp32_basic_flash.bin")


@pytest.fixture
def esp32s3_flash_data():
    """Fixture providing test ESP32-S3 flash data from assets"""
    return load_esp_flash_asset("esp32s3_basic_flash.bin")


@pytest.fixture
def esp_flash_data():
    """Fixture providing default ESP flash data (ESP32)"""
    # return load_esp_flash_asset("esp32_basic_flash.bin")
    return load_esp_flash_asset("firmware-360.bin")


@pytest.fixture
def esp8266_flash_data():
    """Fixture providing ESP8266 app data (not a full flash image)"""
    # Note: We only have an ESP8266 app binary, not a full flash image
    return load_esp_flash_asset("esp8266_hello.bin")


@pytest.fixture  
def esp_app_data():
    """Fixture providing ESP app data from assets"""
    from test_ofrak.components.test_esp_app_component import load_esp_asset
    return load_esp_asset("esp32_hello.bin")


@pytest.mark.asyncio
async def test_esp_flash_identifier(ofrak_context: OFRAKContext, esp_flash_data: bytes):
    """Test that ESPFlashIdentifier correctly identifies ESP flash images."""
    resource = await ofrak_context.create_root_resource("test.bin", esp_flash_data)
    
    await resource.identify()
    
    assert resource.has_tag(ESPFlash)


@pytest.mark.asyncio
async def test_esp_flash_unpacker(ofrak_context: OFRAKContext, esp_flash_data: bytes):
    """Test unpacking ESP flash image."""
    resource = await ofrak_context.create_root_resource("test.bin", esp_flash_data)
    await resource.identify()
    
    await resource.unpack()
    
    # Check bootloader section was unpacked
    bootloader = await resource.get_only_child_as_view(
        ESPFlashSection,
        ResourceFilter(
            tags=(ESPFlashSection,),
            attribute_filters=[
                ResourceAttributeValueFilter(NamedProgramSection.SectionName, "bootloader")
            ]
        )
    )
    assert bootloader is not None
    assert bootloader.virtual_address == ESP_BOOTLOADER_OFFSET
    
    # Check partition table was unpacked
    partition_table = await resource.get_only_child_as_view(
        ESPPartitionTable,
        ResourceFilter(tags=(ESPPartitionTable,))
    )
    assert partition_table is not None
    assert partition_table.virtual_address == ESP_PARTITION_TABLE_OFFSET
    
    # Check partitions were unpacked
    flash = await resource.view_as(ESPFlash)
    sections = list(await flash.get_sections())
    assert len(sections) >= 2  # At least bootloader and partition table


@pytest.mark.asyncio
async def test_esp_flash_analyzer(ofrak_context: OFRAKContext, esp_flash_data: bytes):
    """Test ESP flash analyzer."""
    resource = await ofrak_context.create_root_resource("test.bin", esp_flash_data)
    await resource.identify()
    await resource.unpack()
    
    attributes = await resource.analyze(ESPFlashAttributes)
    
    assert attributes.total_partitions > 0
    assert attributes.total_flash_size == len(esp_flash_data)
    assert isinstance(attributes.has_overlapping_partitions, bool)
    assert attributes.unused_space >= 0


@pytest.mark.asyncio
async def test_esp_partition_table_entries(ofrak_context: OFRAKContext, esp_flash_data: bytes):
    """Test partition table entry parsing."""
    resource = await ofrak_context.create_root_resource("test.bin", esp_flash_data)
    await resource.identify()
    await resource.unpack()
    
    # Get partition table
    flash = await resource.view_as(ESPFlash)
    partition_table = await flash.get_partition_table()
    entries = list(await partition_table.get_entries())
    print(entries)
    assert len(entries) > 0
    
    # Check first entry
    first_entry = entries[0]
    assert isinstance(first_entry.type, ESPPartitionType)
    assert isinstance(first_entry.subtype, ESPPartitionSubtype)
    assert first_entry.name != ""
    
    # Get corresponding partition
    partition = await first_entry.get_body()
    # The partition and entry should have the same name and partition index
    assert partition.name == first_entry.name
    assert partition.partition_index == first_entry.partition_index
    # The partition should have some reasonable size (actual partition data size)
    assert partition.size > 0


@pytest.mark.asyncio
async def test_esp_partition_table_entry_modifier(ofrak_context: OFRAKContext, esp_flash_data: bytes):
    """Test modifying partition table entries."""
    resource = await ofrak_context.create_root_resource("test.bin", esp_flash_data)
    await resource.identify()
    await resource.unpack()
    
    # Get first partition entry
    flash = await resource.view_as(ESPFlash)
    partition_table = await flash.get_partition_table()
    entries = list(await partition_table.get_entries())
    first_entry = entries[0]
    
    # Modify the entry
    new_type = ESPPartitionType.DATA
    new_subtype = ESPPartitionSubtype.NVS
    new_flag = ESPPartitionFlag.ENCRYPTED
    
    await first_entry.resource.run(
        ESPPartitionTableEntryModifier,
        ESPPartitionTableEntryModifierConfig(
            type=new_type,
            subtype=new_subtype,
            flag=new_flag
        )
    )
    
    # Verify modification
    modified_entry = await first_entry.resource.view_as(ESPPartitionTableEntry)
    assert modified_entry.type == new_type
    assert modified_entry.subtype == new_subtype
    assert modified_entry.flag == new_flag

@pytest.mark.asyncio
async def test_esp_flash_with_app_partition(ofrak_context: OFRAKContext, esp_flash_data: bytes):
    """Test handling flash image with app partitions."""
    resource = await ofrak_context.create_root_resource("test.bin", esp_flash_data)
    await resource.identify()
    await resource.unpack()
    
    # Find app partitions
    flash = await resource.view_as(ESPFlash)
    partition_table = await flash.get_partition_table()
    entries = list(await partition_table.get_entries())
    
    app_partitions = [e for e in entries if e.type == ESPPartitionType.APP]
    assert len(app_partitions) > 0
    
    # Check if app partition contains valid ESP app
    for app_entry in app_partitions:
        partition = await app_entry.get_body()
        partition_data = await partition.resource.get_data()
        
        # Check for ESP app magic at start of partition
        if len(partition_data) > 0:
            if partition_data[0] in [0xE9, 0xEA]: # ESP app magic bytes
                assert True
                return
    assert False
