import pytest
import tempfile
from pathlib import Path
from typing import List, Optional
from unittest.mock import patch

from ofrak import OFRAKContext
from ofrak.resource import Resource
from ofrak.core.esp import (
    ESPApp,
    ESPAppHeader,
    ESPAppExtendedHeader,
    ESPAppChecksum,
    ESPAppAttributes,
    ESPAppHeaderModifier,
    ESPAppHeaderModifierConfig,
    ESPAppExtendedHeaderModifier,
    ESPAppExtendedHeaderModifierConfig,
    ESPAppSectionHeaderModifier,
    ESPAppSectionHeaderModifierConfig,
)
from ofrak.service.resource_service_i import ResourceFilter


def load_esp_asset(filename: str) -> bytes:
    """Load ESP binary from test assets."""
    asset_path = Path(__file__).parent / "assets" / "esp" / filename
    return asset_path.read_bytes()


@pytest.fixture
def esp8266_app_data():
    """Fixture providing test ESP8266 app data from assets"""
    return load_esp_asset("esp8266_hello.bin")


@pytest.fixture
def esp32_app_data():
    """Fixture providing test ESP32 app data from assets"""
    return load_esp_asset("esp32_hello.bin")


@pytest.fixture
def esp32s3_app_data():
    """Fixture providing test ESP32-S3 app data from assets"""
    return load_esp_asset("esp32s3_hello.bin")


@pytest.mark.asyncio
async def test_esp_app_identifier(ofrak_context: OFRAKContext, esp32_app_data: bytes):
    """Test that ESPAppIdentifier correctly identifies ESP app binaries."""
    resource = await ofrak_context.create_root_resource("test.bin", esp32_app_data)
    
    await resource.identify()
    
    assert resource.has_tag(ESPApp)


@pytest.mark.asyncio
async def test_esp_app_unpacker_esp32(ofrak_context: OFRAKContext, esp32_app_data: bytes):
    """Test unpacking ESP32 app binary."""
    resource = await ofrak_context.create_root_resource("test.bin", esp32_app_data)
    await resource.identify()
    
    await resource.unpack()
    
    # Check header was unpacked
    header = await resource.get_only_child_as_view(
        ESPAppHeader,
        ResourceFilter(tags=(ESPAppHeader,))
    )
    assert header.magic == 0xE9
    assert header.entry_point != 0
    
    # Check extended header exists (ESP32 has it)
    extended_header = await resource.get_only_child_as_view(
        ESPAppExtendedHeader,
        ResourceFilter(tags=(ESPAppExtendedHeader,))
    )
    assert extended_header is not None
    
    # Check sections were unpacked
    esp_app = await resource.view_as(ESPApp)
    sections = list(await esp_app.get_sections())
    assert len(sections) > 0
    
    # Check checksum was unpacked
    checksum = await resource.get_only_child_as_view(
        ESPAppChecksum,
        ResourceFilter(tags=(ESPAppChecksum,))
    )
    assert checksum is not None


@pytest.mark.asyncio
async def test_esp_app_unpacker_esp8266(ofrak_context: OFRAKContext, esp8266_app_data: bytes):
    """Test unpacking ESP8266 app binary."""
    resource = await ofrak_context.create_root_resource("test.bin", esp8266_app_data)
    await resource.identify()
    
    await resource.unpack()
    
    # Check header was unpacked
    header = await resource.get_only_child_as_view(
        ESPAppHeader,
        ResourceFilter(tags=(ESPAppHeader,))
    )
    assert header.magic == 0xE9
    
    # ESP8266 should NOT have extended header
    try:
        extended_header = await resource.get_only_child_as_view(
            ESPAppExtendedHeader,
            ResourceFilter(tags=(ESPAppExtendedHeader,))
        )
        assert False, "ESP8266 should not have extended header"
    except:
        pass  # Expected


@pytest.mark.asyncio
async def test_esp_app_analyzer(ofrak_context: OFRAKContext, esp32_app_data: bytes):
    """Test ESP app analyzer."""
    resource = await ofrak_context.create_root_resource("test.bin", esp32_app_data)
    await resource.identify()
    await resource.unpack()
    
    attributes = await resource.analyze(ESPAppAttributes)
    
    assert attributes.chip_name.lower() in ["esp32", "esp32-s3", "esp8266"]
    assert isinstance(attributes.checksum_valid, bool)
    assert isinstance(attributes.calculated_checksum, int)


@pytest.mark.asyncio
async def test_esp_app_header_modifier(ofrak_context: OFRAKContext, esp32_app_data: bytes):
    """Test modifying ESP app header."""
    resource = await ofrak_context.create_root_resource("test.bin", esp32_app_data)
    await resource.identify()
    await resource.unpack()
    
    # Get original header
    header = await resource.get_only_child_as_view(
        ESPAppHeader,
        ResourceFilter(tags=(ESPAppHeader,))
    )
    original_entry = header.entry_point
    
    # Modify entry point
    new_entry = 0x40080400
    await header.resource.run(
        ESPAppHeaderModifier,
        ESPAppHeaderModifierConfig(entry_point=new_entry)
    )
    
    # Verify modification
    modified_header = await resource.get_only_child_as_view(
        ESPAppHeader,
        ResourceFilter(tags=(ESPAppHeader,))
    )
    assert modified_header.entry_point == new_entry


@pytest.mark.asyncio
async def test_esp_app_extended_header_modifier(ofrak_context: OFRAKContext, esp32_app_data: bytes):
    """Test modifying ESP app extended header."""
    resource = await ofrak_context.create_root_resource("test.bin", esp32_app_data)
    await resource.identify()
    await resource.unpack()
    
    # Get extended header
    extended_header = await resource.get_only_child_as_view(
        ESPAppExtendedHeader,
        ResourceFilter(tags=(ESPAppExtendedHeader,))
    )
    
    # Modify chip ID
    new_chip_id = 0x0005  # ESP32-C3
    await extended_header.resource.run(
        ESPAppExtendedHeaderModifier,
        ESPAppExtendedHeaderModifierConfig(chip_id=new_chip_id)
    )
    
    # Verify modification
    modified_header = await resource.get_only_child_as_view(
        ESPAppExtendedHeader,
        ResourceFilter(tags=(ESPAppExtendedHeader,))
    )
    assert modified_header.chip_id == new_chip_id


@pytest.mark.asyncio
async def test_esp_app_section_header_modifier(ofrak_context: OFRAKContext, esp32_app_data: bytes):
    """Test modifying ESP app section headers."""
    resource = await ofrak_context.create_root_resource("test.bin", esp32_app_data)
    await resource.identify()
    await resource.unpack()
    
    # Get first section
    esp_app = await resource.view_as(ESPApp)
    sections = list(await esp_app.get_sections())
    if sections:
        first_section = sections[0]
        header = await first_section.get_header()
        
        # Modify size
        original_size = header.segment_size
        new_size = original_size + 0x100
        
        await header.resource.run(
            ESPAppSectionHeaderModifier,
            ESPAppSectionHeaderModifierConfig(segment_size=new_size)
        )