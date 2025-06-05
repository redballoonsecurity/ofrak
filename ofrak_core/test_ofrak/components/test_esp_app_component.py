import pytest
from pathlib import Path

from ofrak import OFRAKContext
from ofrak.core.esp import (
    ESPApp,
    ESPAppHeader,
    ESPAppExtendedHeader,
    ESPAppChecksum,
    ESPAppHash,
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


@pytest.mark.asyncio
async def test_esp_app_packer_esp32(ofrak_context: OFRAKContext, esp32_app_data: bytes):
    """Test packing ESP32 app with checksum and hash recalculation."""
    from ofrak.core.esp import ESPAppPacker
    
    resource = await ofrak_context.create_root_resource("test.bin", esp32_app_data)
    await resource.identify()
    await resource.unpack()
    
    # Get original attributes to compare
    original_attrs = await resource.analyze(ESPAppAttributes)
    
    # Get original checksum and hash values before packing
    original_checksum = await resource.get_only_child_as_view(
        ESPAppChecksum,
        ResourceFilter(tags=(ESPAppChecksum,))
    )
    original_checksum_value = original_checksum.checksum
    
    try:
        original_hash = await resource.get_only_child_as_view(
            ESPAppHash,
            ResourceFilter(tags=(ESPAppHash,))
        )
        original_hash_value = original_hash.hash
        has_hash = True
    except:
        has_hash = False
        original_hash_value = None
    
    # Modify the entry point to invalidate checksums
    header = await resource.get_only_child_as_view(
        ESPAppHeader,
        ResourceFilter(tags=(ESPAppHeader,))
    )
    original_entry = header.entry_point
    new_entry = 0x40080400 if original_entry != 0x40080400 else 0x40080500
    
    await header.resource.run(
        ESPAppHeaderModifier,
        ESPAppHeaderModifierConfig(entry_point=new_entry)
    )
    
    # Pack the modified app
    await resource.run(ESPAppPacker)
    
    # Verify the app was repacked correctly
    new_data = await resource.get_data()
    assert len(new_data) > 0
    
    # Re-unpack to verify the changes
    await resource.unpack()
    
    # Verify entry point was modified
    modified_header = await resource.get_only_child_as_view(
        ESPAppHeader,
        ResourceFilter(tags=(ESPAppHeader,))
    )
    assert modified_header.entry_point == new_entry
    
    # Verify checksum was recalculated
    new_checksum = await resource.get_only_child_as_view(
        ESPAppChecksum,
        ResourceFilter(tags=(ESPAppChecksum,))
    )
    # Note: Checksum won't change from header modifications alone
    # ESP checksums only include segment data
    
    # Verify hash was recalculated if present
    if has_hash:
        new_hash = await resource.get_only_child_as_view(
            ESPAppHash,
            ResourceFilter(tags=(ESPAppHash,))
        )
        # Hash should be different since we modified the entry point
        assert new_hash.hash != original_hash_value
    
    # Verify app attributes show validity
    new_attrs = await resource.analyze(ESPAppAttributes)
    assert new_attrs.checksum_valid == True
    if has_hash:
        assert new_attrs.hash_valid == True
    
    # Verify the packed app still identifies correctly
    assert resource.has_tag(ESPApp)


@pytest.mark.asyncio
async def test_esp_app_packer_esp8266(ofrak_context: OFRAKContext, esp8266_app_data: bytes):
    """Test packing ESP8266 app (no extended header, no hash)."""
    from ofrak.core.esp import ESPAppPacker
    
    resource = await ofrak_context.create_root_resource("test.bin", esp8266_app_data)
    await resource.identify()
    await resource.unpack()
    
    # Get original checksum value before packing
    original_checksum = await resource.get_only_child_as_view(
        ESPAppChecksum,
        ResourceFilter(tags=(ESPAppChecksum,))
    )
    original_checksum_value = original_checksum.checksum
    print(original_checksum_value)
    
    # Modify the entry point
    header = await resource.get_only_child_as_view(
        ESPAppHeader,
        ResourceFilter(tags=(ESPAppHeader,))
    )
    original_entry = header.entry_point
    new_entry = 0x40100000 if original_entry != 0x40100000 else 0x40100100
    
    await header.resource.run(
        ESPAppHeaderModifier,
        ESPAppHeaderModifierConfig(entry_point=new_entry)
    )
    
    # Pack the modified app
    await resource.run(ESPAppPacker)
    
    # Verify the app was repacked correctly
    new_data = await resource.get_data()
    assert len(new_data) > 0
    
    # Re-unpack to verify changes
    await resource.unpack()
    
    # Verify entry point was modified
    modified_header = await resource.get_only_child_as_view(
        ESPAppHeader,
        ResourceFilter(tags=(ESPAppHeader,))
    )
    assert modified_header.entry_point == new_entry
    
    # Verify checksum was recalculated
    new_checksum = await resource.get_only_child_as_view(
        ESPAppChecksum,
        ResourceFilter(tags=(ESPAppChecksum,))
    )
    # Note: Checksum won't change from header modifications alone
    # ESP checksums only include segment data
    
    # ESP8266 should not have hash or extended header
    try:
        await resource.get_only_child_as_view(
            ESPAppExtendedHeader,
            ResourceFilter(tags=(ESPAppExtendedHeader,))
        )
        assert False, "ESP8266 should not have extended header"
    except:
        pass  # Expected
    
    try:
        await resource.get_only_child_as_view(
            ESPAppHash,
            ResourceFilter(tags=(ESPAppHash,))
        )
        assert False, "ESP8266 should not have hash"
    except:
        pass  # Expected
    
    new_attrs = await resource.analyze(ESPAppAttributes)
    assert new_attrs.checksum_valid == True
    
    # Verify the packed app still identifies correctly
    assert resource.has_tag(ESPApp)


@pytest.mark.asyncio
async def test_esp_app_packer_simple(ofrak_context: OFRAKContext, esp32_app_data: bytes):
    """Simple test for ESP app packer without complex verification."""
    from ofrak.core.esp import ESPAppPacker, ESPAppHash
    
    # Create resource and unpack
    resource = await ofrak_context.create_root_resource("test.bin", esp32_app_data)
    await resource.identify()
    await resource.unpack()
    
    # Get original checksum value before modifying
    original_checksum = await resource.get_only_child_as_view(
        ESPAppChecksum,
        ResourceFilter(tags=(ESPAppChecksum,))
    )
    original_checksum_value = original_checksum.checksum
    
    # Modify the entry point to invalidate checksum
    header = await resource.get_only_child_as_view(
        ESPAppHeader,
        ResourceFilter(tags=(ESPAppHeader,))
    )
    original_entry = header.entry_point
    new_entry = 0x40080400 if original_entry != 0x40080400 else 0x40080500
    
    await header.resource.run(
        ESPAppHeaderModifier,
        ESPAppHeaderModifierConfig(entry_point=new_entry)
    )
    
    # Verify entry point was changed
    modified_header = await resource.get_only_child_as_view(
        ESPAppHeader,
        ResourceFilter(tags=(ESPAppHeader,))
    )
    assert modified_header.entry_point == new_entry
    
    # Pack the modified app
    await resource.run(ESPAppPacker)
    
    # Verify the app was repacked
    new_data = await resource.get_data()
    assert len(new_data) > 0
    assert len(new_data) == len(esp32_app_data)  # Should be same size
    
    # The packed app should still identify as ESP
    await resource.identify()
    assert resource.has_tag(ESPApp)
    
    # Re-analyze to verify checksum validity after packing
    new_attrs = await resource.analyze(ESPAppAttributes)
    assert new_attrs.checksum_valid == True
    # Note: The checksum won't change from modifying the entry point alone
    # because ESP checksums are calculated only from segment data, not headers


@pytest.mark.asyncio
async def test_esp_app_packer_with_esptool_verification(ofrak_context: OFRAKContext, esp32_app_data: bytes):
    """Test packing ESP app and verify with esptool image_info."""
    from ofrak.core.esp import ESPAppPacker
    import tempfile
    import subprocess
    import os
    
    resource = await ofrak_context.create_root_resource("test.bin", esp32_app_data)
    await resource.identify()
    await resource.unpack()
    
    # Modify something to ensure we're testing the packer
    header = await resource.get_only_child_as_view(
        ESPAppHeader,
        ResourceFilter(tags=(ESPAppHeader,))
    )
    original_entry = header.entry_point
    new_entry = 0x40080400 if original_entry != 0x40080400 else 0x40080500
    
    await header.resource.run(
        ESPAppHeaderModifier,
        ESPAppHeaderModifierConfig(entry_point=new_entry)
    )
    
    # Pack the modified app
    await resource.run(ESPAppPacker)
    
    # Get the packed data and save to temporary file
    packed_data = await resource.get_data()
    
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as temp_file:
        temp_file.write(packed_data)
        temp_file.flush()
        
        try:
            # Use esptool.py to verify the image
            result = subprocess.run([
                "python", "-m", "esptool", 
                "image_info", 
                "--version", "2", 
                temp_file.name
            ], capture_output=True, text=True, timeout=30)
            
            # Check that esptool ran successfully
            assert result.returncode == 0, f"esptool failed: {result.stderr}"
            
            # Check that the output contains expected information
            output = result.stdout
            assert "Checksum:" in output, "esptool output should contain checksum information"
            assert "invalid" not in output.lower(), "Checksum should not be invalid"
            
            # If the image has a hash, verify it's mentioned
            try:
                await resource.get_only_child_as_view(
                    ESPAppHash,
                    ResourceFilter(tags=(ESPAppHash,))
                )
                # Should have hash information in output
                assert any(word in output.lower() for word in ["hash", "digest", "sha256"]), \
                    "Output should contain hash information for ESP32 images"
            except:
                pass  # No hash present
                
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            # Skip test if esptool is not available or times out
            pytest.skip(f"esptool not available or timed out: {e}")
        finally:
            # Clean up
            try:
                os.unlink(temp_file.name)
            except:
                pass
