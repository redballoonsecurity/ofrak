import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pytest

from ofrak import OFRAKContext
from ofrak.resource import Resource
from ofrak.core.esp import (
    ESPApp,
    ESPAppAttributes,
    ESPAppHeaderModifier,
    ESPAppHeaderModifierConfig,
    ESPAppPacker,
    ESPChip,
)
from pytest_ofrak.patterns.modify import ModifyPattern
from pytest_ofrak.patterns.unpack_modify_pack import UnpackModifyPackPattern


def load_esp_asset(filename: str) -> bytes:
    """Load an ESP binary from the test assets."""
    asset_path = Path(__file__).parent / "assets" / "esp" / filename
    return asset_path.read_bytes()


@dataclass
class ESPAppUnpackTestCase:
    label: str
    binary_path: str
    has_extended_header: bool
    has_hash: bool
    num_sections: int
    magic: int
    entry_point: int
    checksum: int
    chip: ESPChip
    chip_id: Optional[int] = None
    stored_hash: Optional[bytes] = None


ESP_APP_TEST_CASES = [
    ESPAppUnpackTestCase(
        label="ESP32 App",
        binary_path="esp32_hello.bin",
        has_extended_header=True,
        has_hash=True,
        num_sections=5,
        magic=0xE9,
        entry_point=0x400829AC,
        checksum=0xEA,
        chip=ESPChip.ESP32,
        chip_id=0x0000,  # ESP32
        stored_hash=bytes.fromhex(
            "0750ce50194e3125f218af81d7a07ad0f5c23500ac487f047d77e89acadb6300"
        ),
    ),
    ESPAppUnpackTestCase(
        label="ESP32-S3 App",
        binary_path="esp32s3_hello.bin",
        has_extended_header=True,
        has_hash=True,
        num_sections=5,
        magic=0xE9,
        entry_point=0x40376EC4,
        checksum=0x70,
        chip=ESPChip.ESP32S3,
        chip_id=0x0009,  # ESP32-S3
        stored_hash=bytes.fromhex(
            "fec85e5eee92d767571cf058f150907c988c482cb2a71c0fc280f5202667832e"
        ),
    ),
    ESPAppUnpackTestCase(
        label="ESP8266 App",
        binary_path="esp8266_hello.bin",
        has_extended_header=False,
        has_hash=False,
        num_sections=2,
        magic=0xE9,
        entry_point=0x4010F480,
        checksum=0x2B,
        chip=ESPChip.ESP8266,
    ),
]


@pytest.mark.parametrize("test_case", ESP_APP_TEST_CASES, ids=lambda tc: tc.label)
async def test_esp_app_unpack(ofrak_context: OFRAKContext, test_case: ESPAppUnpackTestCase):
    """Identify and unpack an ESP app, verifying its segments and parsed attributes."""
    root_resource = await ofrak_context.create_root_resource(
        test_case.label, load_esp_asset(test_case.binary_path)
    )
    await root_resource.identify()
    assert root_resource.has_tag(ESPApp), "Resource was not identified as an ESPApp"

    await root_resource.unpack()

    # Only the loadable segments become children.
    esp_app = await root_resource.view_as(ESPApp)
    sections = list(await esp_app.get_sections())
    assert len(sections) == test_case.num_sections

    # Header / extended header / checksum / hash are exposed as attributes, not children.
    attributes = await root_resource.analyze(ESPAppAttributes)
    assert attributes.magic == test_case.magic
    assert attributes.entry_point == test_case.entry_point
    assert attributes.num_segments == test_case.num_sections
    assert attributes.checksum == test_case.checksum
    assert attributes.chip == test_case.chip
    assert attributes.has_extended_header == test_case.has_extended_header

    # The unmodified images are valid.
    assert attributes.checksum_valid is True
    if test_case.has_extended_header:
        assert attributes.chip_id == test_case.chip_id
    if test_case.has_hash:
        assert attributes.hash_appended is True
        assert attributes.stored_hash == test_case.stored_hash
        assert attributes.hash_valid is True


class TestESPAppHeaderModification(ModifyPattern):
    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        resource = await ofrak_context.create_root_resource(
            "test.bin", load_esp_asset("esp32_hello.bin")
        )
        await resource.identify()
        await resource.unpack()
        return resource

    async def modify(self, root_resource: Resource) -> None:
        attributes = await root_resource.analyze(ESPAppAttributes)
        self.original_entry_point = attributes.entry_point

        await root_resource.run(
            ESPAppHeaderModifier, ESPAppHeaderModifierConfig(entry_point=0x40080400)
        )

    async def verify(self, root_resource: Resource) -> None:
        attributes = await root_resource.analyze(ESPAppAttributes)
        assert attributes.entry_point == 0x40080400
        assert attributes.entry_point != self.original_entry_point


def _verify_with_esptool(packed_data: bytes, has_hash: bool = True):
    """Verify packed ESP app data with esptool's image_info, skipping if esptool is unavailable."""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as temp_file:
        temp_file.write(packed_data)
        temp_file.flush()
        temp_path = temp_file.name

    try:
        result = subprocess.run(
            [sys.executable, "-m", "esptool", "image_info", "--version", "2", temp_path],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0, f"esptool failed: {result.stderr}"

        output = result.stdout
        assert "Checksum:" in output, "esptool output should contain checksum information"
        assert "invalid" not in output.lower(), "Checksum should not be invalid"

        if has_hash:
            assert any(
                word in output.lower() for word in ["hash", "digest", "sha256"]
            ), "Output should contain hash information for ESP32 images"

    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        pytest.skip(f"esptool not available or timed out: {e}")
    finally:
        try:
            os.unlink(temp_path)
        except OSError:
            pass


class TestESP32AppUnpackModifyPack(UnpackModifyPackPattern):
    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        return await ofrak_context.create_root_resource(
            "test.bin", load_esp_asset("esp32_hello.bin")
        )

    async def unpack(self, root_resource: Resource) -> None:
        await root_resource.identify()
        await root_resource.unpack()

    async def modify(self, unpacked_root_resource: Resource) -> None:
        attributes = await unpacked_root_resource.analyze(ESPAppAttributes)
        self.new_entry_point = 0x40080400 if attributes.entry_point != 0x40080400 else 0x40080500

        await unpacked_root_resource.run(
            ESPAppHeaderModifier, ESPAppHeaderModifierConfig(entry_point=self.new_entry_point)
        )

    async def repack(self, modified_root_resource: Resource) -> None:
        await modified_root_resource.run(ESPAppPacker)

    async def verify(self, repacked_root_resource: Resource) -> None:
        await repacked_root_resource.identify()
        assert repacked_root_resource.has_tag(ESPApp)

        attributes = await repacked_root_resource.analyze(ESPAppAttributes)
        assert attributes.entry_point == self.new_entry_point
        assert attributes.checksum_valid is True
        assert attributes.hash_valid is True

        _verify_with_esptool(await repacked_root_resource.get_data(), has_hash=True)


class TestESP8266AppUnpackModifyPack(UnpackModifyPackPattern):
    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        return await ofrak_context.create_root_resource(
            "test.bin", load_esp_asset("esp8266_hello.bin")
        )

    async def unpack(self, root_resource: Resource) -> None:
        await root_resource.identify()
        await root_resource.unpack()

    async def modify(self, unpacked_root_resource: Resource) -> None:
        attributes = await unpacked_root_resource.analyze(ESPAppAttributes)
        self.new_entry_point = 0x40080400 if attributes.entry_point != 0x40080400 else 0x40080500

        await unpacked_root_resource.run(
            ESPAppHeaderModifier, ESPAppHeaderModifierConfig(entry_point=self.new_entry_point)
        )

    async def repack(self, modified_root_resource: Resource) -> None:
        await modified_root_resource.run(ESPAppPacker)

    async def verify(self, repacked_root_resource: Resource) -> None:
        await repacked_root_resource.identify()
        assert repacked_root_resource.has_tag(ESPApp)

        attributes = await repacked_root_resource.analyze(ESPAppAttributes)
        assert attributes.entry_point == self.new_entry_point
        assert attributes.checksum_valid is True

        _verify_with_esptool(await repacked_root_resource.get_data(), has_hash=False)
