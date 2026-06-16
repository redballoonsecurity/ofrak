import os
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pytest

from ofrak.component.unpacker import UnpackerError
from ofrak.core.esp.app import _parse_image

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
    assert attributes.image_version == 1
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


# ---------------------------------------------------------------------------
# ESP8266 v2 (magic 0xEA) images
# ---------------------------------------------------------------------------
V2_IROM_ADDR = 0x40201010
V2_IRAM_ADDR = 0x40100000
V2_DRAM_ADDR = 0x3FFE8000
V2_ENTRY_POINT = 0x40100000


def _build_esp8266_v2_image() -> bytes:
    """Build a valid ESP8266 v2 (0xEA) image with esptool, or skip if esptool is unavailable."""
    try:
        from esptool.bin_image import ESP8266V2FirmwareImage, ImageSegment
    except ImportError:
        pytest.skip("esptool not available to build a v2 fixture")

    image = ESP8266V2FirmwareImage()
    image.entrypoint = V2_ENTRY_POINT
    image.flash_mode = 0
    image.flash_size_freq = 0
    image.segments.append(
        ImageSegment(V2_IROM_ADDR, b"\xAA" * 48, 0)
    )  # irom0 (excluded from cksum)
    image.segments.append(ImageSegment(V2_IRAM_ADDR, b"\xBB" * 32, 0))
    image.segments.append(ImageSegment(V2_DRAM_ADDR, b"\xCC" * 16, 0))

    path = tempfile.mktemp(suffix=".bin")
    try:
        image.save(path)
        with open(path, "rb") as f:
            return f.read()
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


async def test_esp8266_v2_unpack(ofrak_context: OFRAKContext):
    """An ESP8266 v2 image is identified, unpacked into irom0 + segments, and validated."""
    data = _build_esp8266_v2_image()
    root_resource = await ofrak_context.create_root_resource("v2.bin", data)
    await root_resource.identify()
    assert root_resource.has_tag(ESPApp)

    await root_resource.unpack()
    esp_app = await root_resource.view_as(ESPApp)
    sections = list(await esp_app.get_sections())
    assert len(sections) == 3  # irom0 + iram + dram

    attributes = await root_resource.analyze(ESPAppAttributes)
    assert attributes.image_version == 2
    assert attributes.magic == 0xEA
    assert attributes.chip == ESPChip.ESP8266
    assert attributes.entry_point == V2_ENTRY_POINT
    assert attributes.has_extended_header is False
    assert attributes.hash_appended is False
    # v2 images carry a CRC32 footer (not a SHA256 digest); both checksum and CRC must be valid.
    assert attributes.checksum_valid is True
    assert attributes.crc32 is not None
    assert attributes.crc32_valid is True


class TestESP8266V2UnpackModifyPack(UnpackModifyPackPattern):
    async def create_root_resource(self, ofrak_context: OFRAKContext) -> Resource:
        return await ofrak_context.create_root_resource("v2.bin", _build_esp8266_v2_image())

    async def unpack(self, root_resource: Resource) -> None:
        await root_resource.identify()
        await root_resource.unpack()

    async def modify(self, unpacked_root_resource: Resource) -> None:
        self.new_entry_point = 0x40108000
        await unpacked_root_resource.run(
            ESPAppHeaderModifier, ESPAppHeaderModifierConfig(entry_point=self.new_entry_point)
        )

    async def repack(self, modified_root_resource: Resource) -> None:
        await modified_root_resource.run(ESPAppPacker)

    async def verify(self, repacked_root_resource: Resource) -> None:
        await repacked_root_resource.identify()
        assert repacked_root_resource.has_tag(ESPApp)

        attributes = await repacked_root_resource.analyze(ESPAppAttributes)
        assert attributes.image_version == 2
        assert attributes.entry_point == self.new_entry_point
        # The packer must recompute both the XOR checksum and the trailing CRC32.
        assert attributes.checksum_valid is True
        assert attributes.crc32_valid is True


# ---------------------------------------------------------------------------
# Robustness: malformed / truncated input must fail cleanly, not crash
# ---------------------------------------------------------------------------
def test_parse_image_rejects_malformed():
    """_parse_image raises UnpackerError (not IndexError/struct.error) on bad input."""
    # Too small to hold even a header.
    with pytest.raises(UnpackerError):
        _parse_image(b"\xe9")
    # Valid magic but the declared segments run past the end of the data.
    truncated = bytes([0xE9, 3, 0, 0]) + struct.pack("<I", 0x40080000)
    with pytest.raises(UnpackerError):
        _parse_image(truncated)
    # Unknown magic.
    with pytest.raises(UnpackerError):
        _parse_image(b"\x00" * 64)


async def test_identifier_ignores_short_resource(ofrak_context: OFRAKContext):
    """A 1-3 byte resource starting with 0xE9 must not crash the ESP app identifier."""
    root_resource = await ofrak_context.create_root_resource("tiny.bin", b"\xe9\x00")
    await root_resource.identify()  # must not raise IndexError
    assert not root_resource.has_tag(ESPApp)
