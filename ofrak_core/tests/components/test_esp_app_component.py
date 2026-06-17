import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pytest

from ofrak.component.unpacker import UnpackerError
from ofrak.core.esp.app import _determine_chip, _parse_image
from ofrak.core.program import CodeRegion

from ofrak import OFRAKContext
from ofrak.resource import Resource
from ofrak.core.esp import (
    ESPApp,
    ESPAppAttributes,
    ESPAppFlashMode,
    ESPAppHeaderModifier,
    ESPAppHeaderModifierConfig,
    ESPAppPacker,
    ESPChip,
    ESP_APP_HEADER_SIZE,
    ESP_APP_SEGMENT_HEADER_SIZE,
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
    # Expected names of the chip-aware decoded flash size / frequency (the analyzer turns the raw
    # nibbles into these so the breakdown is interpretable in the GUI).
    flash_size_decoded: str
    flash_frequency_decoded: str
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
        flash_size_decoded="S_4MB",
        flash_frequency_decoded="ITFF_0MHz",
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
        flash_size_decoded="S_8MB",
        flash_frequency_decoded="ITFF_FMHz",
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
        flash_size_decoded="S_4MB",
        flash_frequency_decoded="F_40MHz",
    ),
    ESPAppUnpackTestCase(
        label="ESP32-C3 App (RISC-V)",
        binary_path="esp32c3_hello.bin",
        has_extended_header=True,
        has_hash=True,
        num_sections=1,
        magic=0xE9,
        entry_point=0x4037C000,
        checksum=0x0F,
        chip=ESPChip.ESP32C3,
        flash_size_decoded="S_1MB",
        flash_frequency_decoded="ITFF_0MHz",
        chip_id=0x0005,  # ESP32-C3 (RISC-V)
        stored_hash=bytes.fromhex(
            "f4fff5fd5a1c7eaceeec150360b8e1ce94b231c74b3e5563d4dde2b43954a86e"
        ),
    ),
    ESPAppUnpackTestCase(
        label="ESP32-C6 App (RISC-V)",
        binary_path="esp32c6_hello.bin",
        has_extended_header=True,
        has_hash=True,
        num_sections=1,
        magic=0xE9,
        entry_point=0x40800000,
        checksum=0x0F,
        chip=ESPChip.ESP32C6,
        flash_size_decoded="S_1MB",
        # C6 uses a chip-specific frequency table (raw 0 -> 80 MHz, not the ESP32 ITFF encoding).
        flash_frequency_decoded="F_80MHz",
        chip_id=0x000D,  # ESP32-C6 (RISC-V)
        stored_hash=bytes.fromhex(
            "1f018e001c9410499711dc01c89e0e0f5e44407108009d3d3a51a1cf40bb0f70"
        ),
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

    # The raw flash size/frequency nibbles are decoded (chip-aware) so the breakdown is readable.
    # Compare names with ``is not None`` first -- the value-0 members (e.g. ITFF_0MHz) are falsy.
    assert attributes.flash_size_decoded is not None
    assert attributes.flash_size_decoded.name == test_case.flash_size_decoded
    assert attributes.flash_frequency_decoded is not None
    assert attributes.flash_frequency_decoded.name == test_case.flash_frequency_decoded

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
    """Independently validate packed ESP app data with esptool's ``image_info`` (a pinned test dep)."""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as temp_file:
        temp_file.write(packed_data)
        temp_file.flush()
        temp_path = temp_file.name

    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "esptool",
                "image_info",
                "--version",
                "2",
                temp_path,
            ],
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
            ESPAppHeaderModifier,
            ESPAppHeaderModifierConfig(entry_point=self.new_entry_point),
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
            ESPAppHeaderModifier,
            ESPAppHeaderModifierConfig(entry_point=self.new_entry_point),
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
# Entry point of the committed esp8266v2_hello.bin fixture (its _start, in IRAM).
V2_ENTRY_POINT = 0x40100000


async def test_esp8266_v2_unpack(ofrak_context: OFRAKContext):
    """An ESP8266 v2 image is identified, unpacked into irom0 + segments, and validated."""
    data = load_esp_asset("esp8266v2_hello.bin")
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
        return await ofrak_context.create_root_resource(
            "v2.bin", load_esp_asset("esp8266v2_hello.bin")
        )

    async def unpack(self, root_resource: Resource) -> None:
        await root_resource.identify()
        await root_resource.unpack()

    async def modify(self, unpacked_root_resource: Resource) -> None:
        self.new_entry_point = 0x40108000
        await unpacked_root_resource.run(
            ESPAppHeaderModifier,
            ESPAppHeaderModifierConfig(entry_point=self.new_entry_point),
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
@pytest.mark.parametrize("asset", ["esp32c3_hello.bin", "esp8266v2_hello.bin"])
def test_parse_image_truncation_never_crashes(asset: str):
    """
    Truncating a real image at any length must make ``_parse_image`` either parse it or raise a
    clean ``UnpackerError`` -- never an IndexError/struct.error. Sweeping the small ESP32-family
    image (extended header + appended SHA256) and the ESP8266 v2 image (CRC32 footer) exercises
    every truncation guard with real data.
    """
    data = load_esp_asset(asset)
    for n in range(len(data) + 1):
        try:
            _parse_image(data[:n])
        except UnpackerError:
            pass


def test_parse_image_rejects_unknown_magic():
    """A real image whose magic byte is corrupted is rejected, not misparsed."""
    data = bytearray(load_esp_asset("esp32_hello.bin"))
    data[0] = 0x00  # neither 0xE9 nor 0xEA
    with pytest.raises(UnpackerError):
        _parse_image(bytes(data))


def test_parse_image_rejects_bad_v2_second_header():
    """An ESP8266 v2 image whose second header lacks the 0xE9 magic is rejected."""
    data = bytearray(load_esp_asset("esp8266v2_hello.bin"))
    # The second header follows the 8-byte first header and the irom0 segment (8-byte header + data).
    irom_size = int.from_bytes(data[12:16], "little")
    second_header = ESP_APP_HEADER_SIZE + ESP_APP_SEGMENT_HEADER_SIZE + irom_size
    data[second_header] = 0x00  # corrupt the expected 0xE9 second-header magic
    with pytest.raises(UnpackerError):
        _parse_image(bytes(data))


def test_determine_chip_unknown_chip_id_is_esp8266():
    """
    An extended header carrying an *unrecognized* chip id falls back to ESP8266 (the
    ``_determine_chip`` UNKNOWN branch). Byte-patch a real ESP32 image's chip-id field.
    """
    data = bytearray(load_esp_asset("esp32_hello.bin"))
    data[12:14] = (0xABCD).to_bytes(2, "little")  # not a known IMAGE_CHIP_ID
    assert _determine_chip(bytes(data)) == ESPChip.ESP8266


async def test_identifier_ignores_short_resource(ofrak_context: OFRAKContext):
    """A 1-3 byte resource starting with 0xE9 must not crash the ESP app identifier."""
    root_resource = await ofrak_context.create_root_resource("tiny.bin", b"\xe9\x00")
    await root_resource.identify()  # must not raise IndexError
    assert not root_resource.has_tag(ESPApp)


async def test_esp_app_header_modifier_flash_fields(ofrak_context: OFRAKContext):
    """ESPAppHeaderModifier rewrites flash mode/size/frequency in place (packer revalidates)."""
    root = await ofrak_context.create_root_resource("hdr.bin", load_esp_asset("esp32_hello.bin"))
    await root.identify()
    await root.run(
        ESPAppHeaderModifier,
        ESPAppHeaderModifierConfig(
            flash_mode=ESPAppFlashMode.DIO,
            flash_size=0x20,  # high nibble
            flash_frequency=0x0F,  # low nibble
        ),
    )
    await root.run(ESPAppPacker)
    attributes = await root.analyze(ESPAppAttributes)
    assert attributes.flash_mode == ESPAppFlashMode.DIO.value
    assert attributes.flash_size == 0x20
    assert attributes.flash_frequency == 0x0F
    assert attributes.checksum_valid is True


async def test_esp_app_get_section_by_name(ofrak_context: OFRAKContext):
    """ESPApp.get_section_by_name returns the loadable segment with the given name."""
    root = await ofrak_context.create_root_resource("byname.bin", load_esp_asset("esp32_hello.bin"))
    await root.identify()
    await root.unpack()
    esp_app = await root.view_as(ESPApp)
    names = [s.name for s in await esp_app.get_sections()]
    unique_name = next(n for n in names if names.count(n) == 1)
    section = await esp_app.get_section_by_name(unique_name)
    assert section.name == unique_name


async def test_flash_decode_handles_unknown_codes(ofrak_context: OFRAKContext):
    """
    A flash size/frequency code outside the chip's table decodes to None rather than crashing the
    analyzer -- real-world firmware can carry non-standard or modified flash bytes.
    """
    data = bytearray(load_esp_asset("esp32c6_hello.bin"))
    # High nibble 0x90 is not a valid ESP32 flash size; low nibble 0x1 is not a valid ESP32-C6
    # frequency. The low nibble (1) still passes the identifier's flash-frequency sanity check.
    data[3] = 0x91
    root = await ofrak_context.create_root_resource("weird_flash.bin", bytes(data))
    await root.identify()
    assert root.has_tag(ESPApp)
    attributes = await root.analyze(ESPAppAttributes)
    assert attributes.flash_size_decoded is None
    assert attributes.flash_frequency_decoded is None


async def test_esp_code_region_tagging(ofrak_context: OFRAKContext):
    """
    Loadable segments mapped to instruction memory are tagged CodeRegion, but a segment must NOT be
    tagged on the RISC-V parts where the IRAM and DRAM windows are the same address range (the bug
    `_classify_segment` guards against). ESP32-C6's only segment loads into that coincident window.
    """
    # ESP32: IRAM/IROM are distinct from DRAM/DROM, so at least one segment is genuinely code.
    esp32 = await ofrak_context.create_root_resource("esp32.bin", load_esp_asset("esp32_hello.bin"))
    await esp32.identify()
    await esp32.unpack()
    esp32_sections = list(await (await esp32.view_as(ESPApp)).get_sections())
    assert any(s.resource.has_tag(CodeRegion) for s in esp32_sections)

    # ESP32-C6: IRAM == DRAM window, so its RAM segment must NOT be mistagged as code.
    c6 = await ofrak_context.create_root_resource("c6.bin", load_esp_asset("esp32c6_hello.bin"))
    await c6.identify()
    await c6.unpack()
    c6_sections = list(await (await c6.view_as(ESPApp)).get_sections())
    coincident = [s for s in c6_sections if s.virtual_address == 0x40800000]
    assert coincident, "expected the ESP32-C6 segment in the coincident IRAM/DRAM window"
    assert all(not s.resource.has_tag(CodeRegion) for s in coincident)
